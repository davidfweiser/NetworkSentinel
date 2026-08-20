using NetworkSentinel.Models;
using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// Folding the two ends of a local socket into one row.
///
/// The kernel's TCP table holds a row per endpoint, so a connection between two
/// processes on this machine appears twice — once owned by each end. Listed as-is it
/// reads as a table full of duplicates, and the two halves sort apart, so the
/// repetition is not even visibly a pair.
/// </summary>
public class LoopbackPairsTests
{
    private static NetworkConnection Conn(
        string process, string localAddr, int localPort, string remoteAddr, int remotePort,
        string protocol = "TCP") => new()
    {
        Protocol = protocol,
        LocalAddress = localAddr,
        LocalPort = localPort,
        RemoteAddress = remoteAddr,
        RemotePort = remotePort,
        ProcessName = process
    };

    /// <summary>The case from the bug report, endpoint for endpoint.</summary>
    [Fact]
    public void TheTwoEndsOfALocalSocket_BecomeOneRow()
    {
        var server = Conn("CoordinatorService", "127.0.0.1", 31100, "127.0.0.1", 49709);
        var client = Conn("Manager", "127.0.0.1", 49709, "127.0.0.1", 31100);

        var kept = LoopbackPairs.Collapse(new[] { server, client });

        var row = Assert.Single(kept);
        // The client's view survives: it reads the way the connection was made.
        Assert.Same(client, row);
        Assert.Equal("Manager", row.ProcessName);
        Assert.Equal("CoordinatorService", row.LoopbackPeer);
    }

    /// <summary>
    /// The fold is what makes the row name both processes — and it displaces the
    /// hosts-file name, which on a machine running Docker Desktop maps 127.0.0.1 to
    /// "kubernetes.docker.internal" and makes every local socket look like a container.
    /// </summary>
    [Fact]
    public void TheSurvivingRow_NamesThePeerProcessRatherThanTheHostsFileName()
    {
        var server = Conn("CoordinatorService", "127.0.0.1", 31100, "127.0.0.1", 49709);
        var client = Conn("Manager", "127.0.0.1", 49709, "127.0.0.1", 31100);
        client.RemoteHostName = "kubernetes.docker.internal";

        var row = Assert.Single(LoopbackPairs.Collapse(new[] { server, client }));

        Assert.Equal("CoordinatorService (127.0.0.1:31100)", row.DisplayRemote);
    }

    /// <summary>
    /// Order must not decide the outcome, or the same table would fold differently
    /// from one poll to the next as rows are re-sorted by last-seen.
    /// </summary>
    [Fact]
    public void WhichEndSurvives_DoesNotDependOnListOrder()
    {
        var server = Conn("CoordinatorService", "127.0.0.1", 31100, "127.0.0.1", 49709);
        var client = Conn("Manager", "127.0.0.1", 49709, "127.0.0.1", 31100);

        var oneWay = Assert.Single(LoopbackPairs.Collapse(new[] { server, client }));
        var theOther = Assert.Single(LoopbackPairs.Collapse(new[] { client, server }));

        Assert.Same(oneWay, theOther);
    }

    /// <summary>A connection leaving this machine has no second row, and must survive whole.</summary>
    [Fact]
    public void ARemoteConnection_IsLeftAlone()
    {
        var remote = Conn("firefox", "192.168.1.20", 51000, "140.82.121.4", 443);

        var row = Assert.Single(LoopbackPairs.Collapse(new[] { remote }));

        Assert.Same(remote, row);
        Assert.Equal("", row.LoopbackPeer);
    }

    /// <summary>
    /// Only the far end of *this* socket folds. Two local sockets that merely share a
    /// port number are different conversations.
    /// </summary>
    [Fact]
    public void ALocalRowWithNoMatchingFarEnd_IsKept()
    {
        var lonely = Conn("python", "127.0.0.1", 63402, "127.0.0.1", 63403);
        var unrelated = Conn("python", "127.0.0.1", 63500, "127.0.0.1", 63501);

        var kept = LoopbackPairs.Collapse(new[] { lonely, unrelated });

        Assert.Equal(2, kept.Count);
        Assert.All(kept, c => Assert.Equal("", c.LoopbackPeer));
    }

    /// <summary>The protocol is part of the identity: a UDP row cannot fold a TCP one.</summary>
    [Fact]
    public void APairMustAgreeOnProtocol()
    {
        var tcp = Conn("a", "127.0.0.1", 5000, "127.0.0.1", 6000, protocol: "TCP");
        var udp = Conn("b", "127.0.0.1", 6000, "127.0.0.1", 5000, protocol: "UDP");

        Assert.Equal(2, LoopbackPairs.Collapse(new[] { tcp, udp }).Count);
    }

    /// <summary>
    /// A socket connected to itself is its own far end. Folding it would delete the
    /// only row describing it.
    /// </summary>
    [Fact]
    public void ASocketConnectedToItself_SurvivesItsOwnFold()
    {
        var self = Conn("weird", "127.0.0.1", 7000, "127.0.0.1", 7000);

        Assert.Same(self, Assert.Single(LoopbackPairs.Collapse(new[] { self })));
    }

    /// <summary>
    /// These objects live across polls, so a row that was half of a pair must stop
    /// claiming a peer once the far end is gone — otherwise it advertises a process
    /// that is no longer on the other end of anything.
    /// </summary>
    [Fact]
    public void AStalePeer_IsClearedWhenTheFarEndGoesAway()
    {
        var server = Conn("CoordinatorService", "127.0.0.1", 31100, "127.0.0.1", 49709);
        var client = Conn("Manager", "127.0.0.1", 49709, "127.0.0.1", 31100);

        LoopbackPairs.Collapse(new[] { server, client });
        Assert.Equal("CoordinatorService", client.LoopbackPeer);

        // Next poll: the server end has closed.
        var kept = LoopbackPairs.Collapse(new[] { client });

        Assert.Same(client, Assert.Single(kept));
        Assert.Equal("", client.LoopbackPeer);
        Assert.Equal("127.0.0.1:31100", client.DisplayRemote);
    }

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.5.6.7", true)]   // the whole /8 is loopback, not just .0.1
    [InlineData("::1", true)]
    [InlineData("::ffff:127.0.0.1", true)]
    [InlineData("192.168.1.10", false)]
    [InlineData("0.0.0.0", false)]
    [InlineData("", false)]
    public void LoopbackIsRecognised(string address, bool expected)
        => Assert.Equal(expected, LoopbackPairs.IsLoopbackAddress(address));

    /// <summary>A pair bound elsewhere in 127.0.0.0/8 is still a local pair.</summary>
    [Fact]
    public void APairElsewhereInTheLoopbackRange_StillFolds()
    {
        var a = Conn("server", "127.0.0.2", 8080, "127.0.0.3", 55000);
        var b = Conn("client", "127.0.0.3", 55000, "127.0.0.2", 8080);

        var row = Assert.Single(LoopbackPairs.Collapse(new[] { a, b }));

        Assert.Same(b, row);
        Assert.Equal("server", row.LoopbackPeer);
    }
}
