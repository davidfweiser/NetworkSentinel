using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// Batched firewall writes under the scoped sudoers grant the README documents
/// (ufw, nft, iptables, ip6tables — never /bin/sh). Passwordless sudo runs each
/// command of a batch on its own, so it has to be able to tell sudo turning a
/// command down from the command itself failing, and the shell loops in the
/// batch scripts need a command-by-command twin.
/// </summary>
public class ScopedSudoBatchTests
{
    [Theory]
    [InlineData("sudo: a password is required")]
    [InlineData("\nsudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper")]
    [InlineData("Sorry, user ns is not allowed to execute '/bin/sh -c true' as root on host.")]
    [InlineData("Sorry, user ns may not run sudo on host.")]
    [InlineData("ns is not in the sudoers file.  This incident will be reported.")]
    public void SudoDecliningIsRecognised(string message)
        => Assert.True(FirewallService.LooksLikeSudoRefusal(message));

    [Theory]
    [InlineData("iptables: Bad rule (does a matching rule exist in that chain?).")]
    [InlineData("Error: Could not process rule: No such file or directory")]
    [InlineData("ERROR: Could not find a profile matching 'x'")]
    [InlineData("")]
    public void ToolErrorsAreNotSudoRefusals(string message)
        => Assert.False(FirewallService.LooksLikeSudoRefusal(message));

    [Fact]
    public void ProbeRulesAreDeletedByTheirOwnHandlesOnly()
    {
        const string listing = """
            table inet networksentinel { # handle 7
            	chain input { # handle 1
            		type filter hook input priority filter; policy accept;
            		ip saddr 203.0.113.9 drop comment "NetworkSentinel-Block-203.0.113.9" # handle 4
            		tcp flags & (syn | ack) == syn ct state new limit rate 50/second log prefix "NS-PROBE " comment "NetworkSentinel-ProbeLog" # handle 12
            		tcp flags & (syn | ack) == syn ct state new limit rate 50/second log prefix "NS-PROBE " comment "NetworkSentinel-ProbeLog" # handle 15
            	}
            }
            """;

        var calls = new List<string[]>();
        FirewallOperationResult Step(string[] argv)
        {
            calls.Add(argv);
            return argv.Contains("list")
                ? FirewallOperationResult.Ok(listing)
                : FirewallOperationResult.Ok("");
        }

        FirewallService.DeleteNftProbeRules(Step, "/usr/sbin/nft", new[] { "inet", "networksentinel" });

        Assert.Equal(new[] { "/usr/sbin/nft", "-a", "list", "table", "inet", "networksentinel" }, calls[0]);
        Assert.Equal(3, calls.Count);
        Assert.Equal(new[] { "/usr/sbin/nft", "delete", "rule", "inet", "networksentinel", "input", "handle", "12" }, calls[1]);
        Assert.Equal(new[] { "/usr/sbin/nft", "delete", "rule", "inet", "networksentinel", "input", "handle", "15" }, calls[2]);
    }

    [Fact]
    public void NoTableMeansNothingToDelete()
    {
        var calls = 0;
        FirewallService.DeleteNftProbeRules(_ =>
        {
            calls++;
            return FirewallOperationResult.Fail("Error: No such file or directory");
        }, "/usr/sbin/nft", new[] { "inet", "networksentinel" });

        Assert.Equal(1, calls);
    }
}
