using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Folds the two ends of a local socket into the one row an operator expects.
///
/// A connection between two processes on this machine is two rows in the kernel's TCP
/// table, one owned by each end, and the Live Connections list showed both:
///
///   CoordinatorService  127.0.0.1:31100 → 127.0.0.1:49709
///   Manager             127.0.0.1:49709 → 127.0.0.1:31100
///
/// Both rows are real and neither is wrong, but they are one conversation, and a list
/// that prints every local socket twice reads as a list full of duplicates — which is
/// exactly how it was reported. Worse, the two halves sort apart, so the pair is rarely
/// adjacent and the repetition is not even visibly a pair.
///
/// The surviving row is the client's: the end whose local port is the ephemeral one.
/// That reads the way the connection was made — <em>this</em> process reached out to
/// <em>that</em> port — and it is the half whose remote endpoint is the well-known port
/// worth recognising. The rule needs no cross-referencing to stay consistent, because
/// the partner's ports are this row's ports reversed: whenever one side keeps itself
/// the other necessarily drops itself.
///
/// The dropped end is not simply discarded. Its process name is carried onto the
/// survivor as <see cref="NetworkConnection.LoopbackPeer"/>, so the row names both
/// processes and the remote column says "CoordinatorService" rather than whatever the
/// hosts file happens to map 127.0.0.1 to — on a machine running Docker Desktop that
/// is "kubernetes.docker.internal", which makes every local socket look like it is
/// talking to a container.
///
/// Display only. The detectors and the host accounting read the poll's own tables, not
/// this, so nothing here can change what is measured or blocked — only what is listed.
/// </summary>
public static class LoopbackPairs
{
    /// <summary>
    /// Whether an address is this machine talking to itself. The whole 127.0.0.0/8
    /// block is loopback, not just 127.0.0.1 — services do bind elsewhere in it.
    /// </summary>
    public static bool IsLoopbackAddress(string? address)
    {
        var value = (address ?? "").Trim();
        if (value.Length == 0) return false;

        if (value is "::1" or "0:0:0:0:0:0:0:1") return true;

        // IPv4-mapped IPv6 loopback, as the TCP table sometimes prints it.
        if (value.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase))
            value = value["::ffff:".Length..];

        return System.Net.IPAddress.TryParse(value, out var ip) &&
               System.Net.IPAddress.IsLoopback(ip);
    }

    /// <summary>
    /// The list with each local socket's far end removed, and the survivor annotated
    /// with the process that was on it.
    /// </summary>
    public static IReadOnlyList<NetworkConnection> Collapse(IReadOnlyList<NetworkConnection> connections)
    {
        if (connections.Count == 0) return connections;

        // Every row indexed by the endpoints it joins, so a partner is one lookup
        // rather than a scan of the whole list per row.
        var byEndpoints = new Dictionary<string, NetworkConnection>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in connections)
            byEndpoints[EndpointKey(c.Protocol, c.LocalAddress, c.LocalPort, c.RemoteAddress, c.RemotePort)] = c;

        var kept = new List<NetworkConnection>(connections.Count);

        foreach (var c in connections)
        {
            var partner = FindPartner(byEndpoints, c);

            if (partner == null)
            {
                // Cleared, not left alone: these objects live across polls, so a row
                // that was half of a pair a moment ago must stop claiming a peer once
                // the other end is gone.
                c.LoopbackPeer = "";
                kept.Add(c);
                continue;
            }

            // The ephemeral end survives; the listening end is folded into it.
            if (c.LocalPort > c.RemotePort)
            {
                c.LoopbackPeer = partner.ProcessName;
                kept.Add(c);
            }
            else
            {
                c.LoopbackPeer = "";
            }
        }

        return kept;
    }

    /// <summary>
    /// The other end of <paramref name="c"/>, or null when there is none to fold: not a
    /// local socket, or the far end is not in this list because the table moved on
    /// between the two reads.
    /// </summary>
    private static NetworkConnection? FindPartner(
        Dictionary<string, NetworkConnection> byEndpoints, NetworkConnection c)
    {
        if (!IsLoopbackAddress(c.LocalAddress) || !IsLoopbackAddress(c.RemoteAddress))
            return null;

        // A socket connected to itself is its own partner; folding it would delete the
        // only row describing it.
        if (c.LocalPort == c.RemotePort &&
            string.Equals(c.LocalAddress, c.RemoteAddress, StringComparison.OrdinalIgnoreCase))
            return null;

        return byEndpoints.TryGetValue(
            EndpointKey(c.Protocol, c.RemoteAddress, c.RemotePort, c.LocalAddress, c.LocalPort),
            out var partner) ? partner : null;
    }

    private static string EndpointKey(string protocol, string localAddr, int localPort, string remoteAddr, int remotePort)
        => $"{protocol}|{localAddr}:{localPort}|{remoteAddr}:{remotePort}";
}
