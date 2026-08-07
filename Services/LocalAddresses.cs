using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetworkSentinel.Services;

/// <summary>
/// Cached view of the IP addresses assigned to this machine's own interfaces.
///
/// <see cref="GeoIpService.IsNonPublic"/> can only recognise private ranges, which is
/// not the same thing as "this machine": on a VPS or VPN server the host's own address
/// is public, and a detector that attributes a threat to the wrong end of a flow can
/// hand the prevention engine the host's own IP. Blocking that firewalls the machine
/// off from itself, so both the Suricata remote-end resolution and the auto-block gate
/// stack check here.
/// </summary>
public static class LocalAddresses
{
    private static readonly TimeSpan MaxAge = TimeSpan.FromSeconds(30);

    private static readonly object Gate = new();
    private static HashSet<string> _addresses = new(StringComparer.OrdinalIgnoreCase);
    private static DateTime _refreshedUtc = DateTime.MinValue;

    /// <summary>True when the address is assigned to one of this machine's interfaces.</summary>
    public static bool IsOwnAddress(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip) || !IPAddress.TryParse(ip.Trim(), out var address))
            return false;

        var key = Canonical(address);
        lock (Gate)
        {
            if (DateTime.UtcNow - _refreshedUtc > MaxAge)
            {
                _addresses = Snapshot();
                _refreshedUtc = DateTime.UtcNow;
            }
            return _addresses.Contains(key);
        }
    }

    private static HashSet<string> Snapshot()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                try
                {
                    foreach (var info in nic.GetIPProperties().UnicastAddresses)
                        set.Add(Canonical(info.Address));
                }
                catch
                {
                    // An interface that can't be queried just contributes nothing.
                }
            }
        }
        catch
        {
            // No interface list at all — an empty set simply never matches.
        }
        return set;
    }

    private static string Canonical(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        // Drop the IPv6 zone id so fe80::1%eth0 and fe80::1 compare equal.
        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0)
            address = new IPAddress(address.GetAddressBytes());
        return address.ToString();
    }
}
