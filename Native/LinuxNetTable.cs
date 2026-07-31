using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using NetworkSentinel.Models;

namespace NetworkSentinel.Native;

/// <summary>
/// Reads TCP/UDP tables from the Linux kernel via /proc/net/* and maps
/// socket inodes to PIDs through /proc/*/fd. Replaces Windows IP Helper.
/// </summary>
internal static class LinuxNetTable
{
    // Linux TCP states match the classic BSD numbering used by Windows MIB too.
    private static readonly Dictionary<int, TcpConnectionState> TcpStates = new()
    {
        [1] = TcpConnectionState.Established,
        [2] = TcpConnectionState.SynSent,
        [3] = TcpConnectionState.SynReceived,
        [4] = TcpConnectionState.FinWait1,
        [5] = TcpConnectionState.FinWait2,
        [6] = TcpConnectionState.TimeWait,
        [7] = TcpConnectionState.Closed,
        [8] = TcpConnectionState.CloseWait,
        [9] = TcpConnectionState.LastAck,
        [10] = TcpConnectionState.Listen,
        [11] = TcpConnectionState.Closing,
        [12] = TcpConnectionState.DeleteTcb
    };

    private static Dictionary<long, int>? _inodeToPid;
    private static DateTime _inodeMapBuiltAt = DateTime.MinValue;
    private static readonly TimeSpan InodeMapTtl = TimeSpan.FromSeconds(2);
    private static readonly object InodeLock = new();

    [DllImport("libc", SetLastError = true)]
    private static extern int readlink(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        byte[] buf,
        int bufsiz);

    public static IReadOnlyList<NetworkConnection> GetTcpConnections()
    {
        var list = new List<NetworkConnection>();
        list.AddRange(ReadTcp("/proc/net/tcp", AddressFamily.InterNetwork));
        list.AddRange(ReadTcp("/proc/net/tcp6", AddressFamily.InterNetworkV6));
        return list;
    }

    /// <summary>
    /// UDP sockets split into bound-only listeners and connected sockets. A UDP
    /// socket that has called connect() carries a real peer in rem_address, and
    /// that peer is as much a remote host as any TCP conversation — DNS
    /// resolvers, QUIC/HTTP3, WireGuard and most beacons live there.
    /// </summary>
    public static (IReadOnlyList<ListeningPort> Listeners, IReadOnlyList<NetworkConnection> Connections) GetUdpTable()
    {
        var listeners = new List<ListeningPort>();
        var connections = new List<NetworkConnection>();
        ReadUdp("/proc/net/udp", AddressFamily.InterNetwork, listeners, connections);
        ReadUdp("/proc/net/udp6", AddressFamily.InterNetworkV6, listeners, connections);
        return (listeners, connections);
    }

    private static List<NetworkConnection> ReadTcp(string path, AddressFamily family)
    {
        var result = new List<NetworkConnection>();
        if (!File.Exists(path)) return result;

        var inodeMap = GetInodeToPidMap();
        foreach (var line in File.ReadLines(path).Skip(1))
        {
            if (!TryParseSocketLine(line, family, out var localIp, out var localPort,
                    out var remoteIp, out var remotePort, out var stateHex, out var inode))
                continue;

            var stateNum = int.Parse(stateHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            var state = TcpStates.TryGetValue(stateNum, out var s) ? s : TcpConnectionState.Closed;
            inodeMap.TryGetValue(inode, out var pid);

            result.Add(new NetworkConnection
            {
                Protocol = "TCP",
                LocalAddress = localIp,
                LocalPort = localPort,
                RemoteAddress = remoteIp,
                RemotePort = state == TcpConnectionState.Listen ? 0 : remotePort,
                State = state,
                ProcessId = pid
            });
        }

        return result;
    }

    private static void ReadUdp(
        string path,
        AddressFamily family,
        List<ListeningPort> listeners,
        List<NetworkConnection> connections)
    {
        if (!File.Exists(path)) return;

        var inodeMap = GetInodeToPidMap();
        foreach (var line in File.ReadLines(path).Skip(1))
        {
            if (!TryParseSocketLine(line, family, out var localIp, out var localPort,
                    out var remoteIp, out var remotePort, out _, out var inode))
                continue;

            inodeMap.TryGetValue(inode, out var pid);

            if (remotePort > 0 && remoteIp is not ("" or "0.0.0.0" or "::"))
            {
                connections.Add(new NetworkConnection
                {
                    Protocol = "UDP",
                    LocalAddress = localIp,
                    LocalPort = localPort,
                    RemoteAddress = remoteIp,
                    RemotePort = remotePort,
                    // UDP is stateless; Established is the closest label for a
                    // socket with a fixed peer.
                    State = TcpConnectionState.Established,
                    ProcessId = pid
                });
                continue;
            }

            listeners.Add(new ListeningPort
            {
                Protocol = "UDP",
                Address = localIp,
                Port = localPort,
                ProcessId = pid,
                ServiceHint = PortCatalog.GetHint(localPort, "UDP")
            });
        }
    }

    private static bool TryParseSocketLine(
        string line,
        AddressFamily family,
        out string localIp,
        out int localPort,
        out string remoteIp,
        out int remotePort,
        out string stateHex,
        out long inode)
    {
        localIp = remoteIp = stateHex = "";
        localPort = remotePort = 0;
        inode = 0;

        var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 10) return false;

        if (!TryParseEndpoint(parts[1], family, out localIp, out localPort)) return false;
        if (!TryParseEndpoint(parts[2], family, out remoteIp, out remotePort)) return false;
        stateHex = parts[3];
        return long.TryParse(parts[9], NumberStyles.Integer, CultureInfo.InvariantCulture, out inode);
    }

    private static bool TryParseEndpoint(string token, AddressFamily family, out string ip, out int port)
    {
        ip = "";
        port = 0;
        var colon = token.LastIndexOf(':');
        if (colon <= 0) return false;

        var addrHex = token[..colon];
        var portHex = token[(colon + 1)..];
        if (!int.TryParse(portHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out port))
            return false;

        try
        {
            ip = HexAddressToString(addrHex, family);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string HexAddressToString(string hex, AddressFamily family)
    {
        if (family == AddressFamily.InterNetwork)
        {
            var value = uint.Parse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            var bytes = BitConverter.GetBytes(value);
            return new IPAddress(bytes).ToString();
        }

        if (hex.Length != 32)
            hex = hex.PadLeft(32, '0');

        var raw = new byte[16];
        for (int i = 0; i < 4; i++)
        {
            var chunk = hex.Substring(i * 8, 8);
            var word = uint.Parse(chunk, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            var le = BitConverter.GetBytes(word);
            Buffer.BlockCopy(le, 0, raw, i * 4, 4);
        }

        return new IPAddress(raw).ToString();
    }

    private static Dictionary<long, int> GetInodeToPidMap()
    {
        lock (InodeLock)
        {
            if (_inodeToPid != null && DateTime.UtcNow - _inodeMapBuiltAt < InodeMapTtl)
                return _inodeToPid;

            var map = new Dictionary<long, int>();
            var buf = new byte[256];
            try
            {
                foreach (var dir in Directory.EnumerateDirectories("/proc"))
                {
                    var name = Path.GetFileName(dir);
                    if (!int.TryParse(name, out var pid)) continue;

                    string fdPath = Path.Combine(dir, "fd");
                    if (!Directory.Exists(fdPath)) continue;

                    try
                    {
                        foreach (var fd in Directory.EnumerateFileSystemEntries(fdPath))
                        {
                            var target = ReadLink(fd, buf);
                            if (string.IsNullOrEmpty(target)) continue;
                            if (!target.StartsWith("socket:[", StringComparison.Ordinal)) continue;
                            var end = target.IndexOf(']');
                            if (end < 9) continue;
                            if (long.TryParse(target.AsSpan(8, end - 8), out var inode) && inode > 0)
                                map.TryAdd(inode, pid);
                        }
                    }
                    catch
                    {
                        // EACCES on other users' /proc/*/fd is normal when not root
                    }
                }
            }
            catch
            {
                // /proc not available
            }

            _inodeToPid = map;
            _inodeMapBuiltAt = DateTime.UtcNow;
            return map;
        }
    }

    private static string? ReadLink(string path, byte[] buf)
    {
        int n = readlink(path, buf, buf.Length - 1);
        if (n <= 0) return null;
        return Encoding.UTF8.GetString(buf, 0, n);
    }
}

/// <summary>
/// Facade used by NetworkMonitorService — Linux /proc implementation.
/// </summary>
internal static class IpHelper
{
    public static IReadOnlyList<NetworkConnection> GetTcpConnections()
        => LinuxNetTable.GetTcpConnections();

    public static (IReadOnlyList<ListeningPort> Listeners, IReadOnlyList<NetworkConnection> Connections) GetUdpTable()
        => LinuxNetTable.GetUdpTable();
}

internal static class PortCatalog
{
    private static readonly Dictionary<int, string> Map = new()
    {
        [20] = "FTP Data",
        [21] = "FTP",
        [22] = "SSH",
        [23] = "Telnet",
        [25] = "SMTP",
        [53] = "DNS",
        [80] = "HTTP",
        [110] = "POP3",
        [135] = "RPC / Epmap",
        [139] = "NetBIOS",
        [143] = "IMAP",
        [443] = "HTTPS",
        [445] = "SMB",
        [993] = "IMAPS",
        [995] = "POP3S",
        [1433] = "SQL Server",
        [1521] = "Oracle",
        [3306] = "MySQL",
        [3389] = "RDP",
        [5432] = "PostgreSQL",
        [5900] = "VNC",
        [5985] = "WinRM HTTP",
        [5986] = "WinRM HTTPS",
        [631] = "CUPS",
        [8080] = "HTTP Alt",
        [8443] = "HTTPS Alt"
    };

    public static readonly HashSet<int> SensitivePorts = new()
    {
        21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 5985, 5986, 631
    };

    public static string GetHint(int port, string protocol)
    {
        if (Map.TryGetValue(port, out var name))
            return name;
        return protocol == "UDP" ? "UDP service" : "Custom / unknown";
    }
}
