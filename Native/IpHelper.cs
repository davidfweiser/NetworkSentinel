using System.Net;
using System.Runtime.InteropServices;
using NetworkSentinel.Models;

namespace NetworkSentinel.Native;

internal static class IpHelper
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const uint ErrorInsufficientBuffer = 122;

    private enum TcpTableClass
    {
        TcpTableOwnerPidAll = 5
    }

    private enum UdpTableClass
    {
        UdpTableOwnerPid = 1
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpRowOwnerPid
    {
        public uint LocalAddr;
        public uint LocalPort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddr;
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        TcpTableClass tblClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        UdpTableClass tblClass,
        uint reserved);

    public static IReadOnlyList<NetworkConnection> GetTcpConnections()
    {
        var list = new List<NetworkConnection>();
        list.AddRange(ReadTcpV4());
        list.AddRange(ReadTcpV6());
        return list;
    }

    public static IReadOnlyList<ListeningPort> GetUdpListeners()
    {
        var list = new List<ListeningPort>();
        list.AddRange(ReadUdpV4());
        list.AddRange(ReadUdpV6());
        return list;
    }

    private static List<NetworkConnection> ReadTcpV4()
        => ReadTcpTable<MibTcpRowOwnerPid>(AfInet, row => (
            (TcpConnectionState)row.State,
            new IPAddress(row.LocalAddr).ToString(),
            ntohs(row.LocalPort),
            new IPAddress(row.RemoteAddr).ToString(),
            ntohs(row.RemotePort),
            (int)row.OwningPid));

    private static List<NetworkConnection> ReadTcpV6()
        => ReadTcpTable<MibTcp6RowOwnerPid>(AfInet6, row => (
            (TcpConnectionState)row.State,
            ToIpString(row.LocalAddr, row.LocalScopeId),
            ntohs(row.LocalPort),
            ToIpString(row.RemoteAddr, row.RemoteScopeId),
            ntohs(row.RemotePort),
            (int)row.OwningPid));

    private static List<NetworkConnection> ReadTcpTable<TRow>(
        int addressFamily,
        Func<TRow, (TcpConnectionState State, string Local, int LocalPort, string Remote, int RemotePort, int Pid)> parse)
        where TRow : struct
    {
        var result = new List<NetworkConnection>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, addressFamily, TcpTableClass.TcpTableOwnerPidAll, 0);

        // The table can grow between the size query and the fetch — retry on
        // ERROR_INSUFFICIENT_BUFFER instead of silently returning an empty poll.
        for (int attempt = 0; attempt < 3 && size > 0; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var ret = GetExtendedTcpTable(buffer, ref size, true, addressFamily, TcpTableClass.TcpTableOwnerPidAll, 0);
                if (ret == ErrorInsufficientBuffer) continue;
                if (ret != 0) return result;

                int count = Marshal.ReadInt32(buffer);
                IntPtr rowPtr = buffer + 4;
                int rowSize = Marshal.SizeOf<TRow>();

                for (int i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<TRow>(rowPtr);
                    var (state, local, localPort, remote, remotePort, pid) = parse(row);

                    result.Add(new NetworkConnection
                    {
                        Protocol = "TCP",
                        LocalAddress = local,
                        LocalPort = localPort,
                        RemoteAddress = remote,
                        RemotePort = state == TcpConnectionState.Listen ? 0 : remotePort,
                        State = state,
                        ProcessId = pid
                    });

                    rowPtr += rowSize;
                }

                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        return result;
    }

    private static List<ListeningPort> ReadUdpV4()
        => ReadUdpTable<MibUdpRowOwnerPid>(AfInet, row => (
            new IPAddress(row.LocalAddr).ToString(),
            ntohs(row.LocalPort),
            (int)row.OwningPid));

    private static List<ListeningPort> ReadUdpV6()
        => ReadUdpTable<MibUdp6RowOwnerPid>(AfInet6, row => (
            ToIpString(row.LocalAddr, row.LocalScopeId),
            ntohs(row.LocalPort),
            (int)row.OwningPid));

    private static List<ListeningPort> ReadUdpTable<TRow>(
        int addressFamily,
        Func<TRow, (string Local, int Port, int Pid)> parse)
        where TRow : struct
    {
        var result = new List<ListeningPort>();
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, true, addressFamily, UdpTableClass.UdpTableOwnerPid, 0);

        for (int attempt = 0; attempt < 3 && size > 0; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var ret = GetExtendedUdpTable(buffer, ref size, true, addressFamily, UdpTableClass.UdpTableOwnerPid, 0);
                if (ret == ErrorInsufficientBuffer) continue;
                if (ret != 0) return result;

                int count = Marshal.ReadInt32(buffer);
                IntPtr rowPtr = buffer + 4;
                int rowSize = Marshal.SizeOf<TRow>();

                for (int i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<TRow>(rowPtr);
                    var (local, port, pid) = parse(row);

                    result.Add(new ListeningPort
                    {
                        Protocol = "UDP",
                        Address = local,
                        Port = port,
                        ProcessId = pid,
                        ServiceHint = PortCatalog.GetHint(port, "UDP")
                    });

                    rowPtr += rowSize;
                }

                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        return result;
    }

    private static string ToIpString(byte[] addressBytes, uint scopeId)
    {
        var address = scopeId == 0
            ? new IPAddress(addressBytes)
            : new IPAddress(addressBytes, scopeId);
        return address.ToString();
    }

    private static int ntohs(uint port) => (int)(((port & 0xFF) << 8) | ((port >> 8) & 0xFF));
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
        [8080] = "HTTP Alt",
        [8443] = "HTTPS Alt"
    };

    public static readonly HashSet<int> SensitivePorts = new()
    {
        21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 5985, 5986
    };

    public static string GetHint(int port, string protocol)
    {
        if (Map.TryGetValue(port, out var name))
            return name;
        return protocol == "UDP" ? "UDP service" : "Custom / unknown";
    }
}
