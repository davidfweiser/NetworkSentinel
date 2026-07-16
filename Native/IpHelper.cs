using System.Net;
using System.Runtime.InteropServices;
using NetworkSentinel.Models;

namespace NetworkSentinel.Native;

internal static class IpHelper
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;

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
    {
        var result = new List<NetworkConnection>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, AfInet, TcpTableClass.TcpTableOwnerPidAll, 0);
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var ret = GetExtendedTcpTable(buffer, ref size, true, AfInet, TcpTableClass.TcpTableOwnerPidAll, 0);
            if (ret != 0) return result;

            int count = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = buffer + 4;
            int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();

            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr);
                var state = (TcpConnectionState)row.State;
                var local = new IPAddress(row.LocalAddr).ToString();
                var remote = new IPAddress(row.RemoteAddr).ToString();
                int localPort = ntohs(row.LocalPort);
                int remotePort = ntohs(row.RemotePort);

                result.Add(new NetworkConnection
                {
                    Protocol = "TCP",
                    LocalAddress = local,
                    LocalPort = localPort,
                    RemoteAddress = remote,
                    RemotePort = state == TcpConnectionState.Listen ? 0 : remotePort,
                    State = state,
                    ProcessId = (int)row.OwningPid
                });

                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
    }

    private static List<NetworkConnection> ReadTcpV6()
    {
        var result = new List<NetworkConnection>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, true, AfInet6, TcpTableClass.TcpTableOwnerPidAll, 0);
        if (size <= 0) return result;

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var ret = GetExtendedTcpTable(buffer, ref size, true, AfInet6, TcpTableClass.TcpTableOwnerPidAll, 0);
            if (ret != 0) return result;

            int count = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = buffer + 4;
            int rowSize = Marshal.SizeOf<MibTcp6RowOwnerPid>();

            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(rowPtr);
                var state = (TcpConnectionState)row.State;
                var local = new IPAddress(row.LocalAddr).ToString();
                var remote = new IPAddress(row.RemoteAddr).ToString();
                int localPort = ntohs(row.LocalPort);
                int remotePort = ntohs(row.RemotePort);

                result.Add(new NetworkConnection
                {
                    Protocol = "TCP",
                    LocalAddress = local,
                    LocalPort = localPort,
                    RemoteAddress = remote,
                    RemotePort = state == TcpConnectionState.Listen ? 0 : remotePort,
                    State = state,
                    ProcessId = (int)row.OwningPid
                });

                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
    }

    private static List<ListeningPort> ReadUdpV4()
    {
        var result = new List<ListeningPort>();
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, true, AfInet, UdpTableClass.UdpTableOwnerPid, 0);
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var ret = GetExtendedUdpTable(buffer, ref size, true, AfInet, UdpTableClass.UdpTableOwnerPid, 0);
            if (ret != 0) return result;

            int count = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = buffer + 4;
            int rowSize = Marshal.SizeOf<MibUdpRowOwnerPid>();

            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibUdpRowOwnerPid>(rowPtr);
                var local = new IPAddress(row.LocalAddr).ToString();
                int localPort = ntohs(row.LocalPort);

                result.Add(new ListeningPort
                {
                    Protocol = "UDP",
                    Address = local,
                    Port = localPort,
                    ProcessId = (int)row.OwningPid,
                    ServiceHint = PortCatalog.GetHint(localPort, "UDP")
                });

                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
    }

    private static List<ListeningPort> ReadUdpV6()
    {
        var result = new List<ListeningPort>();
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, true, AfInet6, UdpTableClass.UdpTableOwnerPid, 0);
        if (size <= 0) return result;

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var ret = GetExtendedUdpTable(buffer, ref size, true, AfInet6, UdpTableClass.UdpTableOwnerPid, 0);
            if (ret != 0) return result;

            int count = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = buffer + 4;
            int rowSize = Marshal.SizeOf<MibUdp6RowOwnerPid>();

            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibUdp6RowOwnerPid>(rowPtr);
                var local = new IPAddress(row.LocalAddr).ToString();
                int localPort = ntohs(row.LocalPort);

                result.Add(new ListeningPort
                {
                    Protocol = "UDP",
                    Address = local,
                    Port = localPort,
                    ProcessId = (int)row.OwningPid,
                    ServiceHint = PortCatalog.GetHint(localPort, "UDP")
                });

                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
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
