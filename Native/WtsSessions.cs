using System.Net;
using System.Runtime.InteropServices;

namespace NetworkSentinel.Native;

/// <summary>
/// The client addresses of the Remote Desktop sessions someone is logged on to right
/// now, from the Remote Desktop Services API (wtsapi32). The Windows counterpart of the
/// utmp table the Linux build reads for its SSH sessions.
///
/// Only a session with a user in it counts. Without Network Level Authentication a
/// session exists — state Connected, client address and all — while the logon screen
/// is still waiting for a password, so a brute-forcer has one too.
///
/// Reading another user's session needs the Query Information permission, which
/// Administrators and SYSTEM have; an unelevated process sees its own session only.
/// </summary>
internal static class WtsSessions
{
    private const int WtsUserName = 5;
    private const int WtsClientAddress = 14;
    private const int AfInet = 2;

    /// <summary>WTS_CONNECTSTATE_CLASS: logged on and attached, and logged on with the client gone.</summary>
    private const int WtsActive = 0;
    private const int WtsDisconnected = 4;

    [StructLayout(LayoutKind.Sequential)]
    private struct WtsSessionInfo
    {
        public int SessionId;
        public IntPtr WinStationName;
        public int State;
    }

    [DllImport("wtsapi32.dll", EntryPoint = "WTSEnumerateSessionsW", SetLastError = true)]
    private static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version,
        out IntPtr sessionInfo, out int count);

    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", SetLastError = true)]
    private static extern bool WTSQuerySessionInformation(IntPtr server, int sessionId, int infoClass,
        out IntPtr buffer, out int bytesReturned);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);

    private static readonly IntPtr CurrentServer = IntPtr.Zero;

    /// <summary>Client addresses of the logged-on Remote Desktop sessions. Empty when none can be read.</summary>
    public static List<string> LoggedOnClientAddresses()
    {
        var result = new List<string>();
        if (!WTSEnumerateSessions(CurrentServer, 0, 1, out var sessions, out var count) || sessions == IntPtr.Zero)
            return result;

        try
        {
            var size = Marshal.SizeOf<WtsSessionInfo>();
            for (var i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<WtsSessionInfo>(sessions + i * size);
                if (info.State is not (WtsActive or WtsDisconnected))
                    continue;
                if (string.IsNullOrEmpty(QueryUserName(info.SessionId)))
                    continue;
                if (QueryClientAddress(info.SessionId) is { } address)
                    result.Add(address);
            }
        }
        finally
        {
            WTSFreeMemory(sessions);
        }
        return result;
    }

    private static string? QueryUserName(int sessionId)
    {
        if (!WTSQuerySessionInformation(CurrentServer, sessionId, WtsUserName, out var buffer, out _) ||
            buffer == IntPtr.Zero)
            return null;
        try
        {
            return Marshal.PtrToStringUni(buffer);
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    private static string? QueryClientAddress(int sessionId)
    {
        if (!WTSQuerySessionInformation(CurrentServer, sessionId, WtsClientAddress, out var buffer, out var bytes) ||
            buffer == IntPtr.Zero)
            return null;
        try
        {
            // WTS_CLIENT_ADDRESS: a DWORD address family, then 20 bytes of address.
            if (bytes < 24) return null;
            var family = Marshal.ReadInt32(buffer);
            var address = new byte[20];
            Marshal.Copy(buffer + 4, address, 0, address.Length);
            return ParseClientAddress(family, address);
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    /// <summary>
    /// The address in a WTS_CLIENT_ADDRESS. For AF_INET the four bytes start at
    /// Address[2], where a sockaddr_in keeps them after its port. IPv6 clients are not
    /// read: the layout of their 20 bytes is not documented, and a misread address would
    /// shield a stranger. Their logons are still remembered through the Security log.
    /// </summary>
    internal static string? ParseClientAddress(int family, byte[] address)
    {
        if (family != AfInet || address.Length < 6)
            return null;
        var ip = new IPAddress(address.AsSpan(2, 4));
        return ip.Equals(IPAddress.Any) ? null : ip.ToString();
    }
}
