using System.Net;
using System.Runtime.InteropServices;

namespace NetworkSentinel.Native;

/// <summary>A flow the kernel just created, as reported by conntrack.</summary>
public sealed class ConntrackFlow
{
    public required string Protocol { get; init; }
    public required string SourceAddress { get; init; }
    public required int SourcePort { get; init; }
    public required string DestinationAddress { get; init; }
    public required int DestinationPort { get; init; }
    public DateTime Observed { get; init; } = DateTime.Now;
}

/// <summary>
/// Subscribes to the kernel's conntrack NEW events over NETLINK_NETFILTER.
///
/// Polling /proc/net can only ever tell you what was true when the file was read;
/// on the default 1.2 s cycle an attacker gets a free window before anything is
/// even sampled. Conntrack pushes a message the moment the kernel creates the
/// flow, which lets the monitor take its snapshot *because* something happened
/// rather than because a timer fired.
///
/// This deliberately does not replace the poll or the heuristics — those are
/// snapshot-based by design, and a snapshot is still what they consume. It
/// collapses the latency between "the flow exists" and "we look".
///
/// Subscribing to the conntrack group needs CAP_NET_ADMIN (root). Without it the
/// bind fails with EPERM, <see cref="Status"/> explains why, and the caller keeps
/// its timer cadence — no functionality is lost, only reaction time.
/// </summary>
public sealed class ConntrackEventSource : IDisposable
{
    private const int AF_NETLINK = 16;
    private const int SOCK_RAW = 3;
    private const int NETLINK_NETFILTER = 12;

    /// <summary>NFNLGRP_CONNTRACK_NEW is group 1, so bit 0 of the bind mask.</summary>
    private const uint NfnlGroupConntrackNew = 1u << 0;

    /// <summary>(NFNL_SUBSYS_CTNETLINK &lt;&lt; 8) | IPCTNL_MSG_CT_NEW</summary>
    private const ushort MsgConntrackNew = (1 << 8) | 0;

    private const int NLMSG_HDRLEN = 16;
    private const int NFGENMSG_LEN = 4;
    private const ushort NLA_F_NESTED = 0x8000;
    private const ushort NLA_TYPE_MASK = 0x3fff;

    // CTA_* (top level)
    private const ushort CTA_TUPLE_ORIG = 1;
    // CTA_TUPLE_*
    private const ushort CTA_TUPLE_IP = 1;
    private const ushort CTA_TUPLE_PROTO = 2;
    // CTA_IP_*
    private const ushort CTA_IP_V4_SRC = 1;
    private const ushort CTA_IP_V4_DST = 2;
    private const ushort CTA_IP_V6_SRC = 3;
    private const ushort CTA_IP_V6_DST = 4;
    // CTA_PROTO_*
    private const ushort CTA_PROTO_NUM = 1;
    private const ushort CTA_PROTO_SRC_PORT = 2;
    private const ushort CTA_PROTO_DST_PORT = 3;

    private const short POLLIN = 0x001;
    private const int EPERM = 1;
    private const int EACCES = 13;
    private const int EPROTONOSUPPORT = 93;

    [DllImport("libc", SetLastError = true)]
    private static extern int socket(int domain, int type, int protocol);

    [DllImport("libc", SetLastError = true)]
    private static extern int bind(int fd, ref SockAddrNl addr, int addrlen);

    [DllImport("libc", SetLastError = true)]
    private static extern nint recv(int fd, byte[] buf, nint len, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int poll([In, Out] PollFd[] fds, uint nfds, int timeout);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    [DllImport("libc", SetLastError = true)]
    private static extern int setsockopt(int fd, int level, int optname, ref int optval, int optlen);

    [StructLayout(LayoutKind.Sequential)]
    private struct SockAddrNl
    {
        public ushort nl_family;
        public ushort nl_pad;
        public uint nl_pid;
        public uint nl_groups;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PollFd
    {
        public int fd;
        public short events;
        public short revents;
    }

    private readonly object _gate = new();
    private int _fd = -1;
    private CancellationTokenSource? _cts;
    private Task? _reader;
    private volatile string _status = "Conntrack events not started";

    /// <summary>Raised on the reader thread for every new flow. Keep handlers cheap.</summary>
    public event Action<ConntrackFlow>? FlowCreated;

    /// <summary>Human-readable state of the netlink source.</summary>
    public string Status => _status;

    /// <summary>True when events are actually flowing (as opposed to degraded to polling).</summary>
    public bool IsActive => Volatile.Read(ref _fd) >= 0;

    /// <summary>Opens the socket and starts reading. Returns false if the kernel source is unavailable.</summary>
    public bool Start()
    {
        lock (_gate)
        {
            if (_cts != null) return IsActive;

            var fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
            if (fd < 0)
            {
                var err = Marshal.GetLastWin32Error();
                _status = err == EPROTONOSUPPORT
                    ? "Conntrack events unavailable (nf_conntrack_netlink module not loaded) — using timed polling"
                    : $"Conntrack events unavailable (socket failed, errno {err}) — using timed polling";
                return false;
            }

            // A scan can produce thousands of events per second; a small default buffer
            // would drop them (ENOBUFS) exactly when the information matters most.
            var rcvbuf = 1 << 20;
            _ = setsockopt(fd, 1 /* SOL_SOCKET */, 8 /* SO_RCVBUF */, ref rcvbuf, sizeof(int));

            var addr = new SockAddrNl
            {
                nl_family = AF_NETLINK,
                nl_pad = 0,
                nl_pid = 0, // let the kernel assign
                nl_groups = NfnlGroupConntrackNew
            };

            if (bind(fd, ref addr, Marshal.SizeOf<SockAddrNl>()) < 0)
            {
                var err = Marshal.GetLastWin32Error();
                close(fd);
                _status = err is EPERM or EACCES
                    ? "Conntrack events need root (CAP_NET_ADMIN) — using timed polling"
                    : $"Conntrack events unavailable (bind failed, errno {err}) — using timed polling";
                return false;
            }

            Volatile.Write(ref _fd, fd);
            _cts = new CancellationTokenSource();
            var ct = _cts.Token;
            _reader = Task.Run(() => ReadLoop(ct), ct);
            _status = "Watching conntrack NEW events (sub-second reaction)";
            return true;
        }
    }

    public void Stop()
    {
        CancellationTokenSource? cts;
        Task? reader;
        lock (_gate)
        {
            cts = _cts;
            reader = _reader;
            _cts = null;
            _reader = null;
        }
        if (cts == null) return;

        cts.Cancel();

        // The reader parks in poll() with a short timeout, so it notices cancellation
        // on its own; close only after it has stopped touching the descriptor.
        try { reader?.Wait(1500); } catch { /* shutting down */ }

        var fd = Interlocked.Exchange(ref _fd, -1);
        if (fd >= 0) close(fd);

        cts.Dispose();
        _status = "Conntrack events stopped";
    }

    private void ReadLoop(CancellationToken ct)
    {
        var buffer = new byte[64 * 1024];
        var fds = new PollFd[1];

        while (!ct.IsCancellationRequested)
        {
            var fd = Volatile.Read(ref _fd);
            if (fd < 0) return;

            fds[0] = new PollFd { fd = fd, events = POLLIN, revents = 0 };

            var ready = poll(fds, 1, 500);
            if (ready < 0)
            {
                if (Marshal.GetLastWin32Error() == 4 /* EINTR */) continue;
                _status = $"Conntrack event read failed (poll errno {Marshal.GetLastWin32Error()})";
                return;
            }
            if (ready == 0 || (fds[0].revents & POLLIN) == 0)
                continue;

            var n = (long)recv(fd, buffer, buffer.Length, 0);
            if (n <= 0)
            {
                // ENOBUFS means the kernel dropped events because we fell behind; the
                // socket stays usable, so keep reading rather than tearing down.
                if (n < 0 && Marshal.GetLastWin32Error() == 105 /* ENOBUFS */) continue;
                if (ct.IsCancellationRequested) return;
                continue;
            }

            try
            {
                DispatchMessages(buffer.AsSpan(0, (int)n));
            }
            catch
            {
                // A malformed message must never take the reader down.
            }
        }
    }

    private void DispatchMessages(ReadOnlySpan<byte> buffer)
    {
        var offset = 0;
        while (offset + NLMSG_HDRLEN <= buffer.Length)
        {
            var len = (int)BitConverter.ToUInt32(buffer.Slice(offset, 4));
            var type = BitConverter.ToUInt16(buffer.Slice(offset + 4, 2));

            if (len < NLMSG_HDRLEN || offset + len > buffer.Length)
                return;

            if (type == MsgConntrackNew)
            {
                var payload = buffer.Slice(offset + NLMSG_HDRLEN, len - NLMSG_HDRLEN);
                if (payload.Length > NFGENMSG_LEN)
                {
                    var flow = ParseFlow(payload[NFGENMSG_LEN..]);
                    if (flow != null)
                        FlowCreated?.Invoke(flow);
                }
            }

            offset += Align(len);
        }
    }

    /// <summary>
    /// Walks the top-level attributes looking for the original-direction tuple.
    /// Internal for tests / replaying a captured netlink buffer.
    /// </summary>
    internal static ConntrackFlow? ParseFlow(ReadOnlySpan<byte> attrs)
    {
        foreach (var (type, payload) in EnumerateAttributes(attrs))
        {
            if (type != CTA_TUPLE_ORIG)
                continue;

            string? src = null, dst = null;
            int sport = 0, dport = 0, proto = 0;

            foreach (var (tupleType, tuplePayload) in EnumerateAttributes(payload))
            {
                switch (tupleType)
                {
                    case CTA_TUPLE_IP:
                        foreach (var (ipType, ipPayload) in EnumerateAttributes(tuplePayload))
                        {
                            switch (ipType)
                            {
                                case CTA_IP_V4_SRC when ipPayload.Length == 4:
                                case CTA_IP_V6_SRC when ipPayload.Length == 16:
                                    src = new IPAddress(ipPayload).ToString();
                                    break;
                                case CTA_IP_V4_DST when ipPayload.Length == 4:
                                case CTA_IP_V6_DST when ipPayload.Length == 16:
                                    dst = new IPAddress(ipPayload).ToString();
                                    break;
                            }
                        }
                        break;

                    case CTA_TUPLE_PROTO:
                        foreach (var (protoType, protoPayload) in EnumerateAttributes(tuplePayload))
                        {
                            switch (protoType)
                            {
                                case CTA_PROTO_NUM when protoPayload.Length >= 1:
                                    proto = protoPayload[0];
                                    break;
                                // Ports are big-endian on the wire.
                                case CTA_PROTO_SRC_PORT when protoPayload.Length >= 2:
                                    sport = (protoPayload[0] << 8) | protoPayload[1];
                                    break;
                                case CTA_PROTO_DST_PORT when protoPayload.Length >= 2:
                                    dport = (protoPayload[0] << 8) | protoPayload[1];
                                    break;
                            }
                        }
                        break;
                }
            }

            if (src == null || dst == null)
                return null;

            var name = proto switch { 6 => "TCP", 17 => "UDP", _ => null };
            if (name == null)
                return null;

            return new ConntrackFlow
            {
                Protocol = name,
                SourceAddress = src,
                SourcePort = sport,
                DestinationAddress = dst,
                DestinationPort = dport
            };
        }

        return null;
    }

    /// <summary>Iterates netlink attributes, yielding (type, payload) with the nested flag stripped.</summary>
    private static IEnumerable<(ushort Type, byte[] Payload)> EnumerateAttributes(ReadOnlySpan<byte> span)
    {
        // Span can't cross an iterator boundary, so collect eagerly. Attribute
        // blocks here are a few dozen bytes; the copy is irrelevant next to the syscall.
        var result = new List<(ushort, byte[])>();
        var offset = 0;

        while (offset + 4 <= span.Length)
        {
            var len = BitConverter.ToUInt16(span.Slice(offset, 2));
            var type = BitConverter.ToUInt16(span.Slice(offset + 2, 2));

            if (len < 4 || offset + len > span.Length)
                break;

            result.Add(((ushort)(type & NLA_TYPE_MASK & ~NLA_F_NESTED),
                span.Slice(offset + 4, len - 4).ToArray()));

            offset += Align(len);
        }

        return result;
    }

    private static int Align(int len) => (len + 3) & ~3;

    public void Dispose() => Stop();
}
