using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;

namespace NetworkSentinel.Native;

/// <summary>A flow the kernel just reported, normalised to originator → responder.</summary>
public sealed class FlowEvent
{
    public required string Protocol { get; init; }
    public required string SourceAddress { get; init; }
    public required int SourcePort { get; init; }
    public required string DestinationAddress { get; init; }
    public required int DestinationPort { get; init; }
    public DateTime Observed { get; init; } = DateTime.Now;
}

/// <summary>
/// Subscribes to kernel flow events from the Microsoft-Windows-Kernel-Network ETW
/// provider.
///
/// Polling the TCP/UDP tables can only ever tell you what was true when the table was
/// read; on the default 1.2 s cycle an attacker gets a free window before anything is
/// even sampled. ETW pushes an event the moment the stack completes a connect or an
/// accept, which lets the monitor take its snapshot *because* something happened
/// rather than because a timer fired.
///
/// This deliberately does not replace the poll or the heuristics — those are
/// snapshot-based by design, and a snapshot is still what they consume. It collapses
/// the latency between "the flow exists" and "we look".
///
/// It is also the only place UDP peers are visible at all. GetExtendedUdpTable reports
/// unconnected sockets with no remote address, so a DNS query has no representation in
/// the socket table; the DNS hygiene monitor is fed entirely from here.
///
/// Starting a real-time session needs Administrator. Without it StartTrace fails with
/// ERROR_ACCESS_DENIED, <see cref="Status"/> explains why, and the caller keeps its
/// timer cadence — no functionality is lost, only reaction time.
/// </summary>
public sealed unsafe class FlowEventSource : IDisposable
{
    /// <summary>Microsoft-Windows-Kernel-Network.</summary>
    private static readonly Guid KernelNetworkProvider = new("7dd42a49-5329-4832-8dfd-43d979153a88");

    /// <summary>
    /// Session name. Fixed rather than randomised so a session leaked by a previous crash
    /// can be found and stopped instead of accumulating — ETW sessions outlive the process
    /// that created them and the system cap is finite.
    /// </summary>
    private const string SessionName = "NetworkSentinel-FlowEvents";

    // Kernel-Network keywords: which address families to report.
    private const ulong KeywordIpv4 = 0x10;
    private const ulong KeywordIpv6 = 0x20;

    // Event IDs, confirmed against the provider manifest (wevtutil gp /ge).
    private const int TcpV4Connect = 12;   // this host originated
    private const int TcpV4Accept = 15;    // the remote end originated
    private const int TcpV6Connect = 28;
    private const int TcpV6Accept = 31;
    private const int UdpV4Send = 42;
    private const int UdpV4Recv = 43;
    private const int UdpV6Send = 58;
    private const int UdpV6Recv = 59;

    private static readonly ushort[] WantedEventIds =
    {
        TcpV4Connect, TcpV4Accept, TcpV6Connect, TcpV6Accept,
        UdpV4Send, UdpV4Recv, UdpV6Send, UdpV6Recv
    };

    /// <summary>
    /// How long one 5-tuple stays deduplicated. ETW raises a UDP event per datagram, but
    /// consumers here want flow-creation semantics — without this a single DNS-heavy
    /// second would look like hundreds of new flows.
    /// </summary>
    private static readonly TimeSpan DedupeWindow = TimeSpan.FromSeconds(10);

    private const int DedupeMaxEntries = 4096;

    private readonly object _gate = new();
    private readonly Dictionary<string, DateTime> _recent = new(StringComparer.Ordinal);
    private DateTime _lastDedupeSweep = DateTime.UtcNow;

    private ulong _sessionHandle;
    private ulong _consumerHandle;
    private Thread? _reader;
    private volatile bool _stopping;
    private volatile string _status = "Flow events not started";
    private volatile bool _active;

    // Held as fields so the GC cannot collect the thunks while ETW holds pointers to them.
    private EventRecordCallback? _eventCallback;
    private BufferCallback? _bufferCallback;

    /// <summary>Raised on the ETW consumer thread for every new flow. Keep handlers cheap.</summary>
    public event Action<FlowEvent>? FlowCreated;

    /// <summary>Human-readable state of the ETW source.</summary>
    public string Status => _status;

    /// <summary>True when events are actually arriving rather than having degraded to polling.</summary>
    public bool IsActive => _active;

    public void Start()
    {
        lock (_gate)
        {
            if (_reader is { IsAlive: true })
                return;

            _stopping = false;

            if (!TryStartSession(out var error))
            {
                _status = error;
                _active = false;
                return;
            }

            _reader = new Thread(ConsumeLoop)
            {
                IsBackground = true,
                Name = "NetworkSentinel.FlowEvents"
            };
            _reader.Start();
        }
    }

    public void Stop()
    {
        Thread? reader;
        lock (_gate)
        {
            _stopping = true;
            reader = _reader;
            _reader = null;
        }

        StopSession();

        // ProcessTrace returns once the session is stopped and its buffers are flushed.
        if (reader is { IsAlive: true } && !reader.Join(TimeSpan.FromSeconds(5)))
            _status = "Flow events stopped (consumer did not exit cleanly)";
        else if (!_status.StartsWith("Flow events unavailable", StringComparison.Ordinal))
            _status = "Flow events stopped";

        _active = false;
        lock (_gate) _recent.Clear();
    }

    private bool TryStartSession(out string error)
    {
        // A session leaked by an earlier crash keeps the name; take it over rather than fail.
        var status = StartSession(out _sessionHandle);
        if (status == ErrorAlreadyExists)
        {
            ControlSession(EventTraceControlStop);
            status = StartSession(out _sessionHandle);
        }

        if (status != ErrorSuccess)
        {
            _sessionHandle = 0;
            error = status switch
            {
                ErrorAccessDenied =>
                    "Flow events unavailable: starting an ETW session needs Administrator — restart elevated, or leave timed polling on.",
                ErrorNoSystemResources =>
                    "Flow events unavailable: no ETW session slots left on this system.",
                _ => $"Flow events unavailable: StartTrace failed ({status})."
            };
            return false;
        }

        status = EnableProvider();
        if (status != ErrorSuccess)
        {
            // Always stop the session we just created — an abandoned ETW session outlives
            // this process and the system has a finite number of them.
            ControlSession(EventTraceControlStop);
            _sessionHandle = 0;
            // In practice this is where a non-elevated run fails: creating the session can
            // succeed, but attaching a kernel provider to it is the privileged part.
            error = status == ErrorAccessDenied
                ? "Flow events unavailable: subscribing to kernel network events needs Administrator — restart elevated, or leave timed polling on."
                : $"Flow events unavailable: EnableTraceEx2 failed ({status}).";
            return false;
        }

        error = "";
        return true;
    }

    private uint StartSession(out ulong handle)
    {
        // EVENT_TRACE_PROPERTIES is followed in the same allocation by the session name;
        // LoggerNameOffset points at it and ETW copies the name out of that trailing space.
        var nameBytes = (SessionName.Length + 1) * 2;
        var size = sizeof(EventTraceProperties) + nameBytes;
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            new Span<byte>((void*)buffer, size).Clear();

            var props = (EventTraceProperties*)buffer;
            props->Wnode.BufferSize = (uint)size;
            props->Wnode.Flags = WnodeFlagTracedGuid;
            props->Wnode.ClientContext = 1; // QPC timestamps
            props->LogFileMode = EventTraceRealTimeMode;
            props->BufferSize = 64;         // KB
            props->MinimumBuffers = 8;
            props->MaximumBuffers = 32;
            props->LoggerNameOffset = (uint)sizeof(EventTraceProperties);

            var nameTarget = new Span<char>((char*)(buffer + sizeof(EventTraceProperties)), SessionName.Length + 1);
            SessionName.AsSpan().CopyTo(nameTarget);
            nameTarget[SessionName.Length] = '\0';

            return StartTraceW(out handle, SessionName, buffer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private uint EnableProvider()
    {
        var provider = KernelNetworkProvider;

        // Filter to the handful of event IDs we act on. The provider has no keyword that
        // separates TCP from UDP, so without this the session would carry every data-sent
        // and data-received event on the box — orders of magnitude more than we read.
        var idCount = WantedEventIds.Length;
        var filterSize = 4 + idCount * 2;
        var filterBuffer = Marshal.AllocHGlobal(filterSize);
        try
        {
            var raw = (byte*)filterBuffer;
            raw[0] = 1;                 // FilterIn
            raw[1] = 0;                 // Reserved
            *(ushort*)(raw + 2) = (ushort)idCount;
            for (var i = 0; i < idCount; i++)
                *(ushort*)(raw + 4 + i * 2) = WantedEventIds[i];

            var descriptor = new EventFilterDescriptor
            {
                Ptr = (ulong)filterBuffer,
                Size = (uint)filterSize,
                Type = EventFilterTypeEventId
            };

            var parameters = new EnableTraceParameters
            {
                Version = 2,
                EnableFilterDesc = &descriptor,
                FilterDescCount = 1
            };

            var status = EnableTraceEx2(
                _sessionHandle, ref provider, EventControlCodeEnableProvider,
                TraceLevelInformation, KeywordIpv4 | KeywordIpv6, 0, 0, &parameters);

            if (status == ErrorSuccess)
                return status;

            // Event-ID filtering is not supported everywhere; a noisier session still works.
            return EnableTraceEx2(
                _sessionHandle, ref provider, EventControlCodeEnableProvider,
                TraceLevelInformation, KeywordIpv4 | KeywordIpv6, 0, 0, null);
        }
        finally
        {
            Marshal.FreeHGlobal(filterBuffer);
        }
    }

    private void ConsumeLoop()
    {
        _eventCallback = OnEventRecord;
        // Returning 0 tells ProcessTrace to stop delivering buffers and unwind.
        _bufferCallback = _ => _stopping ? 0u : 1u;

        var logfile = new EventTraceLogfile
        {
            LoggerName = Marshal.StringToHGlobalUni(SessionName),
            ProcessTraceMode = ProcessTraceModeRealTime | ProcessTraceModeEventRecord,
            EventRecordCallback = Marshal.GetFunctionPointerForDelegate(_eventCallback),
            BufferCallback = Marshal.GetFunctionPointerForDelegate(_bufferCallback)
        };

        try
        {
            _consumerHandle = OpenTraceW(ref logfile);
            if (_consumerHandle == InvalidTraceHandle)
            {
                _status = $"Flow events unavailable: OpenTrace failed ({Marshal.GetLastWin32Error()}).";
                _active = false;
                return;
            }

            _status = "Flow events active (ETW kernel network)";
            _active = true;

            var handles = new[] { _consumerHandle };
            var status = ProcessTrace(handles, 1, IntPtr.Zero, IntPtr.Zero);

            if (status != ErrorSuccess && !_stopping)
                _status = $"Flow events stopped: ProcessTrace returned {status}.";
        }
        catch (Exception ex)
        {
            _status = $"Flow events unavailable: {ex.Message}";
        }
        finally
        {
            _active = false;
            if (_consumerHandle != 0 && _consumerHandle != InvalidTraceHandle)
            {
                CloseTrace(_consumerHandle);
                _consumerHandle = 0;
            }
            if (logfile.LoggerName != IntPtr.Zero)
                Marshal.FreeHGlobal(logfile.LoggerName);
        }
    }

    private void StopSession()
    {
        if (_sessionHandle == 0)
            return;
        ControlSession(EventTraceControlStop);
        _sessionHandle = 0;
    }

    private void ControlSession(uint controlCode)
    {
        var nameBytes = (SessionName.Length + 1) * 2;
        var size = sizeof(EventTraceProperties) + nameBytes;
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            new Span<byte>((void*)buffer, size).Clear();
            var props = (EventTraceProperties*)buffer;
            props->Wnode.BufferSize = (uint)size;
            props->LoggerNameOffset = (uint)sizeof(EventTraceProperties);
            ControlTraceW(0, SessionName, buffer, controlCode);
        }
        catch
        {
            // Best effort — a session we cannot stop is reported by the next Start.
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private void OnEventRecord(EventRecord* record)
    {
        try
        {
            var flow = Decode(record);
            if (flow is null)
                return;

            if (!ClaimFresh(flow))
                return;

            FlowCreated?.Invoke(flow);
        }
        catch
        {
            // A malformed event must never take down the consumer thread.
        }
    }

    /// <summary>
    /// Collapses repeats of the same 5-tuple to one flow. ETW fires per datagram for UDP;
    /// consumers here are written against flow creation, not packet arrival.
    /// </summary>
    private bool ClaimFresh(FlowEvent flow)
    {
        var key = $"{flow.Protocol}|{flow.SourceAddress}|{flow.SourcePort}|{flow.DestinationAddress}|{flow.DestinationPort}";
        var now = DateTime.UtcNow;

        lock (_gate)
        {
            if (_recent.TryGetValue(key, out var seen) && now - seen < DedupeWindow)
                return false;

            _recent[key] = now;

            if (_recent.Count > DedupeMaxEntries || now - _lastDedupeSweep > DedupeWindow)
            {
                foreach (var stale in _recent.Where(kv => now - kv.Value >= DedupeWindow).Select(kv => kv.Key).ToList())
                    _recent.Remove(stale);
                _lastDedupeSweep = now;

                // Still oversized means a flood of distinct tuples (a scan); start clean
                // rather than let the dictionary grow without bound.
                if (_recent.Count > DedupeMaxEntries)
                    _recent.Clear();
            }
        }

        return true;
    }

    /// <summary>
    /// Turns one ETW record into a flow whose Source is the originator, matching the
    /// orientation the rest of the app expects: for an accepted connection the remote
    /// client is the source and the served local port is the destination.
    ///
    /// Which of saddr/daddr holds the local end is resolved by testing the addresses
    /// against this machine's own, not by assuming the provider's field order. Getting
    /// that backwards would hand the prevention engine this host's own address to
    /// firewall, so it is derived from something checkable rather than taken on trust;
    /// the field convention is only the fallback when neither end is local.
    /// </summary>
    private FlowEvent? Decode(EventRecord* record)
    {
        var id = record->EventHeader.EventDescriptor.Id;

        string protocol;
        bool remoteOriginated;
        switch (id)
        {
            case TcpV4Connect or TcpV6Connect:
                protocol = "tcp";
                remoteOriginated = false;
                break;
            case TcpV4Accept or TcpV6Accept:
                protocol = "tcp";
                remoteOriginated = true;
                break;
            case UdpV4Send or UdpV6Send:
                protocol = "udp";
                remoteOriginated = false;
                break;
            case UdpV4Recv or UdpV6Recv:
                protocol = "udp";
                remoteOriginated = true;
                break;
            default:
                return null;
        }

        var layout = EventLayout.For(record);
        if (layout is null)
            return null;

        var data = new ReadOnlySpan<byte>(record->UserData, record->UserDataLength);
        if (!layout.TryRead(data, out var sAddr, out var sPort, out var dAddr, out var dPort))
            return null;

        // Decide which endpoint is this machine by asking the machine, then let the event
        // type say who started the conversation. If exactly one end is ours, that settles
        // it; otherwise fall back to the provider's own convention that saddr is local.
        var sourceIsLocal = IsLocalAddress(sAddr);
        var destIsLocal = IsLocalAddress(dAddr);

        string localAddr, remoteAddr;
        int localPort, remotePort;
        if (destIsLocal && !sourceIsLocal)
        {
            localAddr = dAddr; localPort = dPort;
            remoteAddr = sAddr; remotePort = sPort;
        }
        else
        {
            localAddr = sAddr; localPort = sPort;
            remoteAddr = dAddr; remotePort = dPort;
        }

        // For an accept or an inbound datagram the operation is inbound, so the
        // originator — what the rest of the app treats as the threat source — is the
        // remote end.
        return remoteOriginated
            ? new FlowEvent
            {
                Protocol = protocol,
                SourceAddress = remoteAddr,
                SourcePort = remotePort,
                DestinationAddress = localAddr,
                DestinationPort = localPort
            }
            : new FlowEvent
            {
                Protocol = protocol,
                SourceAddress = localAddr,
                SourcePort = localPort,
                DestinationAddress = remoteAddr,
                DestinationPort = remotePort
            };
    }

    /// <summary>
    /// Addresses that mean "this machine", refreshed periodically because a DHCP lease or
    /// a tunnel coming up changes them while the session is running.
    /// </summary>
    private volatile HashSet<string> _localAddresses = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _localAddressesAt = DateTime.MinValue;
    private static readonly TimeSpan LocalAddressRefresh = TimeSpan.FromMinutes(1);

    private bool IsLocalAddress(string ip)
    {
        var now = DateTime.UtcNow;
        if (now - _localAddressesAt >= LocalAddressRefresh)
        {
            _localAddressesAt = now;
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "127.0.0.1", "::1" };
            try
            {
                foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up)
                        continue;
                    foreach (var addr in ni.GetIPProperties().UnicastAddresses)
                        set.Add(addr.Address.ToString());
                }
                _localAddresses = set;
            }
            catch
            {
                // Keep the previous snapshot rather than calling every address remote.
            }
        }

        return _localAddresses.Contains(ip);
    }

    /// <summary>
    /// Where saddr/daddr/sport/dport sit inside one event's payload, discovered once per
    /// event ID from the provider's own schema via TDH and then cached.
    ///
    /// This is looked up by property *name* rather than by hand-computed offsets on
    /// purpose. A wrong offset here would not throw — it would silently yield a plausible
    /// but wrong address, and the prevention engine would firewall it. If the schema is
    /// not what we expect, the event is dropped instead of guessed at.
    /// </summary>
    private sealed class EventLayout
    {
        private static readonly Dictionary<(ushort Id, byte Version), EventLayout?> Cache = new();
        private static readonly object CacheGate = new();

        private int _saddrOffset;
        private int _daddrOffset;
        private int _sportOffset;
        private int _dportOffset;
        private int _addrLength;   // 4 for IPv4, 16 for IPv6
        private int _minLength;

        public static EventLayout? For(EventRecord* record)
        {
            var key = (record->EventHeader.EventDescriptor.Id, record->EventHeader.EventDescriptor.Version);
            lock (CacheGate)
            {
                if (Cache.TryGetValue(key, out var cached))
                    return cached;
            }

            var built = Build(record);
            lock (CacheGate) Cache[key] = built;
            return built;
        }

        private static EventLayout? Build(EventRecord* record)
        {
            uint size = 0;
            var status = TdhGetEventInformation(record, 0, IntPtr.Zero, IntPtr.Zero, ref size);
            if (status != ErrorInsufficientBuffer || size == 0)
                return null;

            var buffer = Marshal.AllocHGlobal((int)size);
            try
            {
                status = TdhGetEventInformation(record, 0, IntPtr.Zero, buffer, ref size);
                if (status != ErrorSuccess)
                    return null;

                var raw = (byte*)buffer;
                var propertyCount = *(uint*)(raw + TraceEventInfoPropertyCountOffset);
                if (propertyCount == 0 || propertyCount > 64)
                    return null;

                var layout = new EventLayout();
                var offset = 0;
                var found = 0;

                for (var i = 0u; i < propertyCount; i++)
                {
                    var info = raw + TraceEventInfoPropertyArrayOffset + i * EventPropertyInfoSize;

                    var flags = *(uint*)info;
                    if ((flags & PropertyVariableLayoutMask) != 0)
                        return null; // struct / variable-length: not the flat template we expect

                    var nameOffset = *(uint*)(info + 4);
                    var inType = *(ushort*)(info + 8);
                    var outType = *(ushort*)(info + 10);
                    var count = *(ushort*)(info + 16);
                    var length = *(ushort*)(info + 18);

                    if (count != 1)
                        return null;

                    var fieldSize = SizeOf(inType, length);
                    if (fieldSize <= 0)
                        return null;

                    var name = nameOffset == 0
                        ? ""
                        : Marshal.PtrToStringUni((IntPtr)(raw + nameOffset)) ?? "";

                    switch (name)
                    {
                        // The output type is what pins down byte order, so it is checked
                        // rather than assumed: an address field that is not declared
                        // IPv4/IPv6, or a port not declared win:Port, is not something
                        // this parser knows how to read.
                        case "saddr" or "daddr":
                            if (!IsAddressField(outType, fieldSize)) return null;
                            if (layout._addrLength != 0 && layout._addrLength != fieldSize) return null;
                            layout._addrLength = fieldSize;
                            if (name == "saddr") layout._saddrOffset = offset;
                            else layout._daddrOffset = offset;
                            found++;
                            break;
                        case "sport" or "dport":
                            if (fieldSize != 2 || outType != TdhOuttypePort) return null;
                            if (name == "sport") layout._sportOffset = offset;
                            else layout._dportOffset = offset;
                            found++;
                            break;
                    }

                    offset += fieldSize;
                }

                if (found != 4 || layout._addrLength is not (4 or 16))
                    return null;

                layout._minLength = Math.Max(
                    Math.Max(layout._saddrOffset, layout._daddrOffset) + layout._addrLength,
                    Math.Max(layout._sportOffset, layout._dportOffset) + 2);

                return layout;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// An address field is a 4-byte UINT32 tagged IPv4, or a 16-byte binary blob
        /// tagged IPv6. Both are already in network byte order in the payload.
        /// </summary>
        private static bool IsAddressField(ushort outType, int fieldSize)
            => (outType == TdhOuttypeIpv4 && fieldSize == 4)
            || (outType == TdhOuttypeIpv6 && fieldSize == 16);

        /// <summary>Payload width of one fixed-size TDH input type, or -1 if it isn't one.</summary>
        private static int SizeOf(ushort inType, ushort declaredLength) => inType switch
        {
            TdhIntypeInt8 or TdhIntypeUint8 => 1,
            TdhIntypeInt16 or TdhIntypeUint16 => 2,
            // TDH_INTYPE_BOOLEAN is a 32-bit value, not a byte.
            TdhIntypeInt32 or TdhIntypeUint32 or TdhIntypeHexInt32 or TdhIntypeFloat
                or TdhIntypeBoolean => 4,
            TdhIntypeInt64 or TdhIntypeUint64 or TdhIntypeHexInt64 or TdhIntypeDouble
                or TdhIntypeFiletime => 8,
            TdhIntypeGuid => 16,
            TdhIntypePointer => IntPtr.Size,
            // The IPv6 address fields are declared as fixed-length binary.
            TdhIntypeBinary => declaredLength > 0 ? declaredLength : -1,
            _ => -1
        };

        /// <summary>Reads the four fields as the provider names them — saddr/daddr, not local/remote.</summary>
        public bool TryRead(
            ReadOnlySpan<byte> data,
            out string sourceAddress, out int sourcePort,
            out string destAddress, out int destPort)
        {
            sourceAddress = destAddress = "";
            sourcePort = destPort = 0;

            if (data.Length < _minLength)
                return false;

            try
            {
                sourceAddress = new IPAddress(data.Slice(_saddrOffset, _addrLength)).ToString();
                destAddress = new IPAddress(data.Slice(_daddrOffset, _addrLength)).ToString();
            }
            catch
            {
                return false;
            }

            // Ports carry the win:Port output type, which is network byte order on the wire.
            sourcePort = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(_sportOffset, 2));
            destPort = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(_dportOffset, 2));
            return true;
        }
    }

    public void Dispose()
    {
        Stop();
        StopSession();
    }

    // ---- Win32 -------------------------------------------------------------------

    private const uint ErrorSuccess = 0;
    private const uint ErrorAccessDenied = 5;
    private const uint ErrorInsufficientBuffer = 122;
    private const uint ErrorAlreadyExists = 183;
    private const uint ErrorNoSystemResources = 1450;

    private const uint WnodeFlagTracedGuid = 0x00020000;
    private const uint EventTraceRealTimeMode = 0x00000100;
    private const uint EventTraceControlStop = 1;

    private const uint ProcessTraceModeRealTime = 0x00000100;
    private const uint ProcessTraceModeEventRecord = 0x10000000;

    private const uint EventControlCodeEnableProvider = 1;
    private const byte TraceLevelInformation = 4;
    private const uint EventFilterTypeEventId = 0x80000200;

    private const ulong InvalidTraceHandle = 0xFFFFFFFFFFFFFFFF;

    // Offsets inside TRACE_EVENT_INFO, whose leading fields are all fixed width:
    // two GUIDs (32) + EVENT_DESCRIPTOR (16) + 15 ULONGs.
    private const int TraceEventInfoPropertyCountOffset = 100;
    private const int TraceEventInfoPropertyArrayOffset = 112;
    private const int EventPropertyInfoSize = 24;

    // _TDH_IN_TYPE. Verified against this provider's own manifest: the Kernel-Network
    // templates use UINT32 (8) for PID/size/IPv4 addresses, UINT16 (6) for ports, and
    // fixed-length BINARY (14) for IPv6 addresses.
    private const ushort TdhIntypeInt8 = 3;
    private const ushort TdhIntypeUint8 = 4;
    private const ushort TdhIntypeInt16 = 5;
    private const ushort TdhIntypeUint16 = 6;
    private const ushort TdhIntypeInt32 = 7;
    private const ushort TdhIntypeUint32 = 8;
    private const ushort TdhIntypeInt64 = 9;
    private const ushort TdhIntypeUint64 = 10;
    private const ushort TdhIntypeFloat = 11;
    private const ushort TdhIntypeDouble = 12;
    private const ushort TdhIntypeBoolean = 13;
    private const ushort TdhIntypeBinary = 14;
    private const ushort TdhIntypeGuid = 15;
    private const ushort TdhIntypePointer = 16;
    private const ushort TdhIntypeFiletime = 17;
    private const ushort TdhIntypeHexInt32 = 20;
    private const ushort TdhIntypeHexInt64 = 21;

    // _TDH_OUT_TYPE, for the fields whose byte order depends on it.
    private const ushort TdhOuttypePort = 22;
    private const ushort TdhOuttypeIpv4 = 23;
    private const ushort TdhOuttypeIpv6 = 24;

    // _PROPERTY_FLAGS. The first three mean the payload is not a flat run of
    // fixed-width fields and cannot be walked by accumulating sizes; FixedLength
    // and FixedCount are just telling us the width is in the struct already.
    private const uint PropertyStruct = 0x1;
    private const uint PropertyParamLength = 0x2;
    private const uint PropertyParamCount = 0x4;
    private const uint PropertyVariableLayoutMask = PropertyStruct | PropertyParamLength | PropertyParamCount;

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate void EventRecordCallback(EventRecord* record);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate uint BufferCallback(IntPtr logfile);

    [StructLayout(LayoutKind.Sequential)]
    private struct WnodeHeader
    {
        public uint BufferSize;
        public uint ProviderId;
        public ulong HistoricalContext;
        public long TimeStamp;
        public Guid Guid;
        public uint ClientContext;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EventTraceProperties
    {
        public WnodeHeader Wnode;
        public uint BufferSize;
        public uint MinimumBuffers;
        public uint MaximumBuffers;
        public uint MaximumFileSize;
        public uint LogFileMode;
        public uint FlushTimer;
        public uint EnableFlags;
        public int AgeLimit;
        public uint NumberOfBuffers;
        public uint FreeBuffers;
        public uint EventsLost;
        public uint BuffersWritten;
        public uint LogBuffersLost;
        public uint RealTimeBuffersLost;
        public IntPtr LoggerThreadId;
        public uint LogFileNameOffset;
        public uint LoggerNameOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EventFilterDescriptor
    {
        public ulong Ptr;
        public uint Size;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EnableTraceParameters
    {
        public uint Version;
        public uint EnableProperty;
        public uint ControlFlags;
        public Guid SourceId;
        public EventFilterDescriptor* EnableFilterDesc;
        public uint FilterDescCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EventDescriptor
    {
        public ushort Id;
        public byte Version;
        public byte Channel;
        public byte Level;
        public byte Opcode;
        public ushort Task;
        public ulong Keyword;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EventHeader
    {
        public ushort Size;
        public ushort HeaderType;
        public ushort Flags;
        public ushort EventProperty;
        public uint ThreadId;
        public uint ProcessId;
        public long TimeStamp;
        public Guid ProviderId;
        public EventDescriptor EventDescriptor;
        public ulong ProcessorTime;
        public Guid ActivityId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EtwBufferContext
    {
        public byte ProcessorNumber;
        public byte Alignment;
        public ushort LoggerId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EventRecord
    {
        public EventHeader EventHeader;
        public EtwBufferContext BufferContext;
        public ushort ExtendedDataCount;
        public ushort UserDataLength;
        public IntPtr ExtendedData;
        public byte* UserData;
        public IntPtr UserContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EventTraceHeader
    {
        public ushort Size;
        public ushort FieldTypeFlags;
        public uint Version;
        public uint ThreadId;
        public uint ProcessId;
        public long TimeStamp;
        public Guid Guid;
        public ulong ProcessorTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EventTrace
    {
        public EventTraceHeader Header;
        public uint InstanceId;
        public uint ParentInstanceId;
        public Guid ParentGuid;
        public IntPtr MofData;
        public uint MofLength;
        public uint ClientContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SystemTime
    {
        public ushort Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds;
    }

    // Fixed buffers rather than marshalled char[] so the whole EVENT_TRACE_LOGFILEW stays
    // blittable: OpenTrace then receives a pointer to our struct instead of a marshaller
    // copy, which is what lets the callback fields survive the call unchanged.
    [StructLayout(LayoutKind.Sequential)]
    private struct TimeZoneInformation
    {
        public int Bias;
        public fixed char StandardName[32];
        public SystemTime StandardDate;
        public int StandardBias;
        public fixed char DaylightName[32];
        public SystemTime DaylightDate;
        public int DaylightBias;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TraceLogfileHeader
    {
        public uint BufferSize;
        public uint Version;
        public uint ProviderVersion;
        public uint NumberOfProcessors;
        public long EndTime;
        public uint TimerResolution;
        public uint MaximumFileSize;
        public uint LogFileMode;
        public uint BuffersWritten;
        public Guid LogInstanceGuid;
        public IntPtr LoggerName;
        public IntPtr LogFileName;
        public TimeZoneInformation TimeZone;
        public long BootTime;
        public long PerfFreq;
        public long StartTime;
        public uint ReservedFlags;
        public uint BuffersLost;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct EventTraceLogfile
    {
        public IntPtr LogFileName;
        public IntPtr LoggerName;
        public long CurrentTime;
        public uint BuffersRead;
        public uint ProcessTraceMode;
        public EventTrace CurrentEvent;
        public TraceLogfileHeader LogfileHeader;
        public IntPtr BufferCallback;
        public uint BufferSize;
        public uint Filled;
        public uint EventsLost;
        public IntPtr EventRecordCallback;
        public uint IsKernelTrace;
        public IntPtr Context;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint StartTraceW(out ulong handle, string sessionName, IntPtr properties);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint ControlTraceW(ulong handle, string sessionName, IntPtr properties, uint controlCode);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint EnableTraceEx2(
        ulong handle, ref Guid providerId, uint controlCode, byte level,
        ulong matchAnyKeyword, ulong matchAllKeyword, uint timeout, EnableTraceParameters* parameters);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ulong OpenTraceW(ref EventTraceLogfile logfile);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint ProcessTrace(ulong[] handles, uint handleCount, IntPtr startTime, IntPtr endTime);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint CloseTrace(ulong handle);

    [DllImport("tdh.dll", SetLastError = true)]
    private static extern uint TdhGetEventInformation(
        EventRecord* record, uint contextCount, IntPtr context, IntPtr buffer, ref uint bufferSize);
}
