using System.Globalization;
using System.IO;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Measures how much data crosses this machine's network interfaces, in each
/// direction, and keeps a per-day history so the dashboard can show the month.
///
/// The source is the per-interface octet counters Windows keeps for every
/// adapter, read through <see cref="NetworkInterface.GetIPStatistics"/>. They are
/// cumulative, need no elevation and no packet capture, and — unlike the macOS
/// build's <c>netstat -ib</c> — cost no subprocess at all. Each sample is diffed
/// against the previous one, so the meter reports traffic, not the counter value.
///
/// Three details the numbers depend on:
///   - <b>One row per adapter.</b> Windows keeps one counter pair per interface,
///     already summed across its addresses, so nothing has to be de-duplicated the
///     way the macOS parser skips all but the <c>&lt;Link#n&gt;</c> row.
///   - <b>Physical links only.</b> A tunnel (WireGuard, IKEv2, SSTP, an OpenVPN
///     TAP adapter) carries the same bytes that already crossed the physical link,
///     encapsulated — counting both double-counts every tunnelled byte. The same
///     goes for Hyper-V and VMware virtual switches, a teaming multiplexor above
///     its members, and the KM-TEST loopback adapter. Real loopback is excluded
///     for the reason it is excluded from the connection views: it never leaves
///     the machine. See <see cref="IsMeteredInterface"/>.
///   - <b>Counters reset.</b> A reboot or an adapter bounce restarts them at zero.
///     A counter that moved backwards is treated as a fresh start and its current
///     value is the delta, matching <see cref="ExfiltrationMonitor"/>.
///
/// The daily history persists to <c>traffic-history.json</c>, and so do the last
/// raw counters: on the next launch the diff continues from where it left off,
/// so traffic that crossed the wire while the console was closed still lands in
/// the right day rather than vanishing or arriving as one huge spike.
/// </summary>
public sealed class TrafficMeterService : IDisposable
{
    /// <summary>
    /// Sample cadence. Fast enough for a live rate chart, slow enough that the
    /// reads stay invisible.
    /// </summary>
    private static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(5);

    /// <summary>Live samples retained — 120 × 5 s is the last 10 minutes.</summary>
    private const int LiveSampleCap = 120;

    /// <summary>
    /// Days of history kept. 400 covers a 12-month chart plus the running month
    /// with room for the rollover.
    /// </summary>
    private const int RetentionDays = 400;

    /// <summary>
    /// How often the history file is rewritten. Every sample would be a disk
    /// write every 5 s for a file only the charts read; a minute of lost history
    /// after a crash is not worth that.
    /// </summary>
    private static readonly TimeSpan SaveInterval = TimeSpan.FromMinutes(1);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly object _gate = new();
    private readonly List<TrafficSample> _live = new();
    private readonly Dictionary<string, DayTotal> _days = new(StringComparer.Ordinal);
    private readonly Dictionary<string, InterfaceCounter> _counters = new(StringComparer.Ordinal);

    private CancellationTokenSource? _cts;
    private Task? _loop;
    private bool _firstSampleOfRun = true;
    private DateTime _lastSampleTime;
    private DateTime _lastSaveUtc = DateTime.MinValue;
    private volatile string _status = "Traffic meter not started";
    private volatile bool _loaded;

    /// <summary>Raised after each sample so the UI can redraw off the meter's cadence.</summary>
    public event Action? Updated;

    public string Status => _status;

    public bool IsRunning => _loop != null;

    public void Start()
    {
        lock (_gate)
        {
            if (_cts != null) return;
            LoadHistory();
            // A restart after the meter was switched off has the same gap as a
            // restart of the app: count the catch-up, do not chart it as a rate.
            _firstSampleOfRun = true;
            _lastSampleTime = default;
            _cts = new CancellationTokenSource();
            _loop = Task.Run(() => RunAsync(_cts.Token));
        }
        _status = "Reading adapter byte counters";
    }

    public void Stop()
    {
        CancellationTokenSource? cts;
        lock (_gate)
        {
            cts = _cts;
            _cts = null;
        }
        if (cts == null) return;

        cts.Cancel();
        try { _loop?.Wait(2000); } catch { /* shutting down */ }
        cts.Dispose();
        _loop = null;
        SaveHistory();
        _status = "Traffic meter stopped";
    }

    /// <summary>Recent throughput readings, oldest first.</summary>
    public IReadOnlyList<TrafficSample> Live
    {
        get { lock (_gate) return _live.ToList(); }
    }

    /// <summary>Bytes in/out so far in the calendar month containing <paramref name="anyDayInMonth"/>.</summary>
    public TrafficBucket MonthTotal(DateTime anyDayInMonth)
    {
        var start = new DateTime(anyDayInMonth.Year, anyDayInMonth.Month, 1);
        long inBytes = 0, outBytes = 0;
        lock (_gate)
        {
            foreach (var (key, total) in _days)
            {
                if (!TryParseDayKey(key, out var day)) continue;
                if (day.Year == start.Year && day.Month == start.Month)
                {
                    inBytes += total.In;
                    outBytes += total.Out;
                }
            }
        }

        return new TrafficBucket
        {
            Start = start,
            Label = start.ToString("MMMM yyyy"),
            BytesIn = inBytes,
            BytesOut = outBytes
        };
    }

    /// <summary>
    /// One bucket per day of the given month, zero-filled through today (or
    /// through the last day, for a month already past) so the chart keeps a
    /// stable x-axis instead of stretching two samples across the card.
    /// </summary>
    public IReadOnlyList<TrafficBucket> DailyBuckets(DateTime anyDayInMonth)
    {
        var start = new DateTime(anyDayInMonth.Year, anyDayInMonth.Month, 1);
        var today = DateTime.Today;
        var lastDay = start.Year == today.Year && start.Month == today.Month
            ? today.Day
            : DateTime.DaysInMonth(start.Year, start.Month);

        var buckets = new List<TrafficBucket>(lastDay);
        lock (_gate)
        {
            for (var day = 1; day <= lastDay; day++)
            {
                var date = start.AddDays(day - 1);
                _days.TryGetValue(DayKey(date), out var total);
                buckets.Add(new TrafficBucket
                {
                    Start = date,
                    Label = day.ToString(CultureInfo.InvariantCulture),
                    BytesIn = total.In,
                    BytesOut = total.Out
                });
            }
        }
        return buckets;
    }

    /// <summary>One bucket per calendar month, ending with the current month.</summary>
    public IReadOnlyList<TrafficBucket> MonthlyBuckets(int months)
    {
        months = Math.Clamp(months, 1, 24);
        var first = new DateTime(DateTime.Today.Year, DateTime.Today.Month, 1).AddMonths(-(months - 1));
        var totals = new Dictionary<DateTime, (long In, long Out)>();

        lock (_gate)
        {
            foreach (var (key, total) in _days)
            {
                if (!TryParseDayKey(key, out var day)) continue;
                var month = new DateTime(day.Year, day.Month, 1);
                if (month < first) continue;
                totals.TryGetValue(month, out var running);
                totals[month] = (running.In + total.In, running.Out + total.Out);
            }
        }

        var buckets = new List<TrafficBucket>(months);
        for (var i = 0; i < months; i++)
        {
            var month = first.AddMonths(i);
            totals.TryGetValue(month, out var total);
            buckets.Add(new TrafficBucket
            {
                Start = month,
                // Single letter would collide (June/July); "Jun" fits the axis.
                Label = month.ToString("MMM"),
                BytesIn = total.In,
                BytesOut = total.Out
            });
        }
        return buckets;
    }

    private async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                SampleOnce(DateTime.Now);
            }
            catch (Exception ex)
            {
                _status = $"Traffic meter error: {ex.Message}";
            }

            try { Updated?.Invoke(); }
            catch { /* a bad handler must not kill the loop */ }

            try { await Task.Delay(SampleInterval, ct); }
            catch (OperationCanceledException) { break; }
        }
    }

    private void SampleOnce(DateTime now)
    {
        var current = ReadInterfaceCounters();
        if (current == null)
        {
            _status = "Adapter byte counters unreadable — traffic metering off";
            return;
        }

        if (current.Count == 0)
        {
            _status = "No physical adapters reporting byte counters";
            return;
        }

        long deltaIn = 0, deltaOut = 0;
        var first = false;

        lock (_gate)
        {
            foreach (var (name, counter) in current)
            {
                if (_counters.TryGetValue(name, out var previous))
                {
                    deltaIn += Delta(previous.In, counter.In);
                    deltaOut += Delta(previous.Out, counter.Out);
                }
                else
                {
                    // An adapter seen for the first time in this run has no
                    // baseline to diff against; the next sample is its first
                    // contribution. (A persisted baseline is loaded up front, so
                    // this is a genuinely new adapter, not a fresh launch.)
                    first = true;
                }
                _counters[name] = counter;
            }

            // Adapters that disappeared (VPN down, dock unplugged) are dropped so
            // their stale counters cannot be diffed against a later, unrelated one.
            foreach (var gone in _counters.Keys.Where(k => !current.ContainsKey(k)).ToList())
                _counters.Remove(gone);

            var elapsed = _lastSampleTime == default
                ? SampleInterval
                : now - _lastSampleTime;
            _lastSampleTime = now;

            if (deltaIn > 0 || deltaOut > 0)
                AddToDay(now, deltaIn, deltaOut);

            // The first delta of a run spans however long the console was closed —
            // the persisted counters make that traffic countable, but dividing it by
            // the sample interval would draw a multi-megabyte-per-second spike that
            // never happened, and the shared scale would flatten every real reading
            // after it. It counts toward the day; it does not become a rate.
            var seconds = Math.Max(0.5, elapsed.TotalSeconds);
            _live.Add(new TrafficSample
            {
                Time = now,
                BytesInPerSecond = _firstSampleOfRun ? 0 : deltaIn / seconds,
                BytesOutPerSecond = _firstSampleOfRun ? 0 : deltaOut / seconds
            });
            _firstSampleOfRun = false;
            if (_live.Count > LiveSampleCap)
                _live.RemoveRange(0, _live.Count - LiveSampleCap);

            TrimHistory();
        }

        var month = MonthTotal(now);
        _status = first
            ? $"Metering {current.Count} adapter(s) — baselining"
            : $"Metering {current.Count} adapter(s) · {month.Label}: {month.InText} in / {month.OutText} out";

        if (DateTime.UtcNow - _lastSaveUtc >= SaveInterval)
            SaveHistory();
    }

    /// <summary>Caller holds <see cref="_gate"/>.</summary>
    private void AddToDay(DateTime when, long bytesIn, long bytesOut)
    {
        var key = DayKey(when);
        _days.TryGetValue(key, out var total);
        _days[key] = new DayTotal(total.In + bytesIn, total.Out + bytesOut);
    }

    /// <summary>Caller holds <see cref="_gate"/>.</summary>
    private void TrimHistory()
    {
        if (_days.Count <= RetentionDays) return;
        var cutoff = DateTime.Today.AddDays(-RetentionDays);
        foreach (var key in _days.Keys.ToList())
        {
            if (TryParseDayKey(key, out var day) && day < cutoff)
                _days.Remove(key);
            else if (!TryParseDayKey(key, out _))
                _days.Remove(key); // hand-edited garbage
        }
    }

    /// <summary>
    /// A counter that went backwards restarted (reboot, adapter bounce), so the
    /// current value is itself the traffic since the reset.
    /// </summary>
    internal static long Delta(long previous, long current)
        => current >= previous ? current - previous : Math.Max(0, current);

    /// <summary>
    /// Reads the octet counters of every metered adapter. Null when the adapter
    /// table itself could not be read; an empty map means the table was read and
    /// nothing in it is worth metering.
    /// </summary>
    private static Dictionary<string, InterfaceCounter>? ReadInterfaceCounters()
    {
        NetworkInterface[] adapters;
        try
        {
            adapters = NetworkInterface.GetAllNetworkInterfaces();
        }
        catch
        {
            return null;
        }

        var result = new Dictionary<string, InterfaceCounter>(StringComparer.Ordinal);
        foreach (var adapter in adapters)
        {
            if (!IsMeteredInterface(adapter.NetworkInterfaceType, adapter.Name, adapter.Description))
                continue;

            // An adapter that is not up carries nothing, and its counters are
            // frozen — keeping it would only hold a stale baseline for an adapter
            // that may come back with the counters restarted.
            if (adapter.OperationalStatus != OperationalStatus.Up)
                continue;

            try
            {
                var stats = adapter.GetIPStatistics();
                // Id, not Name: two adapters can be renamed to the same thing, and a
                // rename must not read as "a new adapter with no baseline".
                result[adapter.Id] = new InterfaceCounter(
                    Math.Max(0, stats.BytesReceived), Math.Max(0, stats.BytesSent));
            }
            catch (NetworkInformationException)
            {
                // A driver that will not answer for one adapter must not cost the
                // sample every other adapter's traffic.
            }
        }

        return result;
    }

    /// <summary>
    /// Physical links only. Everything else on a Windows host either carries bytes
    /// that were already counted on the physical link, or never leaves the machine.
    ///
    /// The type alone is not enough. Windows reports its own IKEv2/SSTP/Teredo
    /// tunnels as <see cref="NetworkInterfaceType.Tunnel"/>, but a WireGuard
    /// (Wintun) adapter, an OpenVPN TAP adapter, a Hyper-V virtual switch and the
    /// KM-TEST loopback adapter all present as ordinary Ethernet — so the driver
    /// description has to be read too. The keywords below are what those drivers
    /// call themselves; a virtual adapter this list does not know would be counted
    /// twice, which is why the list names families ("Virtual", "TAP-") rather than
    /// individual products.
    ///
    /// Metering a teaming multiplexor <i>and</i> its members would double every
    /// byte, so the members are counted and the team is not — the same choice the
    /// Linux build makes for a bond master.
    /// </summary>
    internal static bool IsMeteredInterface(NetworkInterfaceType type, string name, string description)
    {
        // Loopback never leaves the machine; a tunnel re-counts bytes that already
        // crossed the physical link; PPP (PPPoE, dial-up VPN) rides an adapter that
        // is itself metered here.
        if (type is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp)
            return false;

        if (type is not (NetworkInterfaceType.Ethernet
            or NetworkInterfaceType.GigabitEthernet
            or NetworkInterfaceType.FastEthernetT
            or NetworkInterfaceType.FastEthernetFx
            or NetworkInterfaceType.Wireless80211
            or NetworkInterfaceType.Wman
            or NetworkInterfaceType.Wwanpp
            or NetworkInterfaceType.Wwanpp2))
        {
            return false;
        }

        var text = $"{name} {description}";
        foreach (var marker in VirtualAdapterMarkers)
        {
            if (text.Contains(marker, StringComparison.OrdinalIgnoreCase))
                return false;
        }

        return true;
    }

    /// <summary>
    /// Driver and adapter names that mean "this is not a wire". Matched against the
    /// adapter's name and description together, case-insensitively.
    /// </summary>
    private static readonly string[] VirtualAdapterMarkers =
    {
        "vEthernet",        // Hyper-V virtual switch ports
        "Hyper-V",
        "Virtual Ethernet", // VMware, Hyper-V's own description
        "VMware",
        "VirtualBox",
        "Loopback",         // Microsoft KM-TEST / Npcap loopback, which claim Ethernet
        "WireGuard",
        "Wintun",
        "TAP-",             // OpenVPN and every VPN client that ships a TAP driver
        "TAP Windows",
        "OpenVPN",
        "Tailscale",
        "ZeroTier",
        "Multiplexor",      // NIC teaming above its own members
        "Bluetooth",        // PAN, which rides nothing this host owns
        "Teredo",
        "ISATAP",
        "Pseudo-Interface"
    };

    // ── Persistence ──────────────────────────────────────────────────────

    internal static string HistoryPath
        => Path.Combine(AppPaths.DataDirectory, "traffic-history.json");

    private void LoadHistory()
    {
        if (_loaded) return;
        _loaded = true;
        try
        {
            if (!File.Exists(HistoryPath)) return;
            var store = JsonSerializer.Deserialize<TrafficStore>(File.ReadAllText(HistoryPath), JsonOptions);
            if (store == null) return;

            foreach (var day in store.Days)
            {
                if (string.IsNullOrWhiteSpace(day.Date)) continue;
                _days[day.Date] = new DayTotal(Math.Max(0, day.In), Math.Max(0, day.Out));
            }
            foreach (var (name, counter) in store.Counters)
                _counters[name] = new InterfaceCounter(Math.Max(0, counter.In), Math.Max(0, counter.Out));

            TrimHistory();
        }
        catch
        {
            // A corrupt history costs the chart its past, not the meter its future.
        }
    }

    private void SaveHistory()
    {
        TrafficStore store;
        lock (_gate)
        {
            store = new TrafficStore
            {
                UpdatedUtc = DateTime.UtcNow,
                Days = _days
                    .OrderBy(kv => kv.Key, StringComparer.Ordinal)
                    .Select(kv => new TrafficDayRecord { Date = kv.Key, In = kv.Value.In, Out = kv.Value.Out })
                    .ToList(),
                Counters = _counters.ToDictionary(
                    kv => kv.Key,
                    kv => new TrafficCounterRecord { In = kv.Value.In, Out = kv.Value.Out },
                    StringComparer.Ordinal)
            };
        }

        try
        {
            AppPaths.WriteAtomic(HistoryPath, JsonSerializer.Serialize(store, JsonOptions));
            _lastSaveUtc = DateTime.UtcNow;
        }
        catch
        {
            // best-effort
        }
    }

    private static string DayKey(DateTime when) => when.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    private static bool TryParseDayKey(string key, out DateTime day)
        => DateTime.TryParseExact(key, "yyyy-MM-dd", CultureInfo.InvariantCulture,
            DateTimeStyles.None, out day);

    public void Dispose() => Stop();

    internal readonly record struct InterfaceCounter(long In, long Out);

    private readonly record struct DayTotal(long In, long Out);

    private sealed class TrafficStore
    {
        public DateTime UpdatedUtc { get; set; }
        public List<TrafficDayRecord> Days { get; set; } = new();
        public Dictionary<string, TrafficCounterRecord> Counters { get; set; } = new(StringComparer.Ordinal);
    }

    private sealed class TrafficDayRecord
    {
        public string Date { get; set; } = "";
        public long In { get; set; }
        public long Out { get; set; }
    }

    private sealed class TrafficCounterRecord
    {
        public long In { get; set; }
        public long Out { get; set; }
    }
}
