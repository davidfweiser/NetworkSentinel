using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// Runs the meter end to end through <c>traffic-history.json</c> on a pretend machine
/// whose adapter counters and boot time the test sets: a launch reads the file, takes
/// one sample and closes, the way the console does. What these pin down is the one
/// thing the pure helpers cannot show — that the counters a launch saves are trusted
/// by the next one exactly when they are still the ones Windows is counting.
/// </summary>
public sealed class TrafficMeterPersistenceTests : IDisposable
{
    private const long MB = 1_000_000;
    private const long GB = 1_000_000_000;

    // Adapters are keyed by NetworkInterface.Id, which is the adapter's GUID.
    private const string Ethernet = "{3F2E1B6A-7C4D-4E8F-9A1B-2C3D4E5F6A7B}";
    private const string WiFi = "{8D9C0B1A-2E3F-4A5B-8C7D-6E5F4A3B2C1D}";
    private const string Dock = "{C4B5A697-8D7E-4F60-A1B2-C3D4E5F60718}";

    private static readonly DateTime Noon = new(2026, 11, 7, 12, 0, 0);

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ns-traffic-" + Guid.NewGuid().ToString("N"));
    private readonly string _historyPath;
    private readonly FakeMachine _machine = new();

    public TrafficMeterPersistenceTests()
    {
        Directory.CreateDirectory(_dir);
        _historyPath = Path.Combine(_dir, "traffic-history.json");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* temp */ }
    }

    [Fact]
    public void ReopeningWithinABootCountsOnlyTheGrowth()
    {
        _machine.Boot(DateTime.UtcNow.AddHours(-1));
        _machine.Counters[Ethernet] = (100 * MB, 40 * MB);
        Assert.Equal((0L, 0L), Launch()); // no history yet: the first launch baselines

        _machine.Counters[Ethernet] = (150 * MB, 45 * MB);
        Assert.Equal((50 * MB, 5 * MB), Launch());
    }

    [Fact]
    public void AfterARebootEverythingSinceBootIsCounted()
    {
        _machine.Boot(DateTime.UtcNow.AddHours(-1));
        _machine.Counters[Ethernet] = (100 * MB, 40 * MB);
        Launch();

        // The counter is already past the saved value, so it never went backwards;
        // diffing against the save would drop 100 MB / 40 MB of real traffic.
        _machine.Reboot();
        _machine.Counters[Ethernet] = (2 * GB, 900 * MB);
        Assert.Equal((2 * GB, 900 * MB), Launch());
    }

    [Fact]
    public void AfterARebootAnAdapterTheLastSaveNeverSawIsCountedToo()
    {
        // Saved while undocked, on Wi-Fi alone; booted docked, on USB Ethernet.
        _machine.Boot(DateTime.UtcNow.AddHours(-1));
        _machine.Counters[WiFi] = (5 * MB, 1 * MB);
        Launch();

        _machine.Reboot();
        _machine.Counters[WiFi] = (1 * MB, 0);
        _machine.Counters[Dock] = (2 * GB, 300 * MB);
        Assert.Equal((2 * GB + 1 * MB, 300 * MB), Launch());
    }

    [Fact]
    public void OnlyTheFirstLaunchAfterARebootCountsFromZero()
    {
        _machine.Boot(DateTime.UtcNow.AddHours(-1));
        _machine.Counters[Ethernet] = (100 * MB, 40 * MB);
        Launch();

        _machine.Reboot();
        _machine.Counters[Ethernet] = (2 * GB, 900 * MB);
        Launch();

        // That launch saved during this boot, so the next one diffs against it
        // rather than counting the 2 GB since boot a second time.
        _machine.Counters[Ethernet] = (2 * GB + 10 * MB, 900 * MB);
        Assert.Equal((10 * MB, 0L), Launch());
    }

    [Theory]
    // Saved an hour before this boot began: the counters it holds are gone.
    [InlineData(-60, 5 * GB)]
    // Saved an hour into it: the diff continues.
    [InlineData(60, 2 * GB)]
    public void AFileIsJudgedByWhenItWasSaved(int savedMinutesAfterBoot, long counted)
    {
        // The format 0.7.23 and earlier wrote, unchanged since: 3 GB in on Ethernet.
        var bootTime = new DateTime(2026, 11, 7, 8, 0, 0, DateTimeKind.Utc);
        WriteHistory(bootTime.AddMinutes(savedMinutesAfterBoot), savedIn: 3 * GB);

        _machine.Boot(bootTime);
        _machine.Counters[Ethernet] = (5 * GB, 0);
        Assert.Equal(counted, Launch().In);
    }

    [Fact]
    public void ClosingBeforeTheFirstSampleLeavesTheFileAsItWas()
    {
        _machine.Boot(DateTime.UtcNow.AddHours(-1));
        _machine.Counters[Ethernet] = (100 * MB, 40 * MB);
        Launch();
        var saved = File.ReadAllText(_historyPath);

        // Opened after a reboot and closed before the loop's first sample. Saving
        // would date the stale counters into this boot, and the next launch would
        // diff against them and lose the traffic since boot.
        _machine.Reboot();
        _machine.Counters[Ethernet] = (2 * GB, 900 * MB);
        var meter = new TrafficMeterService(_historyPath, _machine.Sources);
        meter.LoadHistory();
        meter.SaveHistory();
        Assert.Equal(saved, File.ReadAllText(_historyPath));

        Assert.Equal((2 * GB, 900 * MB), Launch());
    }

    /// <summary>
    /// One run of the console: read the file, take one sample, close. Returns what
    /// that run added to the month.
    /// </summary>
    private (long In, long Out) Launch()
    {
        var meter = new TrafficMeterService(_historyPath, _machine.Sources);
        meter.LoadHistory();
        var before = meter.MonthTotal(Noon);
        meter.SampleOnce(Noon);
        meter.SaveHistory();
        var after = meter.MonthTotal(Noon);
        return (after.BytesIn - before.BytesIn, after.BytesOut - before.BytesOut);
    }

    private void WriteHistory(DateTime updatedUtc, long savedIn)
        => File.WriteAllText(_historyPath, $$"""
            {
              "UpdatedUtc": "{{updatedUtc:O}}",
              "Days": [],
              "Counters": { "{{Ethernet}}": { "In": {{savedIn}}, "Out": 0 } }
            }
            """);

    /// <summary>A machine whose adapters and boot time the test sets.</summary>
    private sealed class FakeMachine
    {
        public readonly Dictionary<string, (long In, long Out)> Counters = new(StringComparer.Ordinal);
        public DateTime BootTime;

        public TrafficMeterService.KernelSources Sources => new(
            () => Counters.ToDictionary(
                kv => kv.Key,
                kv => new TrafficMeterService.InterfaceCounter(kv.Value.In, kv.Value.Out),
                StringComparer.Ordinal),
            () => BootTime);

        /// <summary>A boot at <paramref name="bootTime"/>: every counter gone.</summary>
        public void Boot(DateTime bootTime)
        {
            BootTime = bootTime;
            Counters.Clear();
        }

        /// <summary>
        /// A reboot now. Saves are stamped with the real clock, and the last one was
        /// written before this call, so the new boot begins after it.
        /// </summary>
        public void Reboot() => Boot(DateTime.UtcNow);
    }
}
