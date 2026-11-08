using System.Text;
using NetworkSentinel.Services;
using Xunit;
using static NetworkSentinel.Tests.TrafficMeterTests;

namespace NetworkSentinel.Tests;

/// <summary>
/// Runs the meter end to end through <c>traffic-history.json</c> on a pretend machine
/// whose counters, boot ID and boot time the test sets: a launch reads the file,
/// takes one sample and closes, the way the console does. What these pin down is the
/// one thing the pure helpers cannot show — that the counters a launch saves are
/// trusted by the next one exactly when they are still the kernel's.
/// </summary>
public sealed class TrafficMeterPersistenceTests : IDisposable
{
    private const long MB = 1_000_000;
    private const long GB = 1_000_000_000;

    private static readonly DateTime Noon = new(2026, 11, 7, 12, 0, 0);

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ns-traffic-" + Guid.NewGuid().ToString("N"));
    private readonly string _historyPath;
    private readonly FakeKernel _kernel = new();

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
        _kernel.Boot(BootA, DateTime.UtcNow.AddHours(-1));
        _kernel.Counters["eno1"] = (100 * MB, 40 * MB);
        Assert.Equal((0L, 0L), Launch()); // no history yet: the first launch baselines

        _kernel.Counters["eno1"] = (150 * MB, 45 * MB);
        Assert.Equal((50 * MB, 5 * MB), Launch());
    }

    [Fact]
    public void AfterARebootEverythingSinceBootIsCounted()
    {
        _kernel.Boot(BootA, DateTime.UtcNow.AddHours(-1));
        _kernel.Counters["eno1"] = (100 * MB, 40 * MB);
        Launch();

        // The counter is already past the saved value, so it never went backwards;
        // diffing against the save would drop 100 MB / 40 MB of real traffic.
        _kernel.Boot(BootB, DateTime.UtcNow);
        _kernel.Counters["eno1"] = (2 * GB, 900 * MB);
        Assert.Equal((2 * GB, 900 * MB), Launch());
    }

    [Fact]
    public void AfterARebootAnInterfaceTheLastSaveNeverSawIsCountedToo()
    {
        // Saved while undocked, on Wi-Fi alone; booted docked, on USB Ethernet.
        _kernel.Boot(BootA, DateTime.UtcNow.AddHours(-1));
        _kernel.Counters["wlp3s0"] = (5 * MB, 1 * MB);
        Launch();

        _kernel.Boot(BootB, DateTime.UtcNow);
        _kernel.Counters["wlp3s0"] = (1 * MB, 0);
        _kernel.Counters["enx00e04c680125"] = (2 * GB, 300 * MB);
        Assert.Equal((2 * GB + 1 * MB, 300 * MB), Launch());
    }

    [Theory]
    // Saved an hour before this boot began: the counters it holds are gone.
    [InlineData(-60, 5 * GB)]
    // Saved an hour into it: the diff continues.
    [InlineData(60, 2 * GB)]
    public void AFileWithoutABootIdIsJudgedByWhenItWasSaved(int savedMinutesAfterBoot, long counted)
    {
        // What 0.7.23 and earlier wrote: no BootId, 3 GB in on eno1.
        var bootTime = new DateTime(2026, 11, 7, 8, 0, 0, DateTimeKind.Utc);
        WriteUnstampedHistory(bootTime.AddMinutes(savedMinutesAfterBoot), savedIn: 3 * GB);

        _kernel.Boot(BootB, bootTime);
        _kernel.Counters["eno1"] = (5 * GB, 0);
        Assert.Equal(counted, Launch().In);
    }

    [Fact]
    public void ALaunchThatCannotReadTheBootIdStillLetsTheNextOneSeeTheReboot()
    {
        _kernel.Boot(BootA, DateTime.UtcNow.AddHours(-1));
        _kernel.Counters["eno1"] = (100 * MB, 40 * MB);
        Launch();

        // One launch where the ID cannot be read. The clock still places the save
        // within this boot, so the diff continues — and the file it writes carries
        // no stamp rather than a wrong one.
        _kernel.BootId = null;
        _kernel.Counters["eno1"] = (150 * MB, 45 * MB);
        Assert.Equal((50 * MB, 5 * MB), Launch());
        Assert.DoesNotContain("BootId", File.ReadAllText(_historyPath));

        // The reboot comes after that save, and the next launch reads its ID again.
        // Without a stamp to compare, the save time against the boot time tells.
        _kernel.Boot(BootB, DateTime.UtcNow.AddSeconds(1));
        _kernel.Counters["eno1"] = (2 * GB, 900 * MB);
        Assert.Equal((2 * GB, 900 * MB), Launch());
    }

    [Fact]
    public void ABootIdThatCouldNotBeReadIsTriedAgainAtTheNextSave()
    {
        _kernel.Boot(null, DateTime.UtcNow.AddHours(-1));
        _kernel.Counters["eno1"] = (100 * MB, 40 * MB);

        var meter = new TrafficMeterService(_historyPath, _kernel.Sources);
        meter.LoadHistory();
        meter.SampleOnce(Noon); // the first sample saves
        Assert.DoesNotContain("BootId", File.ReadAllText(_historyPath));

        _kernel.BootId = BootA;
        meter.SaveHistory();
        Assert.Contains(BootA, File.ReadAllText(_historyPath));
    }

    [Fact]
    public void ClosingBeforeTheFirstSampleLeavesTheFileAsItWas()
    {
        _kernel.Boot(BootA, DateTime.UtcNow.AddHours(-1));
        _kernel.Counters["eno1"] = (100 * MB, 40 * MB);
        Launch();
        var saved = File.ReadAllText(_historyPath);

        // Opened after a reboot and closed before the loop's first sample. Saving
        // would stamp the stale counters with this boot (or drop them), and the next
        // launch would diff against them and lose the traffic since boot.
        _kernel.Boot(BootB, DateTime.UtcNow);
        _kernel.Counters["eno1"] = (2 * GB, 900 * MB);
        var meter = new TrafficMeterService(_historyPath, _kernel.Sources);
        meter.LoadHistory();
        meter.SaveHistory();
        Assert.Equal(saved, File.ReadAllText(_historyPath));

        Assert.Equal((2 * GB, 900 * MB), Launch());
    }

    [Fact]
    public void AnUnstampedFileIsNotStampedWithoutASample()
    {
        // Nothing can tell whether these counters are stale (no ID in the file, no
        // boot time), so they are kept — but closing before a sample must not vouch
        // for them by stamping them with this boot.
        WriteUnstampedHistory(new DateTime(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc), savedIn: 500 * MB);
        var saved = File.ReadAllText(_historyPath);

        _kernel.Boot(BootB, bootTime: null);
        var meter = new TrafficMeterService(_historyPath, _kernel.Sources);
        meter.LoadHistory();
        meter.SaveHistory();

        Assert.Equal(saved, File.ReadAllText(_historyPath));
    }

    /// <summary>
    /// One run of the console: read the file, take one sample, close. Returns what
    /// that run added to the month.
    /// </summary>
    private (long In, long Out) Launch()
    {
        var meter = new TrafficMeterService(_historyPath, _kernel.Sources);
        meter.LoadHistory();
        var before = meter.MonthTotal(Noon);
        meter.SampleOnce(Noon);
        meter.SaveHistory();
        var after = meter.MonthTotal(Noon);
        return (after.BytesIn - before.BytesIn, after.BytesOut - before.BytesOut);
    }

    private void WriteUnstampedHistory(DateTime updatedUtc, long savedIn)
        => File.WriteAllText(_historyPath, $$"""
            {
              "UpdatedUtc": "{{updatedUtc:O}}",
              "Days": [],
              "Counters": { "eno1": { "In": {{savedIn}}, "Out": 0 } }
            }
            """);

    /// <summary>A machine whose kernel state the test sets.</summary>
    private sealed class FakeKernel
    {
        public readonly Dictionary<string, (long In, long Out)> Counters = new(StringComparer.Ordinal);
        public string? BootId;
        public DateTime? BootTime;

        public TrafficMeterService.KernelSources Sources => new(NetDev, () => BootId, () => BootTime);

        /// <summary>A (re)boot: a new ID and boot time, and every counter gone.</summary>
        public void Boot(string? bootId, DateTime? bootTime)
        {
            BootId = bootId;
            BootTime = bootTime;
            Counters.Clear();
        }

        private string NetDev()
        {
            var text = new StringBuilder()
                .AppendLine("Inter-|   Receive                                                |  Transmit")
                .AppendLine(" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed");
            foreach (var (name, (bytesIn, bytesOut)) in Counters)
                text.AppendLine($"{name,6}: {bytesIn} 0 0 0 0 0 0 0 {bytesOut} 0 0 0 0 0 0 0");
            return text.ToString();
        }
    }
}
