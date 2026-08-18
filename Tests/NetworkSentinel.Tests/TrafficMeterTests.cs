using System.Net.NetworkInformation;
using NetworkSentinel.Models;
using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// Reads the per-adapter octet counters Windows keeps. Two things decide whether
/// the dashboard's month totals are right: a counter that restarted has to be
/// read as traffic rather than as a negative delta, and every tunnel, virtual
/// switch and teaming multiplexor in the adapter table carries bytes that were
/// already counted on the physical adapter they ride on.
/// </summary>
public class TrafficMeterTests
{
    [Fact]
    public void DeltaIsTheDifferenceWhileTheCounterClimbs()
    {
        Assert.Equal(500L, TrafficMeterService.Delta(1000, 1500));
        Assert.Equal(0L, TrafficMeterService.Delta(1000, 1000));
    }

    [Fact]
    public void CounterResetCountsTheNewValue()
    {
        // A reboot restarts the counters at zero. Subtracting would give a negative
        // delta; treating the reading as "since the reset" is the honest answer.
        Assert.Equal(120L, TrafficMeterService.Delta(9_000_000, 120));
        Assert.Equal(0L, TrafficMeterService.Delta(9_000_000, 0));
    }

    // ── Which adapters count ─────────────────────────────────────────────

    [Theory]
    // Real wires and radios, as their drivers describe themselves.
    [InlineData(NetworkInterfaceType.Ethernet, "Ethernet", "Intel(R) Ethernet Connection I219-LM", true)]
    [InlineData(NetworkInterfaceType.GigabitEthernet, "Ethernet 2", "Realtek PCIe GbE Family Controller", true)]
    [InlineData(NetworkInterfaceType.Wireless80211, "Wi-Fi", "Intel(R) Wi-Fi 6 AX201 160MHz", true)]
    [InlineData(NetworkInterfaceType.Wwanpp, "Mobile Broadband", "Qualcomm Snapdragon X20 LTE", true)]
    // Loopback never leaves the machine.
    [InlineData(NetworkInterfaceType.Loopback, "Loopback Pseudo-Interface 1", "Software Loopback Interface 1", false)]
    // The KM-TEST adapter claims to be Ethernet, so only the name gives it away.
    [InlineData(NetworkInterfaceType.Ethernet, "Npcap Loopback Adapter", "Npcap Loopback Adapter", false)]
    // Windows' own tunnels are typed as tunnels.
    [InlineData(NetworkInterfaceType.Tunnel, "IKEv2 VPN", "WAN Miniport (IKEv2)", false)]
    // A dial-up or PPPoE link rides an adapter that is metered already.
    [InlineData(NetworkInterfaceType.Ppp, "Broadband Connection", "WAN Miniport (PPPOE)", false)]
    // These all present as plain Ethernet and re-count bytes from the real wire.
    [InlineData(NetworkInterfaceType.Ethernet, "wg-office", "WireGuard Tunnel", false)]
    [InlineData(NetworkInterfaceType.Ethernet, "Ethernet 3", "Wintun Userspace Tunnel", false)]
    [InlineData(NetworkInterfaceType.Ethernet, "Ethernet 4", "TAP-Windows Adapter V9", false)]
    [InlineData(NetworkInterfaceType.Ethernet, "OpenVPN Data Channel", "OpenVPN Wintun", false)]
    [InlineData(NetworkInterfaceType.Ethernet, "Tailscale", "Tailscale Tunnel", false)]
    [InlineData(NetworkInterfaceType.Ethernet, "vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", false)]
    [InlineData(NetworkInterfaceType.Ethernet, "VMware Network Adapter VMnet1", "VMware Virtual Ethernet Adapter", false)]
    [InlineData(NetworkInterfaceType.Ethernet, "VirtualBox Host-Only Network", "VirtualBox Host-Only Ethernet Adapter", false)]
    public void OnlyPhysicalLinksAreMetered(NetworkInterfaceType type, string name, string description, bool metered)
        => Assert.Equal(metered, TrafficMeterService.IsMeteredInterface(type, name, description));

    [Fact]
    public void TeamMembersAreMeteredButTheMultiplexorIsNot()
    {
        // A team's traffic leaves through its members, so metering those gives the
        // total exactly once; adding the multiplexor above them would double it —
        // the same choice the Linux build makes for a bond master.
        Assert.True(TrafficMeterService.IsMeteredInterface(
            NetworkInterfaceType.Ethernet, "Ethernet", "Intel(R) I350 Gigabit Network Connection"));
        Assert.True(TrafficMeterService.IsMeteredInterface(
            NetworkInterfaceType.Ethernet, "Ethernet 2", "Intel(R) I350 Gigabit Network Connection #2"));
        Assert.False(TrafficMeterService.IsMeteredInterface(
            NetworkInterfaceType.Ethernet, "Team", "Microsoft Network Adapter Multiplexor Driver"));
    }

    [Fact]
    public void AVirtualAdapterIsRejectedOnItsNameOrItsDescriptionAlone()
    {
        // The two fields are searched together because either one can be the only
        // thing that names the family: a WireGuard adapter is named after its
        // tunnel and described as Wintun, and a renamed Hyper-V port keeps only its
        // description.
        Assert.False(TrafficMeterService.IsMeteredInterface(
            NetworkInterfaceType.Ethernet, "vEthernet (WSL)", "Some Vendor Ethernet Adapter"));
        Assert.False(TrafficMeterService.IsMeteredInterface(
            NetworkInterfaceType.Ethernet, "Office link", "Hyper-V Virtual Ethernet Adapter"));
    }

    // ── Formatting ───────────────────────────────────────────────────────

    [Theory]
    [InlineData(0d, "0 B")]
    [InlineData(-5d, "0 B")]
    [InlineData(999d, "999 B")]
    [InlineData(1000d, "1 kB")]
    [InlineData(1_500_000d, "1.5 MB")]
    [InlineData(150_000_000d, "150 MB")]
    [InlineData(7_590_338_536d, "7.6 GB")]
    public void BytesAreFormattedInDecimalUnits(double bytes, string expected)
        => Assert.Equal(expected, ByteSize.Format(bytes));

    [Fact]
    public void RatesCarryTheirUnit()
    {
        Assert.Equal("1.2 MB/s", ByteSize.FormatRate(1_200_000));
        Assert.Equal("0 B/s", ByteSize.FormatRate(0));
    }

    // ── Buckets ──────────────────────────────────────────────────────────

    [Fact]
    public void TheMonthChartIsZeroFilledThroughTodaySoTheAxisHoldsStill()
    {
        using var meter = new TrafficMeterService();
        var buckets = meter.DailyBuckets(DateTime.Today);

        // One bucket per day so far this month — two samples must not stretch
        // across the whole card.
        Assert.Equal(DateTime.Today.Day, buckets.Count);
        Assert.Equal("1", buckets[0].Label);
        Assert.All(buckets, b => Assert.Equal(0, b.BytesTotal));
    }

    [Fact]
    public void AMonthAlreadyPastIsChartedToItsLastDay()
    {
        using var meter = new TrafficMeterService();
        var lastMonth = DateTime.Today.AddMonths(-1);

        Assert.Equal(
            DateTime.DaysInMonth(lastMonth.Year, lastMonth.Month),
            meter.DailyBuckets(lastMonth).Count);
    }

    [Fact]
    public void TheYearChartEndsWithTheCurrentMonth()
    {
        using var meter = new TrafficMeterService();
        var buckets = meter.MonthlyBuckets(12);

        Assert.Equal(12, buckets.Count);
        Assert.Equal(new DateTime(DateTime.Today.Year, DateTime.Today.Month, 1), buckets[^1].Start);
        // "Jun" not "J" — a single letter would collide with July.
        Assert.Equal(DateTime.Today.ToString("MMM"), buckets[^1].Label);
    }
}
