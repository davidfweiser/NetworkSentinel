using NetworkSentinel.Models;
using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// Reads <c>/proc/net/dev</c>. Two shapes of the same file decide whether the
/// dashboard's month totals are right: the kernel pads the interface name to six
/// characters and a long name or a wide counter closes the gap around the colon,
/// so a plain whitespace split fuses the name to its first counter; and every
/// tunnel, VLAN, bridge and container link in the table carries bytes that were
/// already counted on the physical interface they ride on.
/// </summary>
public class TrafficMeterTests
{
    // Captured from a Linux host on Ethernet with a WireGuard tunnel up and Docker
    // installed. Receive columns are bytes/packets/errs/drop/fifo/frame/compressed/
    // multicast; transmit repeats the shape, so transmit bytes sit at index 8.
    private const string Sample = """
        Inter-|   Receive                                                |  Transmit
         face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
            lo: 140160314   24249    0    0    0     0          0         0 140160314   24249    0    0    0     0       0          0
          eno1: 7590338536 6247182    0    0    0     0          0    123456  995552911 2530487    0    0    0     0       0          0
           wg0: 197804251   163861    0    0    0     0          0         0  27262979    79400    0    0    0     0       0          0
        docker0:         0        0    0    0    0     0          0         0         0        0    0    0    0     0       0          0
        veth9f2:    88213      611    0    0    0     0          0         0    140552      722    0    0    0     0       0          0
        """;

    [Fact]
    public void ReadsTheByteColumnsOfAPhysicalInterface()
    {
        var counters = TrafficMeterService.ParseInterfaceCounters(Sample);

        // Transmit bytes are the ninth column after the colon, not the second —
        // reading left to right without counting the receive block would report
        // 6,247,182 packets as bytes out.
        var eno1 = Assert.Contains("eno1", counters);
        Assert.Equal(7590338536L, eno1.In);
        Assert.Equal(995552911L, eno1.Out);
        Assert.Single(counters);
    }

    [Fact]
    public void SkipsLoopbackTunnelsAndContainerLinks()
    {
        var counters = TrafficMeterService.ParseInterfaceCounters(Sample);

        // wg0 carries the same bytes that already crossed eno1, encapsulated.
        Assert.DoesNotContain("wg0", counters.Keys);
        // lo never leaves the machine — and its 140 MB would dwarf a quiet day.
        Assert.DoesNotContain("lo", counters.Keys);
        // The bridge and the container's pair end both re-count container traffic.
        Assert.DoesNotContain("docker0", counters.Keys);
        Assert.DoesNotContain("veth9f2", counters.Keys);
    }

    [Fact]
    public void ReadsRowsWhereTheCounterAbutsTheColon()
    {
        // The name field is padded to six characters, so a longer name and a wide
        // byte count leave no space after the colon. Splitting the row on
        // whitespace alone would yield "enp0s31f6:7590338536" as one field and
        // shift every counter one place left.
        const string tight = """
            Inter-|   Receive                                                |  Transmit
             face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
            enp0s31f6:7590338536 6247182    0    0    0     0          0         0 995552911 2530487    0    0    0     0       0          0
            """;

        var counters = TrafficMeterService.ParseInterfaceCounters(tight);

        var nic = Assert.Contains("enp0s31f6", counters);
        Assert.Equal(7590338536L, nic.In);
        Assert.Equal(995552911L, nic.Out);
    }

    [Fact]
    public void HeaderLinesAreNotMistakenForInterfaces()
    {
        // The second header line ends in "compressed" with no colon in the name
        // position; only the pipe separates its two halves.
        const string headersOnly = """
            Inter-|   Receive                                                |  Transmit
             face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
            """;

        Assert.Empty(TrafficMeterService.ParseInterfaceCounters(headersOnly));
    }

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

    [Theory]
    // Classic and predictable names for real devices.
    [InlineData("eth0", true)]
    [InlineData("eno1", true)]
    [InlineData("enp0s31f6", true)]
    [InlineData("ens33", true)]
    [InlineData("enx00e04c680125", true)]
    [InlineData("wlan0", true)]
    [InlineData("wlp3s0", true)]
    [InlineData("wwan0", true)]
    // A VLAN sub-interface rides on a parent that is metered already.
    [InlineData("eth0.100", false)]
    [InlineData("enp0s31f6.10", false)]
    // Tunnels re-count bytes that crossed the physical link.
    [InlineData("wg0", false)]
    [InlineData("tun0", false)]
    [InlineData("ipsec0", false)]
    [InlineData("gre0", false)]
    // Bridges, bond masters and container links, likewise.
    [InlineData("br0", false)]
    [InlineData("virbr0", false)]
    [InlineData("docker0", false)]
    [InlineData("veth1a2b3c", false)]
    [InlineData("bond0", false)]
    [InlineData("lo", false)]
    [InlineData("", false)]
    public void OnlyPhysicalLinksAreMetered(string name, bool metered)
        => Assert.Equal(metered, TrafficMeterService.IsMeteredInterface(name));

    [Fact]
    public void BondSlavesAreMeteredButTheMasterIsNot()
    {
        // The bond's traffic leaves through its slaves, so metering eth0 and eth1
        // gives the total exactly once; adding bond0 would double it.
        Assert.True(TrafficMeterService.IsMeteredInterface("eth0"));
        Assert.True(TrafficMeterService.IsMeteredInterface("eth1"));
        Assert.False(TrafficMeterService.IsMeteredInterface("bond0"));
    }

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

    [Fact]
    public void EmptyOutputYieldsNoCounters()
    {
        Assert.Empty(TrafficMeterService.ParseInterfaceCounters(""));
        Assert.Empty(TrafficMeterService.ParseInterfaceCounters("cat: /proc/net/dev: No such file"));
    }
}
