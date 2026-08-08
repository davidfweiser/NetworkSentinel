using NetworkSentinel.Models;
using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

public class PreventionServiceTests
{
    private static PreventionService Create(out AppSettings settings)
    {
        settings = new AppSettings();
        var firewall = new FirewallService();
        var allowlist = new AllowlistService();
        return new PreventionService(firewall, allowlist, settings);
    }

    [Fact]
    public void ManualUnblockSuppressesAndPersists()
    {
        var prevention = Create(out var settings);

        prevention.NoteUnblocked("203.0.113.9");

        Assert.True(prevention.IsSuppressed("203.0.113.9"));
        Assert.True(settings.AutoBlockSuppressedUntil.ContainsKey("203.0.113.9"));

        prevention.ClearSuppression("203.0.113.9");
        Assert.False(prevention.IsSuppressed("203.0.113.9"));
        Assert.False(settings.AutoBlockSuppressedUntil.ContainsKey("203.0.113.9"));
    }

    [Fact]
    public void SuppressionSurvivesReload()
    {
        var prevention = Create(out var settings);
        prevention.NoteUnblocked("203.0.113.10");

        // A second engine over the same settings (a fresh frontend start) must
        // still honor the release.
        var firewall = new FirewallService();
        var allowlist = new AllowlistService();
        var reloaded = new PreventionService(firewall, allowlist, settings);
        Assert.True(reloaded.IsSuppressed("203.0.113.10"));
    }

    [Fact]
    public void NoteBlockedTracksAddress()
    {
        var prevention = Create(out _);
        Assert.False(prevention.IsBlocked("203.0.113.11"));
        prevention.NoteBlocked("203.0.113.11");
        Assert.True(prevention.IsBlocked("203.0.113.11"));
    }

    [Fact]
    public void OperatorProtectionShieldsPublicAddressesOnly()
    {
        var prevention = Create(out _);

        prevention.Protect("192.168.1.50");         // private — never auto-blocked anyway
        Assert.DoesNotContain("192.168.1.50", prevention.ProtectedIps);

        prevention.Protect("203.0.113.12");
        Assert.Contains("203.0.113.12", prevention.ProtectedIps);

        prevention.Unprotect("203.0.113.12");
        Assert.DoesNotContain("203.0.113.12", prevention.ProtectedIps);
    }

    [Fact]
    public void NormalizesBookkeepingKeys()
    {
        var prevention = Create(out _);
        // Port suffix and canonical form must land on the same suppression entry.
        prevention.NoteUnblocked("203.0.113.13:443");
        Assert.True(prevention.IsSuppressed("203.0.113.13"));
    }

    private static ThreatEvent Threat(string ip, ThreatLevel level = ThreatLevel.Critical) => new()
    {
        Type = ThreatType.KnownBadAddress,
        Level = level,
        SourceIp = ip,
        Title = "Listed on a threat-intel feed"
    };

    [Fact]
    public void TunnelEndpointIsHeldBackAndSaidOutLoud()
    {
        var prevention = Create(out _);
        prevention.Enabled = true;
        // Dry run: the gates all run, but no test may write a kernel firewall rule.
        prevention.DryRun = true;
        prevention.IsProtectedAddress = ip => ip == "203.0.113.30";

        var result = prevention.Apply(new[] { Threat("203.0.113.30"), Threat("203.0.113.31") });

        var held = Assert.Single(result.Decisions, d => d.Action == PreventionAction.Skipped);
        Assert.Equal("203.0.113.30", held.Ip);
        Assert.Contains("WireGuard tunnel endpoint", held.Message);
        // The unprotected address in the same batch is unaffected.
        Assert.Contains(result.Decisions, d => d.Ip == "203.0.113.31" && d.Action == PreventionAction.Simulated);
        // Holding a block back is not a rule change; frontends must not refresh on it.
        Assert.False(result.RulesChanged);
    }

    [Fact]
    public void HeldBackNoteIsRateLimitedPerAddress()
    {
        var prevention = Create(out _);
        prevention.Enabled = true;
        prevention.DryRun = true;
        prevention.IsProtectedAddress = _ => true;

        Assert.Single(prevention.Apply(new[] { Threat("203.0.113.32") }).Decisions);
        // A peer whose traffic keeps tripping a heuristic must not repeat the line every poll.
        Assert.Empty(prevention.Apply(new[] { Threat("203.0.113.32") }).Decisions);
    }

    [Fact]
    public void ExpiryMinutesToSpan()
    {
        Assert.Null(SentinelCore.ExpiryMinutesToSpan(0));
        Assert.Null(SentinelCore.ExpiryMinutesToSpan(-5));
        Assert.Equal(TimeSpan.FromHours(1), SentinelCore.ExpiryMinutesToSpan(60));
    }
}
