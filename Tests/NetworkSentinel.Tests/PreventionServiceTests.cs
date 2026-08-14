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

    private static ThreatEvent Threat(string ip, ThreatLevel level = ThreatLevel.Critical,
                                      ThreatType type = ThreatType.PortScan)
        => new() { SourceIp = ip, Level = level, Type = type, Title = "Port scan" };

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
        Assert.Contains("VPN tunnel endpoint", held.Message);
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
    public void DescribeEnforcementSaysNothingWithoutAnAddress()
    {
        var prevention = Create(out _);
        // Nothing to block, so the alert must not claim anything either way.
        Assert.Null(prevention.DescribeEnforcement(Threat("")));
        Assert.Null(prevention.DescribeEnforcement(Threat("not-an-address")));
    }

    [Fact]
    public void DescribeEnforcementReportsAJustWrittenBlock()
    {
        var prevention = Create(out _);
        var threat = Threat("203.0.113.20");
        var result = new PreventionResult
        {
            Decisions = new[]
            {
                new PreventionDecision
                {
                    Ip = "203.0.113.20",
                    Action = PreventionAction.Blocked,
                    Message = "Auto-blocked 203.0.113.20",
                    Threat = threat
                }
            }
        };

        var status = prevention.DescribeEnforcement(threat, result);

        Assert.NotNull(status);
        Assert.Equal(BlockState.Blocked, status!.State);
        Assert.True(status.IsBlocked);
        Assert.Contains("BLOCKED", status.Text);
    }

    [Fact]
    public void DescribeEnforcementReportsAFailedBlockAsNotBlocked()
    {
        var prevention = Create(out _);
        var threat = Threat("203.0.113.21");
        var result = new PreventionResult
        {
            Decisions = new[]
            {
                new PreventionDecision
                {
                    Ip = "203.0.113.21",
                    Action = PreventionAction.Failed,
                    Message = "Auto-block failed for 203.0.113.21: Need admin rights",
                    FailureReason = "Need admin rights",
                    Threat = threat
                }
            }
        };

        var status = prevention.DescribeEnforcement(threat, result);

        Assert.NotNull(status);
        Assert.Equal(BlockState.Failed, status!.State);
        Assert.False(status.IsBlocked);
        Assert.Contains("Need admin rights", status.Text);
    }

    [Fact]
    public void DescribeEnforcementReportsAnAddressAlreadyUnderARule()
    {
        var prevention = Create(out _);
        prevention.NoteBlocked("203.0.113.22");

        var status = prevention.DescribeEnforcement(Threat("203.0.113.22"));

        Assert.NotNull(status);
        Assert.Equal(BlockState.AlreadyBlocked, status!.State);
        Assert.True(status.IsBlocked);
    }

    [Fact]
    public void DescribeEnforcementSaysWhyNothingWasBlocked()
    {
        var prevention = Create(out _);
        prevention.Enabled = false;

        var off = prevention.DescribeEnforcement(Threat("203.0.113.23"));
        Assert.NotNull(off);
        Assert.False(off!.IsBlocked);
        Assert.Contains("auto-block is off", off.Text, StringComparison.OrdinalIgnoreCase);

        // A private address is never a candidate, whatever the settings say.
        var lan = prevention.DescribeEnforcement(Threat("192.168.1.40"));
        Assert.NotNull(lan);
        Assert.False(lan!.IsBlocked);
        Assert.Contains("private", lan.Text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DescribeEnforcementReportsTheGateThatStoppedIt()
    {
        var prevention = Create(out _);
        prevention.Enabled = true;
        prevention.MinLevel = ThreatLevel.Critical;

        var quiet = prevention.DescribeEnforcement(Threat("203.0.113.24", ThreatLevel.Medium));
        Assert.NotNull(quiet);
        Assert.False(quiet!.IsBlocked);
        Assert.Contains("below the auto-block level", quiet.Text);

        prevention.NoteUnblocked("203.0.113.25");
        var released = prevention.DescribeEnforcement(Threat("203.0.113.25"));
        Assert.NotNull(released);
        Assert.False(released!.IsBlocked);
        Assert.Contains("released this address manually", released.Text);
    }

    [Fact]
    public void ExpiryMinutesToSpan()
    {
        Assert.Null(SentinelCore.ExpiryMinutesToSpan(0));
        Assert.Null(SentinelCore.ExpiryMinutesToSpan(-5));
        Assert.Equal(TimeSpan.FromHours(1), SentinelCore.ExpiryMinutesToSpan(60));
    }
}
