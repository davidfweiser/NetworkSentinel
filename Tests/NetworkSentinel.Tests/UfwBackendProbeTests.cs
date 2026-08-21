using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The fallback the UFW backend probe uses when `ufw status` refuses to run.
///
/// It refuses on every ordinary desktop: the GUI runs as the normal user, and
/// `ufw status` needs root. Reading that refusal as "UFW is not active" is what
/// sent rules into nftables on hosts where UFW owned the firewall — applied,
/// reported added, and then missing from `ufw status numbered`.
///
/// So the flag ufw.conf holds decides it instead. These tests pin the parse,
/// because a false negative here is the same silent bug again and a false
/// positive writes rules into a firewall that is switched off.
/// </summary>
public class UfwBackendProbeTests
{
    /// <summary>ufw.conf as Ubuntu ships it, with the comments that surround the flag.</summary>
    private const string StockConfig =
        "# /etc/ufw/ufw.conf\n" +
        "#\n" +
        "\n" +
        "# Set to yes to start on boot. If setting this remotely, be sure to add a rule\n" +
        "# to allow your remote connection before starting ufw. Eg: 'ufw allow 22/tcp'\n" +
        "ENABLED=yes\n" +
        "\n" +
        "# Please use the 'ufw' command to set the loglevel. Eg: 'ufw logging medium'\n" +
        "# See 'man ufw' for details.\n" +
        "LOGLEVEL=low\n";

    [Fact]
    public void StockUbuntuConfig_ReadsAsEnabled()
    {
        Assert.True(FirewallService.ParseUfwEnabledFlag(StockConfig));
    }

    [Fact]
    public void Disabled_ReadsAsDisabled()
    {
        Assert.False(FirewallService.ParseUfwEnabledFlag(StockConfig.Replace("ENABLED=yes", "ENABLED=no")));
    }

    /// <summary>
    /// The prose above the flag says "Set to yes"; the comment block ends with a
    /// commented-out example on some derivatives. Neither is an assignment, and a
    /// parser that matched them would call a switched-off firewall active.
    /// </summary>
    [Fact]
    public void CommentedOutAssignment_IsNotAnAnswer()
    {
        Assert.Null(FirewallService.ParseUfwEnabledFlag("# ENABLED=yes\n#ENABLED=yes\nLOGLEVEL=low\n"));
    }

    [Fact]
    public void QuotedAndPaddedValues_AreRead()
    {
        Assert.True(FirewallService.ParseUfwEnabledFlag("ENABLED=\"yes\"\n"));
        Assert.True(FirewallService.ParseUfwEnabledFlag("\tENABLED = YES \n"));
        Assert.False(FirewallService.ParseUfwEnabledFlag("ENABLED=\"No\"\r\n"));
    }

    /// <summary>Shell-style config: the last assignment is the one in force.</summary>
    [Fact]
    public void LastAssignmentWins()
    {
        Assert.False(FirewallService.ParseUfwEnabledFlag("ENABLED=yes\nLOGLEVEL=low\nENABLED=no\n"));
    }

    /// <summary>
    /// ufw.conf is hand-edited often enough that a typo has to stay unanswered.
    /// Guessing either way picks a firewall backend on a misspelling.
    /// </summary>
    [Fact]
    public void UnrecognisedOrAbsent_IsUnanswered()
    {
        Assert.Null(FirewallService.ParseUfwEnabledFlag("ENABLED=ture\n"));
        Assert.Null(FirewallService.ParseUfwEnabledFlag("LOGLEVEL=low\n"));
        Assert.Null(FirewallService.ParseUfwEnabledFlag(""));
        Assert.Null(FirewallService.ParseUfwEnabledFlag(null));
    }

    /// <summary>A key that merely ends in ENABLED is a different setting.</summary>
    [Fact]
    public void ASimilarlyNamedKey_IsNotTheFlag()
    {
        Assert.Null(FirewallService.ParseUfwEnabledFlag("IPV6_ENABLED=no\n"));
    }
}
