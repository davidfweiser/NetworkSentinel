using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// What the app says about elevation, and to whom.
///
/// The bug these cover is one an operator hit in a browser on a phone: the web
/// console listed 25 inbound rules, offered an Edit button on each, accepted a
/// change, and then failed the save with a paragraph about windows not being
/// terminals and not starting the GUI with sudo under Wayland. None of the three
/// nouns in that advice — window, GUI, Wayland — exists on a headless server, and
/// the one thing that would have fixed it was a sudoers line the message never
/// wrote out.
/// </summary>
public class ElevationSurfaceTests
{
    /// <summary>
    /// <see cref="FirewallService.Surface"/> is process-wide state that the tests
    /// below have to move, so each one puts it back. xUnit runs classes in
    /// parallel but the members of one class in sequence, and this is the only
    /// class that touches it.
    /// </summary>
    private static void WithSurface(FirewallUiSurface surface, Action body)
    {
        var previous = FirewallService.Surface;
        FirewallService.Surface = surface;
        try { body(); }
        finally { FirewallService.Surface = previous; }
    }

    [Fact]
    public void SudoersGrant_NamesThisUserAndAbsolutePaths()
    {
        var grant = FirewallService.SudoersGrantText();

        Assert.StartsWith(Environment.UserName + " ALL=(root) NOPASSWD: ", grant);

        // visudo rejects a relative path, so every binary listed has to be absolute.
        var binaries = grant.Split("NOPASSWD: ")[1].Split(", ");
        Assert.NotEmpty(binaries);
        Assert.All(binaries, b => Assert.StartsWith("/", b));
    }

    [Fact]
    public void SudoersGrant_IsOneLineSoItCanBeEchoedIntoSudoersD()
    {
        var grant = FirewallService.SudoersGrantText();

        Assert.DoesNotContain("\n", grant);
        // The install command wraps it in single quotes; one inside would end them.
        Assert.DoesNotContain("'", grant);
    }

    [Fact]
    public void InstallCommands_WriteTheGrantVerifyItAndRestartTheService()
    {
        var commands = FirewallService.SudoersInstallCommands();

        Assert.Contains(FirewallService.SudoersGrantText(), commands);
        Assert.Contains("/etc/sudoers.d/networksentinel", commands);
        Assert.Contains("chmod 0440", commands);
        Assert.Contains("visudo -c", commands);
        Assert.Contains("systemctl restart networksentinel-web", commands);
    }

    [Fact]
    public void HeadlessHelp_CarriesTheCommandsInBothLayouts()
    {
        var block = FirewallService.HeadlessElevationHelp();
        var flowed = FirewallService.HeadlessElevationHelp(asBlock: false);

        Assert.Contains(FirewallService.SudoersInstallCommands(), block);
        Assert.Contains(FirewallService.HeadlessElevationLead, block);
        Assert.Contains(FirewallService.HeadlessElevationTail, block);

        // The flowed form goes into a single-line status, so it cannot wrap.
        Assert.DoesNotContain("\n", flowed);
        Assert.Contains("visudo -c", flowed);
    }

    [Fact]
    public void WebSurface_DoesNotOfferDesktopAdviceForAFailedWrite()
    {
        WithSurface(FirewallUiSurface.Web, () =>
        {
            var service = new FirewallService();
            var note = service.ElevationNote;
            var privilege = service.PrivilegeText;

            foreach (var text in new[] { note, privilege })
            {
                Assert.DoesNotContain("Wayland", text);
                Assert.DoesNotContain("XOpenDisplay", text);
                Assert.DoesNotContain("this window", text);
            }
        });
    }

    [Fact]
    public void DesktopSurface_KeepsThePromptWordingItAlwaysHad()
    {
        WithSurface(FirewallUiSurface.Desktop, () =>
        {
            var note = new FirewallService().ElevationNote;

            // Root and passwordless-sudo hosts are answered before the prompt
            // branches, and CI runs as root, so only assert what holds either way:
            // the desktop is never told to go and edit sudoers by hand.
            Assert.DoesNotContain("/etc/sudoers.d/networksentinel", note);
        });
    }

    [Fact]
    public void WebSurface_CannotPromptEvenWhereAHelperIsInstalled()
    {
        // A helper being installed is what IsAdministrator reports, and it is true
        // on hosts where every write fails. CanApplyRules is the stronger claim, so
        // it may never be true purely because pkexec or sudo happens to be present.
        WithSurface(FirewallUiSurface.Web, () =>
        {
            var service = new FirewallService();
            if (!service.IsRoot && !FirewallService.CanElevateSilently())
                Assert.False(service.CanApplyRules);
        });
    }

    [Fact]
    public void RootProcess_CanAlwaysApplyRulesOnEverySurface()
    {
        var service = new FirewallService();
        if (!service.IsRoot) return;   // the suite also runs unprivileged

        foreach (var surface in new[] { FirewallUiSurface.Desktop, FirewallUiSurface.Terminal, FirewallUiSurface.Web })
            WithSurface(surface, () => Assert.True(new FirewallService().CanApplyRules));
    }

    [Fact]
    public void ElevationProbe_CanBeInvalidatedSoAFreshGrantIsSeen()
    {
        // The probe caches, because a refused `sudo -n` lands in the auth log this
        // very app watches. An operator who has just written the sudoers file must
        // not have to wait the cache out, so the reset has to be callable and the
        // answer has to survive it unchanged on a host that has not changed.
        var before = FirewallService.CanElevateSilently();
        FirewallService.InvalidateElevationProbe();
        Assert.Equal(before, FirewallService.CanElevateSilently());
    }
}
