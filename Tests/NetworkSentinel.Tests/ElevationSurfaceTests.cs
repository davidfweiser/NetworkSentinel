using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// What the front-ends are told about a privilege they do not have.
///
/// The web console is the surface with no way to raise a prompt: the operator is in a
/// browser, and a UAC consent dialog would appear on the server's desktop with nobody
/// sitting at it. Every message that used to end in "Run as Admin" is wrong there, and
/// wrong in a way that only shows up on a headless install — which is exactly where
/// nobody is running the GUI to notice. These pin the branch instead.
///
/// <see cref="FirewallService.Surface"/> is process-wide static state, so each test
/// restores it; xUnit runs classes in parallel but the members of one class serially,
/// and no other suite in this assembly reads it.
/// </summary>
public class ElevationSurfaceTests
{
    private static void WithSurface(FirewallUiSurface surface, Action body)
    {
        var previous = FirewallService.Surface;
        try
        {
            FirewallService.Surface = surface;
            body();
        }
        finally
        {
            FirewallService.Surface = previous;
        }
    }

    /// <summary>
    /// The default suits the GUI, which is the one entry point that does not set it.
    /// A default of Web would make the desktop app tell users to go and edit a
    /// scheduled task rather than approve the UAC prompt sitting in front of them.
    /// </summary>
    [Fact]
    public void SurfaceDefaultsToDesktop()
    {
        Assert.Equal(FirewallUiSurface.Desktop, FirewallService.Surface);
    }

    /// <summary>
    /// On Windows the token is the whole answer — unlike Linux, where elevation helpers
    /// can be installed and still unable to prompt. The two properties must agree, or
    /// the web console would draw an editor it cannot honour (or hide one it could).
    /// </summary>
    [Fact]
    public void CanApplyRulesTracksAdministrator()
    {
        var firewall = new FirewallService();
        Assert.Equal(firewall.IsAdministrator, firewall.CanApplyRules);
    }

    /// <summary>
    /// The pasted block has to name commands that exist on this host. The scheduled
    /// task is the supported path — it runs as SYSTEM at boot — and the elevated-prompt
    /// line is the same privilege without the persistence.
    /// </summary>
    [Fact]
    public void ElevationCommandsNameTheInstallerAndTheTask()
    {
        var commands = FirewallService.ElevationInstallCommands();

        Assert.Contains("install-web-service.ps1", commands);
        Assert.Contains("NetworkSentinel-Web", commands);
        Assert.Contains("-w", commands);

        // A front-end that lays this out as a code block splits on newlines, so the
        // steps have to survive as separate lines rather than one run-on command.
        Assert.True(commands.Split('\n').Length >= 3, commands);
    }

    /// <summary>
    /// The block form keeps its newlines for a &lt;pre&gt;; the flowed form is for a
    /// one-line status, where a raw newline would truncate the sentence mid-advice.
    /// </summary>
    [Fact]
    public void HeadlessHelpFlowsWhenNotABlock()
    {
        Assert.Contains("\n", FirewallService.HeadlessElevationHelp());
        Assert.DoesNotContain("\n", FirewallService.HeadlessElevationHelp(asBlock: false));
    }

    /// <summary>
    /// Read in a browser, "Run as Admin" names something the operator cannot do — there
    /// is no window on the server to right-click. The web surface has to say what the
    /// fix actually is.
    /// </summary>
    [Fact]
    public void WebPrivilegeTextDropsTheRunAsAdminAdvice()
    {
        var firewall = new FirewallService();
        if (firewall.IsAdministrator)
            return; // Elevated: there is no missing-privilege message to check.

        WithSurface(FirewallUiSurface.Web, () =>
        {
            var text = firewall.PrivilegeText;
            Assert.DoesNotContain("Run as Admin", text);
            Assert.Contains("browser", text);
            Assert.Contains("install-web-service.ps1", text);
        });

        WithSurface(FirewallUiSurface.Desktop, () =>
            Assert.Contains("Run as Admin", firewall.PrivilegeText));
    }

    /// <summary>
    /// Authorize relaunches the process through UAC. From the web console that is wrong
    /// twice over: nobody is at the server to approve it, and a success would tear down
    /// the process serving the page that asked. It must refuse and explain instead.
    /// </summary>
    [Fact]
    public void WebAuthorizeRefusesInsteadOfRelaunching()
    {
        var firewall = new FirewallService();
        if (firewall.IsAdministrator)
            return; // Already elevated: Authorize reports success and never relaunches.

        WithSurface(FirewallUiSurface.Web, () =>
        {
            var result = firewall.AuthorizeElevation();
            Assert.False(result.Success);
            Assert.Contains("install-web-service.ps1", result.Message);
        });
    }

    /// <summary>
    /// The scan note answers two questions — what could be read, and what could be
    /// written — and only the second one changes with the surface.
    /// </summary>
    [Fact]
    public void ScanPrivilegeNoteBranchesOnSurface()
    {
        var firewall = new FirewallService();
        if (firewall.IsAdministrator)
            return;

        var scanner = new HostFirewallScanner(firewall);

        WithSurface(FirewallUiSurface.Web, () =>
            Assert.DoesNotContain("Run as Admin", scanner.Scan().PrivilegeNote));

        WithSurface(FirewallUiSurface.Desktop, () =>
            Assert.Contains("Run as Admin", scanner.Scan().PrivilegeNote));
    }
}
