using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The Program column: what a firewall rule is scoped to, in the width a column has.
///
/// This is the field that decides whether two rows are the same rule, and it was the
/// one nothing displayed. A host carries whole families of rules identical in every
/// column the table did show — 21 "Microsoft Edge (mDNS-In)" rules, one per retained
/// EdgeWebView version, and a "Steam Web Helper" pair split across two cef builds —
/// which read as duplicates of one another with nothing on screen to say otherwise.
/// </summary>
public class RuleScopeTextTests
{
    private static FirewallRuleInfo Rule(string program = "", string service = "") => new()
    {
        Name = "rule",
        Program = program,
        Service = service
    };

    /// <summary>
    /// The Edge case, which is the one a right-trim gets wrong: 21 paths sharing a long
    /// prefix and differing only in the version directory near the end.
    /// </summary>
    [Fact]
    public void PathsThatDifferOnlyNearTheEnd_StillReadDifferently()
    {
        var a = Rule(@"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\151.0.4129.93\msedgewebview2.exe");
        var b = Rule(@"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\150.0.4078.65\msedgewebview2.exe");

        Assert.NotEqual(a.ScopeText, b.ScopeText);
        Assert.Contains("151.0.4129.93", a.ScopeText);
        Assert.Contains("150.0.4078.65", b.ScopeText);
    }

    /// <summary>The Steam pair: same executable name, different build directory.</summary>
    [Fact]
    public void TheSameExecutableInDifferentDirectories_ReadsDifferently()
    {
        var win64 = Rule(@"C:\Program Files (x86)\Steam\bin\cef\cef.win64\steamwebhelper.exe");
        var win7 = Rule(@"C:\Program Files (x86)\Steam\bin\cef\cef.win7x64\steamwebhelper.exe");

        Assert.NotEqual(win64.ScopeText, win7.ScopeText);
    }

    /// <summary>
    /// Trimmed from the left, so the ellipsis marks the cut at the front and the tail —
    /// the half that differs — survives.
    /// </summary>
    [Fact]
    public void ALongPath_IsTrimmedFromTheLeft()
    {
        var rule = Rule(@"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\151.0.4129.93\msedgewebview2.exe");

        Assert.StartsWith("…", rule.ScopeText);
        Assert.EndsWith("msedgewebview2.exe", rule.ScopeText);
    }

    /// <summary>A path that fits is shown whole, with no ellipsis to explain.</summary>
    [Fact]
    public void AShortPath_IsShownWhole()
    {
        var rule = Rule(@"C:\Windows\System32\svchost.exe");

        Assert.Equal(@"C:\Windows\System32\svchost.exe", rule.ScopeText);
        Assert.DoesNotContain("…", rule.ScopeText);
    }

    /// <summary>The tooltip carries the whole value, since no column width fits every path.</summary>
    [Fact]
    public void TheDetailText_KeepsTheWholePath()
    {
        const string path = @"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\151.0.4129.93\msedgewebview2.exe";

        Assert.Equal(path, Rule(path).ScopeDetailText);
    }

    /// <summary>
    /// netsh prints an unconstrained scope as "Any" or "*". Neither names a program, and
    /// echoing them back would claim a rule is scoped when it is not.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("Any")]
    [InlineData("any")]
    [InlineData("*")]
    public void AnUnconstrainedRule_SaysAny(string program)
    {
        var rule = Rule(program);

        Assert.Equal("Any", rule.ScopeText);
        Assert.Contains("any program", rule.ScopeDetailText);
    }

    /// <summary>Four groups on the reported host differ by service rather than program.</summary>
    [Fact]
    public void ARuleScopedToAServiceOnly_NamesTheService()
    {
        var rule = Rule(service: "Dnscache");

        Assert.Equal("Dnscache", rule.ScopeText);
        Assert.Equal("Service: Dnscache", rule.ScopeDetailText);
    }

    /// <summary>
    /// The cell trims anything wider than its column, and it trims from the right —
    /// the opposite end from this one. A value that overflows is therefore trimmed
    /// twice, and the second cut undoes the first: "cef.win64" and "cef.win7x64" both
    /// end as "cef.win…" and the two rows collide again. Keeping the string inside a
    /// width the column can hold is what stops that, so the bound is the invariant
    /// worth pinning rather than the particular number.
    /// </summary>
    [Theory]
    [InlineData(@"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\151.0.4129.93\msedgewebview2.exe")]
    [InlineData(@"C:\Program Files (x86)\Steam\bin\cef\cef.win7x64\steamwebhelper.exe")]
    [InlineData(@"C:\users\david\programing\test\networksentinel\bin\package\windows-server-win-x64-selfcontained\networksentinel.exe")]
    public void TheScopeNeverOutgrowsItsColumn(string program)
    {
        var scope = Rule(program).ScopeText;

        Assert.True(scope.Length <= 34, $"'{scope}' is {scope.Length} chars and would be trimmed a second time.");
    }

    /// <summary>
    /// The Steam pair specifically, since it is the one a second trim ruins: both
    /// paths must still differ within the first characters a narrow column shows.
    /// </summary>
    [Fact]
    public void TheSteamPair_DiffersEarlyEnoughToSurviveANarrowColumn()
    {
        var a = Rule(@"C:\Program Files (x86)\Steam\bin\cef\cef.win64\steamwebhelper.exe").ScopeText;
        var b = Rule(@"C:\Program Files (x86)\Steam\bin\cef\cef.win7x64\steamwebhelper.exe").ScopeText;

        // Compare only what a column roughly 20 characters wide would render.
        var shownA = a[..Math.Min(20, a.Length)];
        var shownB = b[..Math.Min(20, b.Length)];

        Assert.NotEqual(shownA, shownB);
    }

    /// <summary>A rule carrying both is described by both in the tooltip.</summary>
    [Fact]
    public void ARuleScopedToBoth_ReportsBoth()
    {
        var rule = Rule(@"C:\Windows\System32\svchost.exe", "Dnscache");

        Assert.Equal(@"C:\Windows\System32\svchost.exe", rule.ScopeText);
        Assert.Contains("svchost.exe", rule.ScopeDetailText);
        Assert.Contains("Dnscache", rule.ScopeDetailText);
    }
}
