using NetworkSentinel.Services;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The host firewall scan: what netsh's rule dump and profile listing mean, which
/// rules decide whether a listening socket is reachable, and which only look as if
/// they do. Every parser here is static and takes text, so the suite runs against
/// captured output without touching the firewall of the machine it runs on.
/// </summary>
public class HostFirewallScanTests
{
    // ── Fixtures ─────────────────────────────────────────────────────────

    private static string Dump(params string[] blocks) => string.Join("\r\n", blocks);

    /// <summary>
    /// One rule as `netsh advfirewall firewall show rule name=all verbose` prints it.
    /// Fields netsh omits when a rule does not carry them — Description, Program and
    /// Service — are omitted here too, because "absent" is exactly what the scan
    /// reads as "not constrained".
    /// </summary>
    private static string Block(
        string name,
        string direction = "In",
        string action = "Allow",
        string protocol = "TCP",
        string localPort = "Any",
        string remotePort = "Any",
        string remoteIp = "Any",
        string grouping = "",
        string program = "",
        string service = "",
        string profiles = "Domain,Private,Public",
        bool enabled = true)
    {
        var lines = new List<string>
        {
            $"Rule Name:                            {name}",
            "----------------------------------------------------------------------",
            $"Enabled:                              {(enabled ? "Yes" : "No")}",
            $"Direction:                            {direction}",
            $"Profiles:                             {profiles}",
            $"Grouping:                             {grouping}",
            "LocalIP:                              Any",
            $"RemoteIP:                             {remoteIp}",
            $"Protocol:                             {protocol}",
            $"LocalPort:                            {localPort}",
            $"RemotePort:                           {remotePort}"
        };
        if (program.Length > 0) lines.Add($"Program:                              {program}");
        if (service.Length > 0) lines.Add($"Service:                              {service}");
        lines.Add("Edge traversal:                       No");
        lines.Add("InterfaceTypes:                       Any");
        lines.Add("Rule source:                          Local Setting");
        lines.Add($"Action:                               {action}");
        lines.Add("");
        return string.Join("\r\n", lines);
    }

    private static FirewallRuleInfo Rule(
        string name = "rule",
        bool block = false,
        string protocol = "TCP",
        string localPorts = "",
        string addresses = "",
        string program = "",
        string service = "",
        bool foreign = true,
        string profiles = "Domain,Private,Public") => new()
    {
        Name = name,
        Label = name,
        Enabled = true,
        IsBlock = block,
        Direction = FirewallDirection.Inbound,
        Protocol = protocol,
        LocalPorts = localPorts,
        LocalPortsRaw = localPorts,
        RemoteAddresses = addresses,
        Program = program,
        Service = service,
        Profiles = profiles,
        IsForeign = foreign,
        Origin = foreign ? "Some app" : ""
    };

    private static HostListener Socket(
        string port = "445", string address = "0.0.0.0", string protocol = "TCP", string process = "System")
        => new() { Protocol = protocol, Address = address, Port = port, Process = process };

    private static List<HostListener> Annotate(
        HostListener socket, IReadOnlyList<FirewallRuleInfo> inbound,
        bool enabled = true, bool blocksAlways = false)
    {
        var listeners = new List<HostListener> { socket };
        HostFirewallScanner.AnnotateCoverage(listeners, inbound, enabled, blocksAlways);
        return listeners;
    }

    // ── Profiles ─────────────────────────────────────────────────────────

    private const string AllProfiles = """
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound
InboundUserNotification               Enable


Private Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInboundAlways,AllowOutbound


Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,BlockOutbound

Ok.
""";

    [Fact]
    public void EveryProfileComesBackWithItsStateAndDefaultActions()
    {
        var profiles = HostFirewallScanner.ParseProfiles(AllProfiles);

        Assert.Equal(new[] { "Domain", "Private", "Public" }, profiles.Select(p => p.Name));
        Assert.True(profiles[0].On);
        Assert.Equal("Block", profiles[0].DefaultInbound);
        Assert.Equal("Allow", profiles[0].DefaultOutbound);

        Assert.False(profiles[2].On);
        Assert.Equal("Block", profiles[2].DefaultOutbound);
    }

    [Fact]
    public void BlockingInboundAlwaysIsNotTheSameSettingAsBlockingInbound()
    {
        // "Block all inbound connections, including those in the list of allowed
        // apps" makes every allow rule inert. A page that showed the rules without
        // saying so would describe a firewall this host is not running.
        var profiles = HostFirewallScanner.ParseProfiles(AllProfiles);

        Assert.False(profiles[0].BlocksInboundAlways);
        Assert.True(profiles[1].BlocksInboundAlways);
    }

    [Fact]
    public void TheCurrentProfileListingIsOneBlockOfTheSameShape()
    {
        // `show currentprofile` is how the active profile is identified, and it
        // prints a single block with the profile's name in the header.
        var profile = Assert.Single(HostFirewallScanner.ParseProfiles("""
Private Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound
"""));

        Assert.Equal("Private", profile.Name);
        Assert.True(profile.On);
    }

    [Theory]
    [InlineData("Domain,Private,Public", "Private", true)]
    [InlineData("Domain", "Private", false)]
    [InlineData("Public", "Public", true)]
    [InlineData("", "Private", true)]              // no profile named: applies to all
    [InlineData("Any", "Private", true)]
    public void OnlyTheActiveProfilesRulesAreInForce(string ruleProfiles, string active, bool applies)
        => Assert.Equal(applies, HostFirewallScanner.AppliesToProfile(Rule(profiles: ruleProfiles), active));

    // ── Rules ────────────────────────────────────────────────────────────

    [Fact]
    public void TheScanReadsRulesNobodyHereWroteAndLeavesOursToTheManagedList()
    {
        // Ours come from GetConfigRules(), which knows their kind and expiry; picking
        // them up here as well would list every one of them twice.
        var rules = HostFirewallScanner.ParseHostRules(Dump(
            Block("allow 9009", localPort: "9009"),
            Block("NetworkSentinel-Rule-block-inbound-ssh", action: "Block", localPort: "22")), out _);

        var rule = Assert.Single(rules);
        Assert.Equal("allow 9009", rule.Name);
        Assert.True(rule.IsForeign);
        Assert.Equal(FirewallRuleKind.Other, rule.Kind);
    }

    [Fact]
    public void ADisabledRuleIsConfigurationNotEnforcementSoItIsCountedNotListed()
    {
        var rules = HostFirewallScanner.ParseHostRules(Dump(
            Block("live", localPort: "80"),
            Block("switched off", localPort: "81", enabled: false)), out var disabled);

        Assert.Equal("live", Assert.Single(rules).Name);
        Assert.Equal(1, disabled);
    }

    [Fact]
    public void AnOutboundRuleIsShownByThePortItReachesNotThePortItLeavesFrom()
    {
        var rules = HostFirewallScanner.ParseHostRules(Dump(
            Block("dns out", direction: "Out", protocol: "UDP", localPort: "Any", remotePort: "53")), out _);

        var rule = Assert.Single(rules);
        Assert.Equal("53", rule.LocalPorts);      // the column the page shows
        Assert.Equal("53", rule.RemotePortsRaw);  // both halves kept, for the delete filter
        Assert.Equal("", rule.LocalPortsRaw);
        Assert.False(rule.IsInbound);
    }

    [Fact]
    public void WhoWroteARuleFallsBackFromItsGroupToItsProgramToItsService()
    {
        var rules = HostFirewallScanner.ParseHostRules(Dump(
            Block("grouped", grouping: "Core Networking"),
            Block("by program", program: @"C:\Program Files\thing\Thing.exe"),
            Block("by service", service: "dnscache"),
            Block("hand written")), out _);

        Assert.Equal("Core Networking", rules[0].OriginText);
        Assert.Equal("Thing", rules[1].OriginText);
        Assert.Equal("service dnscache", rules[2].OriginText);
        Assert.Equal("Local rule", rules[3].OriginText);
    }

    [Fact]
    public void AStoreAppRuleIsNamedAfterItsPackageRatherThanItsResourceString()
    {
        // netsh prints the indirect string when it cannot resolve a package's display
        // name, which is a paragraph of URI where a rule name should be.
        Assert.Equal("Microsoft.People", HostFirewallScanner.DisplayName(
            "@{Microsoft.People_10.2202.100.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.People/Resources/AppStoreName}"));
        Assert.Equal("Microsoft.XboxApp", HostFirewallScanner.DisplayName(
            "Microsoft.XboxApp_48.104.4001.0_x64__8wekyb3d8bbwe"));

        // Everything else keeps the name it has: it is the name wf.msc shows for the
        // same rule, and the one a delete has to match.
        Assert.Equal("allow 9009", HostFirewallScanner.DisplayName("allow 9009"));
        Assert.Equal("File and Printer Sharing (SMB-In)",
            HostFirewallScanner.DisplayName("File and Printer Sharing (SMB-In)"));
    }

    [Fact]
    public void ARuleWrittenFiveTimesIsOneRowThatSaysFive()
    {
        // A setup script run twice leaves two identical rules; this machine's own
        // firewall holds 685 copies of one. Listing them is noise, and dropping them
        // silently would understate what is actually in the firewall.
        var rules = HostFirewallScanner.Dedupe(HostFirewallScanner.ParseHostRules(Dump(
            Block("allow 9009", localPort: "9009"),
            Block("allow 9009", localPort: "9009"),
            Block("allow 9009", localPort: "9009")), out _));

        var rule = Assert.Single(rules);
        Assert.Equal(3, rule.Copies);
        Assert.Equal("×3", rule.CopiesText);
    }

    [Fact]
    public void OneRuleStoredPerProfileIsOneRowCoveringBothProfiles()
    {
        // How Windows ships its built-in groups: File and Printer Sharing is stored once
        // for Domain and once for Private,Public. Nothing a front-end displays separates
        // them, so they arrived as two rows nothing could tell apart and a delete aimed
        // at either was refused as ambiguous.
        var rules = HostFirewallScanner.Dedupe(HostFirewallScanner.ParseHostRules(Dump(
            Block("File and Printer Sharing (SMB-In)", localPort: "445", profiles: "Domain"),
            Block("File and Printer Sharing (SMB-In)", localPort: "445", profiles: "Private,Public")), out _));

        var rule = Assert.Single(rules);
        Assert.Equal(2, rule.Copies);
        Assert.Equal("Domain,Private,Public", rule.Profiles);
        // Every profile is the same as no scope worth printing.
        Assert.Equal("", rule.ProfileScopeText);
    }

    [Fact]
    public void ARuleLiveOnOneProfileSaysWhichOne()
    {
        var rules = HostFirewallScanner.Dedupe(HostFirewallScanner.ParseHostRules(Dump(
            Block("Remote Desktop", localPort: "3389", profiles: "Domain")), out _));

        var rule = Assert.Single(rules);
        Assert.Equal(1, rule.Copies);
        Assert.Equal("Domain", rule.ProfileScopeText);
    }

    [Fact]
    public void RulesScopedToDifferentProgramsStayApart()
    {
        // The fold drops the profile, not the program: one rule admitting svchost and one
        // admitting System are two rules, and folding them would hide half a firewall.
        var rules = HostFirewallScanner.Dedupe(HostFirewallScanner.ParseHostRules(Dump(
            Block("Core Networking", localPort: "5353", program: @"C:\Windows\System32\svchost.exe"),
            Block("Core Networking", localPort: "5353", program: "System")), out _));

        Assert.Equal(2, rules.Count);
        Assert.All(rules, r => Assert.Equal(1, r.Copies));
    }

    [Theory]
    [InlineData("Domain", "Private,Public", "Domain,Private,Public")]
    [InlineData("Private,Public", "Domain", "Domain,Private,Public")]
    [InlineData("Domain", "Domain", "Domain")]
    [InlineData("", "Public", "Public")]
    public void MergedProfilesKeepWindowsOwnOrder(string left, string right, string expected)
        => Assert.Equal(expected, HostFirewallScanner.MergeProfiles(left, right));

    [Fact]
    public void TwoRulesThatShareANameButNotAShapeAreTwoRules()
    {
        var rules = HostFirewallScanner.Dedupe(HostFirewallScanner.ParseHostRules(Dump(
            Block("Microsoft Teams", protocol: "TCP"),
            Block("Microsoft Teams", protocol: "UDP")), out _));

        Assert.Equal(2, rules.Count);
        Assert.All(rules, r => Assert.Equal(1, r.Copies));
    }

    // ── Port and address matching ────────────────────────────────────────

    [Theory]
    [InlineData("", "445", true)]            // no constraint covers every port
    [InlineData("445", "445", true)]
    [InlineData("445", "139", false)]
    [InlineData("80,443", "443", true)]
    [InlineData("5000-5100", "5050", true)]
    [InlineData("5000-5100", "5101", false)]
    [InlineData("RPC", "49664", false)]      // a port Windows picks at runtime
    public void APortFieldCoversThePortsItNames(string field, string port, bool covers)
        => Assert.Equal(covers, HostFirewallScanner.PortMatches(field, port));

    [Theory]
    [InlineData("All IPv4, All IPv6", true)]
    [InlineData("Any", true)]
    [InlineData("LocalSubnet", false)]
    [InlineData("10.0.0.0/8", false)]        // contains "0.0.0.0" but admits a LAN
    public void AnAddressFieldIsOnlyWideOpenIfEveryTokenIs(string addresses, bool wideOpen)
        => Assert.Equal(wideOpen, HostFirewallScanner.MatchesEveryAddress(addresses));

    // ── What the rules do to a listening socket ──────────────────────────

    [Fact]
    public void ALoopbackListenerIsUnreachableWhateverTheRulesSay()
        => Assert.Equal("Local only",
            Annotate(Socket(address: "127.0.0.1"), Array.Empty<FirewallRuleInfo>())[0].Covered);

    [Fact]
    public void WithTheFirewallOffNothingIsFiltered()
        => Assert.Equal("No firewall",
            Annotate(Socket(), Array.Empty<FirewallRuleInfo>(), enabled: false)[0].Covered);

    [Fact]
    public void NothingCoveringAPortMeansNothingCanReachIt()
        => Assert.Equal("Not allowed",
            Annotate(Socket(port: "2179", process: "vmms"),
                     new[] { Rule(localPorts: "445", program: @"C:\Windows\System32\System") })[0].Covered);

    [Fact]
    public void AnAllowWithNoAddressLimitOpensThePort()
        => Assert.Equal("Open",
            Annotate(Socket(), new[] { Rule(localPorts: "445", program: "System") })[0].Covered);

    [Fact]
    public void AnAllowScopedToTheLocalSubnetIsRestrictedNotOpen()
        => Assert.Equal("Restricted",
            Annotate(Socket(), new[]
            {
                Rule(localPorts: "445", addresses: "LocalSubnet", program: "System")
            })[0].Covered);

    [Fact]
    public void AWideOpenBlockBeatsAnAllowBecauseWindowsEvaluatesItFirst()
        => Assert.Equal("Blocked",
            Annotate(Socket(), new[]
            {
                Rule(localPorts: "445", program: "System"),
                Rule(block: true, localPorts: "445", program: "System")
            })[0].Covered);

    [Fact]
    public void ABlockAimedAtOneAddressDoesNotCloseThePortForEveryoneElse()
    {
        // Auto-block writes one rule per attacker: Block, protocol Any, all ports,
        // one remote address. Reading those as "this port is blocked" marked all 187
        // sockets on a live host Blocked, when what they close is one address.
        var verdict = Annotate(Socket(), new[]
        {
            Rule(localPorts: "445", program: "System"),
            Rule(block: true, protocol: "Any", addresses: "198.58.113.237", foreign: false)
        })[0].Covered;

        Assert.Equal("Open", verdict);
    }

    [Fact]
    public void AStoreAppRuleDoesNotAdmitEveryoneElsesSockets()
    {
        // Windows scopes store-app rules to a package SID, which netsh does not
        // print — so the row names no program, no service and no port. Reading that
        // as "every socket" marked all 159 listeners on a live host Open, SMB and
        // RDP included.
        var verdict = Annotate(Socket(), new[]
        {
            Rule(name: "Microsoft.People", protocol: "Any")
        })[0].Covered;

        Assert.Equal("Not allowed", verdict);
    }

    [Fact]
    public void OurOwnCatchAllStillCoversEverything()
    {
        // The same shape from this app is a rule somebody deliberately wrote, not a
        // package rule in disguise.
        var verdict = Annotate(Socket(), new[]
        {
            Rule(name: "NetworkSentinel-Rule-allow-all", protocol: "Any", foreign: false)
        })[0].Covered;

        Assert.Equal("Open", verdict);
    }

    [Fact]
    public void AProgramRuleCoversItsOwnProcessAndNoOther()
    {
        var rules = new[] { Rule(program: @"C:\tools\winmysftp.exe") };

        Assert.Equal("Open", Annotate(Socket(port: "22", process: "winmysftp"), rules)[0].Covered);
        Assert.Equal("Not allowed", Annotate(Socket(port: "22", process: "sshd"), rules)[0].Covered);
    }

    [Fact]
    public void UnderBlockAllInboundNoAllowRuleReachesAnything()
        => Assert.Equal("Blocked",
            Annotate(Socket(), new[] { Rule(localPorts: "445", program: "System") },
                     blocksAlways: true)[0].Covered);
}
