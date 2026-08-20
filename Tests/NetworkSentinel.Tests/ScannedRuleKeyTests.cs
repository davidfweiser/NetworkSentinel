using NetworkSentinel.Services;
using NetworkSentinel.Web;
using Xunit;

namespace NetworkSentinel.Tests;

/// <summary>
/// The identity the web console uses to say which firewall row a Delete or an Edit
/// meant.
///
/// It used to be built from the rule's shape alone — direction, action, protocol,
/// displayed ports, sources, label, origin, program, service. Shape is not an
/// identity on Windows. Adding the same Firewall Config rule twice, which the page
/// allows and which an operator retrying a failed delete does naturally, produced two
/// rows that shape could not tell apart: the lookup found two matches for either
/// row's key and refused both, so from that point neither row could be deleted or
/// edited again. The one remedy it suggested — give them distinct names — is done by
/// editing them, through the same lookup.
///
/// The invariant is that every row <see cref="HostFirewallScanner.Dedupe"/> keeps
/// apart carries a key of its own, and every set it folds into one row carries one
/// key. Both halves are checked here against the fold itself.
/// </summary>
public class ScannedRuleKeyTests
{
    /// <summary>
    /// One Firewall Config rule as the console lists it. The defaults describe a
    /// rule on TCP 4822 constrained on its local port, which is what an inbound
    /// rule the operator added through the page looks like.
    /// </summary>
    private static FirewallRuleInfo Rule(
        string name,
        string label,
        string ports = "4822",
        string localPortsRaw = "4822",
        string remotePortsRaw = "",
        string profiles = "Domain,Private,Public",
        string program = "",
        string service = "",
        string origin = "",
        bool isForeign = false) => new()
    {
        Name = name,
        Label = label,
        Enabled = true,
        IsBlock = false,
        Direction = FirewallDirection.Inbound,
        RemoteAddresses = "",
        LocalPorts = ports,
        LocalPortsRaw = localPortsRaw,
        RemotePortsRaw = remotePortsRaw,
        Protocol = "TCP",
        Kind = isForeign ? FirewallRuleKind.Other : FirewallRuleKind.Custom,
        Origin = origin,
        Profiles = profiles,
        Program = program,
        Service = service,
        IsForeign = isForeign
    };

    /// <summary>
    /// Two adds of the same rule: same label, same everything an operator can see.
    /// The minted names differ ("…-2"), and so must the keys — this is the case that
    /// used to lock both rows out of Delete and Edit for good.
    /// </summary>
    [Fact]
    public void TwoAddsOfTheSameRule_GetDifferentKeys()
    {
        var first = Rule("NetworkSentinel-Rule-allow-inbound-4822", "allow-inbound-4822");
        var second = Rule("NetworkSentinel-Rule-allow-inbound-4822-2", "allow-inbound-4822");

        Assert.NotEqual(WebApp.ScannedRuleKey(first), WebApp.ScannedRuleKey(second));
    }

    /// <summary>
    /// Two foreign rules whose display names collapse to the same label —
    /// <see cref="HostFirewallScanner.DisplayName"/> reduces a UWP rule name to its
    /// package family, so this is what a pair of store-app rules actually looks like.
    /// The label cannot separate them; the name still does.
    /// </summary>
    [Fact]
    public void ForeignRulesSharingADisplayLabel_GetDifferentKeys()
    {
        const string package = "Microsoft.WindowsStore_8wekyb3d8bbwe";
        var first = Rule("@{Microsoft.WindowsStore_12.0_x64__8wekyb3d8bbwe?ms-resource://Store/In}",
            package, origin: "Store", isForeign: true);
        var second = Rule("@{Microsoft.WindowsStore_12.0_x64__8wekyb3d8bbwe?ms-resource://Store/In2}",
            package, origin: "Store", isForeign: true);

        Assert.NotEqual(WebApp.ScannedRuleKey(first), WebApp.ScannedRuleKey(second));
    }

    /// <summary>
    /// The displayed port is the local port on an inbound rule, so a rule constrained
    /// on its remote port instead shows the same range while being a different rule.
    /// The fold separates on both raw halves; the key has to as well.
    /// </summary>
    [Fact]
    public void SameDisplayedPortDifferentConstraint_GetsDifferentKeys()
    {
        var onLocalPort = Rule("SSH", "SSH", localPortsRaw: "4822", remotePortsRaw: "");
        var onRemotePort = Rule("SSH", "SSH", localPortsRaw: "", remotePortsRaw: "4822");

        Assert.NotEqual(WebApp.ScannedRuleKey(onLocalPort), WebApp.ScannedRuleKey(onRemotePort));
    }

    /// <summary>
    /// The key must still be stable across rescans, or every Delete would land on
    /// "the list has moved on" — it is computed from the rule, not from its position.
    /// </summary>
    [Fact]
    public void TheSameRuleScannedTwice_KeepsItsKey()
    {
        var scanned = Rule("NetworkSentinel-Rule-SSH", "SSH");
        var rescanned = Rule("NetworkSentinel-Rule-SSH", "SSH");

        Assert.Equal(WebApp.ScannedRuleKey(scanned), WebApp.ScannedRuleKey(rescanned));
    }

    /// <summary>
    /// Shape stays part of the key, so a key cannot follow a rule that was edited
    /// into something else between the page rendering and the click arriving.
    /// </summary>
    [Fact]
    public void ARuleEditedToADifferentPort_NoLongerMatchesItsOldKey()
    {
        var before = Rule("NetworkSentinel-Rule-SSH", "SSH", ports: "4822", localPortsRaw: "4822");
        var after = Rule("NetworkSentinel-Rule-SSH", "SSH", ports: "22", localPortsRaw: "22");

        Assert.NotEqual(WebApp.ScannedRuleKey(before), WebApp.ScannedRuleKey(after));
    }

    /// <summary>
    /// The invariant, checked against the fold: two rules it keeps as separate rows
    /// must carry separate keys, or the list shows a row that nothing can address.
    /// </summary>
    [Fact]
    public void EveryRowTheFoldKeeps_CarriesItsOwnKey()
    {
        var rows = HostFirewallScanner.Dedupe(new[]
        {
            Rule("NetworkSentinel-Rule-allow-inbound-4822", "allow-inbound-4822"),
            Rule("NetworkSentinel-Rule-allow-inbound-4822-2", "allow-inbound-4822")
        });

        Assert.Equal(2, rows.Count);
        Assert.Equal(2, rows.Select(WebApp.ScannedRuleKey).Distinct().Count());
    }

    /// <summary>
    /// The other half: rules that differ only by profile are one row, because the fold
    /// merges them and a delete takes every copy anyway. That is why the profile is
    /// left out of the key — putting it in would split one row's identity in two.
    /// </summary>
    [Fact]
    public void RulesDifferingOnlyByProfile_FoldToOneRowAndOneKey()
    {
        var rows = HostFirewallScanner.Dedupe(new[]
        {
            Rule("SSH", "SSH", profiles: "Domain"),
            Rule("SSH", "SSH", profiles: "Private")
        });

        var row = Assert.Single(rows);
        Assert.Equal(2, row.Copies);
        Assert.Equal(WebApp.ScannedRuleKey(Rule("SSH", "SSH", profiles: "Domain")),
                     WebApp.ScannedRuleKey(row));
    }
}
