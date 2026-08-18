using System.Collections.ObjectModel;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkSentinel.Services;

namespace NetworkSentinel.ViewModels;

/// <summary>
/// The Firewall Config view: add, edit and delete inbound and outbound rules,
/// laid out the way FireWallConfig lays out the Linode Cloud Manager firewall
/// page — one list per direction, Label / Action / Protocol / Port Range /
/// Sources, and one form that both creates and edits.
///
/// The backend is Windows Defender Firewall through <see cref="FirewallService"/>,
/// so the rules here sit beside the app's own blocks and are visible in
/// wf.msc like any other rule. What they cannot do is change a profile's default
/// inbound or outbound action — that is a per-profile setting, not a rule. The
/// view says so rather than implying that an Allow rule is what grants access.
/// </summary>
public partial class MainViewModel
{
    /// <summary>Preset label → (protocol, port range). "Custom" leaves the fields alone.</summary>
    private static readonly Dictionary<string, (string Protocol, string Ports)> RulePresets = new()
    {
        ["RDP (3389/tcp)"] = ("TCP", "3389"),
        ["SMB (445/tcp)"] = ("TCP", "445"),
        ["HTTP (80/tcp)"] = ("TCP", "80"),
        ["HTTPS (443/tcp)"] = ("TCP", "443"),
        ["DNS (53/udp)"] = ("UDP", "53"),
        ["WinRM (5985,5986/tcp)"] = ("TCP", "5985, 5986"),
        ["SQL Server (1433/tcp)"] = ("TCP", "1433"),
        ["WireGuard (51820/udp)"] = ("UDP", "51820"),
        ["Web console (18765,18443/tcp)"] = ("TCP", "18765, 18443"),
        ["ICMP (ping)"] = ("ICMP", "")
    };

    private const string PresetCustom = "Custom";

    /// <summary>Name of the rule being edited; empty when the form is creating one.</summary>
    private string _editingRuleName = "";

    /// <summary>Guards the preset combo from re-applying while the form is being filled.</summary>
    private bool _suppressPresetHandler;

    [ObservableProperty] private bool _showFirewallConfig;
    [ObservableProperty] private bool _isRuleEditorOpen;
    [ObservableProperty] private string _ruleEditorTitle = "Add an Inbound Rule";
    [ObservableProperty] private string _ruleEditorNote = "";
    [ObservableProperty] private string _ruleEditorError = "";
    [ObservableProperty] private string _ruleEditorSaveText = "Add Rule";
    [ObservableProperty] private string _firewallConfigMessage = "";
    [ObservableProperty] private string _firewallConfigSummary = "";
    [ObservableProperty] private string _firewallConfigPolicyText = "";

    [ObservableProperty] private string _rulePreset = PresetCustom;
    [ObservableProperty] private string _ruleLabel = "";
    [ObservableProperty] private string _ruleAction = FirewallRuleSpecs.ActionBlock;
    [ObservableProperty] private string _ruleDirection = FirewallRuleSpecs.DirectionInbound;
    [ObservableProperty] private string _ruleProtocol = "TCP";
    [ObservableProperty] private string _rulePortRange = "";
    [ObservableProperty] private string _ruleAddresses = "";

    [ObservableProperty] private FirewallRuleInfo? _selectedInboundRule;
    [ObservableProperty] private FirewallRuleInfo? _selectedOutboundRule;

    /// <summary>Rules the firewall evaluates on traffic arriving at this host.</summary>
    public ObservableCollection<FirewallRuleInfo> InboundRules { get; } = new();

    /// <summary>Rules the firewall evaluates on traffic this host sends.</summary>
    public ObservableCollection<FirewallRuleInfo> OutboundRules { get; } = new();

    public ObservableCollection<string> RuleActionOptions { get; } = new(FirewallRuleSpecs.Actions);
    public ObservableCollection<string> RuleDirectionOptions { get; } = new(FirewallRuleSpecs.Directions);
    public ObservableCollection<string> RuleProtocolOptions { get; } = new(FirewallRuleSpecs.Protocols);

    public ObservableCollection<string> RulePresetOptions { get; } =
        new(new[] { PresetCustom }.Concat(RulePresets.Keys));

    /// <summary>"Sources" reads wrong on an outbound rule, where the field is the far end.</summary>
    public string RuleAddressLabel => RuleDirection == FirewallRuleSpecs.DirectionOutbound
        ? "Destinations"
        : "Sources";

    public string InboundCountText => $"{InboundRules.Count} inbound rule{(InboundRules.Count == 1 ? "" : "s")}";
    public string OutboundCountText => $"{OutboundRules.Count} outbound rule{(OutboundRules.Count == 1 ? "" : "s")}";

    private void InitializeFirewallConfig() => RefreshFirewallConfig();

    [RelayCommand]
    private void RefreshFirewallConfig()
    {
        try
        {
            var rules = _firewall.GetConfigRules();

            InboundRules.Clear();
            OutboundRules.Clear();
            foreach (var rule in rules)
            {
                if (rule.IsInbound) InboundRules.Add(rule);
                else OutboundRules.Add(rule);
            }

            var custom = rules.Count(r => r.IsCustom);
            FirewallConfigSummary =
                $"{Environment.MachineName} · {rules.Count} rule{(rules.Count == 1 ? "" : "s")} loaded " +
                $"({custom} from this page, {rules.Count - custom} from auto-block and manual blocks)";
        }
        catch (Exception ex)
        {
            FirewallConfigMessage = $"Could not read the rule list: {ex.Message}";
        }

        IsAdmin = _firewall.IsAdministrator;
        FirewallConfigPolicyText =
            "Windows Defender Firewall evaluates block rules before allow rules, so an Allow rule here can " +
            "never reopen an address auto-block just closed — whichever was written first. What no rule can " +
            "change is a profile's default action for traffic nothing matches; that is a per-profile setting " +
            "in Windows Firewall (inbound blocked, outbound allowed on a stock install).";

        OnPropertyChanged(nameof(InboundCountText));
        OnPropertyChanged(nameof(OutboundCountText));
    }

    [RelayCommand]
    private void AddInboundRule() => OpenRuleEditor(null, FirewallRuleSpecs.DirectionInbound);

    [RelayCommand]
    private void AddOutboundRule() => OpenRuleEditor(null, FirewallRuleSpecs.DirectionOutbound);

    [RelayCommand]
    private void EditConfigRule(FirewallRuleInfo? rule)
    {
        if (rule == null) return;
        if (!rule.IsCustom)
        {
            MessageBox.Show(
                $"\"{rule.LabelText}\" was created by {rule.OriginText.ToLowerInvariant()}, not by this page.\n\n" +
                "Remove it from the Firewall page (or let its expiry run out) rather than editing it here — " +
                "rewriting it as a config rule would change what it matches.",
                "Not an editable rule",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        OpenRuleEditor(rule, rule.IsInbound
            ? FirewallRuleSpecs.DirectionInbound
            : FirewallRuleSpecs.DirectionOutbound);
    }

    private void OpenRuleEditor(FirewallRuleInfo? existing, string direction)
    {
        _suppressPresetHandler = true;
        try
        {
            _editingRuleName = existing?.Name ?? "";
            RulePreset = PresetCustom;

            if (existing != null)
            {
                var spec = FirewallRuleSpecs.FromRule(existing);
                RuleLabel = spec.Label;
                RuleAction = spec.Action;
                RuleDirection = spec.Direction;
                RuleProtocol = spec.Protocol;
                RulePortRange = spec.PortRange;
                RuleAddresses = spec.Addresses;
            }
            else
            {
                RuleLabel = "";
                RuleAction = FirewallRuleSpecs.ActionBlock;
                RuleDirection = direction;
                RuleProtocol = "TCP";
                RulePortRange = "";
                RuleAddresses = "";
            }
        }
        finally
        {
            _suppressPresetHandler = false;
        }

        var editing = existing != null;
        var side = RuleDirection == FirewallRuleSpecs.DirectionOutbound ? "Outbound" : "Inbound";
        RuleEditorTitle = editing ? $"Edit an {side} Rule" : $"Add an {side} Rule";
        RuleEditorSaveText = editing ? "Save Rule" : "Add Rule";
        RuleEditorNote = editing
            ? "Replaces the loaded rule with these values."
            : "Writes a rule into Windows Defender Firewall. Needs Administrator rights.";
        RuleEditorError = "";
        IsRuleEditorOpen = true;
    }

    [RelayCommand]
    private void CancelRuleEditor()
    {
        IsRuleEditorOpen = false;
        RuleEditorError = "";
        _editingRuleName = "";
    }

    [RelayCommand]
    private async Task SaveConfigRule()
    {
        // Validate before normalising — see FirewallRuleSpecs.TryPrepare. The other
        // order silently drops a port range the parser rejected, and an empty port
        // field means every port, so "443-80" would arm a catch-all block.
        var typed = new FirewallRuleSpec
        {
            Label = RuleLabel,
            Action = RuleAction,
            Direction = RuleDirection,
            Protocol = RuleProtocol,
            PortRange = RulePortRange,
            Addresses = RuleAddresses
        };

        if (!FirewallRuleSpecs.TryPrepare(typed, out var spec, out var error))
        {
            RuleEditorError = error;
            return;
        }
        RuleEditorError = "";

        // Elevating on Windows means relaunching the process, which would throw the
        // half-typed rule away — so the form says what is needed and keeps the values.
        if (!IsAdmin)
        {
            RuleEditorError = "Administrator rights are required to write a firewall rule. " +
                              "Use “Run as Admin”, then reopen this form.";
            return;
        }

        if (!ConfirmRuleImpact(spec))
            return;

        var replace = string.IsNullOrEmpty(_editingRuleName) ? null : _editingRuleName;
        var result = await Task.Run(() => _firewall.SaveCustomRule(spec, replace));

        FirewallConfigMessage = result.Message;
        if (!result.Success)
        {
            RuleEditorError = result.Message;
            return;
        }

        // Reflect the values the firewall actually took, so the label the operator
        // sees in the list is the one that was minted if they left the field blank.
        IsRuleEditorOpen = false;
        _editingRuleName = "";
        RefreshFirewallConfig();
        RefreshFirewallRules();
    }

    /// <summary>
    /// Confirms the two rules that can take the machine off the network: one that
    /// blocks every address on every port, and one that closes remote access.
    /// </summary>
    private bool ConfirmRuleImpact(FirewallRuleSpec spec)
    {
        var blocking = spec.Action == FirewallRuleSpecs.ActionBlock;
        var side = spec.Direction.ToLowerInvariant();

        if (blocking && FirewallRuleSpecs.IsCatchAll(spec))
        {
            var proceed = MessageBox.Show(
                $"\"{spec.Label}\" blocks every {side} connection on every port, from every address.\n\n" +
                (spec.Direction == FirewallRuleSpecs.DirectionInbound
                    ? "Nothing will be able to reach this host — including the web console and any Remote Desktop session you may be relying on right now.\n\n"
                    : "This host will not be able to reach anything — including the internet.\n\n") +
                "Add it anyway?",
                "This rule blocks everything",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning) == MessageBoxResult.Yes;

            if (!proceed)
            {
                FirewallConfigMessage = "Rule not added.";
                return false;
            }
            return true;
        }

        if (blocking && spec.Direction == FirewallRuleSpecs.DirectionInbound &&
            FirewallRuleSpecs.CoversPort(spec, 3389))
        {
            var proceed = MessageBox.Show(
                $"\"{spec.Label}\" blocks inbound Remote Desktop (port 3389).\n\n" +
                "If you administer this host over RDP, this rule will end that access as soon as it applies.\n\n" +
                "Add it anyway?",
                "This rule blocks Remote Desktop",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning) == MessageBoxResult.Yes;

            if (!proceed)
            {
                FirewallConfigMessage = "Rule not added.";
                return false;
            }
        }

        return true;
    }

    [RelayCommand]
    private async Task DeleteConfigRule(FirewallRuleInfo? rule)
    {
        if (rule == null) return;

        if (!IsAdmin)
        {
            FirewallConfigMessage = "Administrator rights are required to remove a firewall rule — use “Run as Admin”.";
            return;
        }

        var warning = "";
        if (!rule.IsBlock && FirewallRuleSpecs.CoversPort(FirewallRuleSpecs.FromRule(rule), 3389))
        {
            warning = "\n\nThis is the rule that allows Remote Desktop — deleting it leaves RDP to whatever " +
                      "the remaining rules and the profile default decide, which may be a block.";
        }
        else if (!rule.IsCustom)
        {
            warning = $"\n\nThis rule came from {rule.OriginText.ToLowerInvariant()}. Deleting it here " +
                      "unblocks that traffic until something detects it again.";
        }

        var confirmed = MessageBox.Show(
            $"Delete \"{rule.LabelText}\"?\n\n" +
            $"{rule.ActionText} · {rule.DirectionText} · {rule.ProtocolText} · {rule.PortRangeText} · {rule.AddressListText}" +
            warning,
            "Delete rule",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question) == MessageBoxResult.Yes;
        if (!confirmed) return;

        var result = await Task.Run(() => _firewall.RemoveRule(rule.Name));
        FirewallConfigMessage = result.Message;

        // An IP block removed here is a deliberate release, exactly as it is on the
        // Firewall page — without this, auto-block would recreate it on the next hit.
        if (result.Success && rule.Kind == FirewallRuleKind.IpBlock &&
            FirewallService.TryExtractIpFromManagedRule(rule.Name, rule.RemoteAddresses, out var ip))
        {
            _prevention.NoteUnblocked(ip);
        }

        RefreshFirewallConfig();
        RefreshFirewallRules();
    }

    partial void OnRuleDirectionChanged(string value)
    {
        OnPropertyChanged(nameof(RuleAddressLabel));

        // Retitle a form the operator re-pointed with the Direction combo.
        var side = value == FirewallRuleSpecs.DirectionOutbound ? "Outbound" : "Inbound";
        RuleEditorTitle = string.IsNullOrEmpty(_editingRuleName)
            ? $"Add an {side} Rule"
            : $"Edit an {side} Rule";
    }

    partial void OnRulePresetChanged(string value)
    {
        if (_suppressPresetHandler || value == PresetCustom) return;
        if (!RulePresets.TryGetValue(value, out var preset)) return;

        RuleProtocol = preset.Protocol;
        RulePortRange = preset.Ports;
        RuleEditorError = "";
    }
}
