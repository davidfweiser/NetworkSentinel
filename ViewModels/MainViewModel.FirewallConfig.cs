using System.Collections.ObjectModel;
using System.Globalization;
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
/// The list is the whole host firewall, read back out of Windows Defender Firewall
/// by <see cref="HostFirewallScanner"/> — Windows' own rules, the ones installers
/// wrote, and this app's, in one list. It used to be this app's rules and nothing
/// else, which is a handful of rows sitting beside the fifteen hundred rules in the
/// same firewall.
///
/// Writes go into that firewall through <see cref="FirewallService"/>, so a rule
/// written here is visible in wf.msc like any other. What no rule can do is change
/// a profile's default inbound or outbound action — that is a per-profile setting,
/// and the view shows the profiles' actual settings rather than implying that an
/// Allow rule is what grants access.
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
    [ObservableProperty] private string _firewallConfigListenerText = "";
    [ObservableProperty] private bool _isFirewallConfigScanning;

    private HostFirewallScanner? _hostScanner;

    /// <summary>Built on first use — _firewall is assigned in the constructor, after field initializers run.</summary>
    private HostFirewallScanner HostScanner => _hostScanner ??= new HostFirewallScanner(_firewall);

    /// <summary>Rules the firewall evaluates on traffic arriving at this host.</summary>
    public ObservableCollection<FirewallRuleInfo> InboundRules { get; } = new();

    /// <summary>Rules the firewall evaluates on traffic this host sends.</summary>
    public ObservableCollection<FirewallRuleInfo> OutboundRules { get; } = new();

    /// <summary>What is listening on this host, and whether the firewall admits it.</summary>
    public ObservableCollection<HostListener> ListeningServices { get; } = new();

    /// <summary>
    /// What the listening-services list is, in the words the web console uses for it —
    /// the two front-ends explain the same table the same way.
    /// </summary>
    public string FirewallConfigListenerHint =>
        "The same set “netstat -ano” prints, with what the inbound rules above do to each one. " +
        "“New rule” fills the form above in with that socket's protocol and port.";

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

    /// <summary>
    /// Rescans the host firewall. The scan shells out to netsh twice and walks a
    /// megabyte of rule dump, so it runs off the UI thread — the old read was of
    /// this app's own rules only and could afford to be synchronous; this cannot.
    /// </summary>
    [RelayCommand]
    private async Task RefreshFirewallConfig() => await RefreshFirewallConfigAsync();

    private async Task RefreshFirewallConfigAsync()
    {
        if (IsFirewallConfigScanning) return;
        IsFirewallConfigScanning = true;
        try
        {
            var scan = await Task.Run(() => HostScanner.Scan());
            ApplyHostScan(scan);
        }
        catch (Exception ex)
        {
            FirewallConfigMessage = $"Could not read the host firewall: {ex.Message}";
        }
        finally
        {
            IsFirewallConfigScanning = false;
        }

        IsAdmin = _firewall.IsAdministrator;
        OnPropertyChanged(nameof(InboundCountText));
        OnPropertyChanged(nameof(OutboundCountText));
    }

    private void ApplyHostScan(HostFirewallSnapshot scan)
    {
        InboundRules.Clear();
        OutboundRules.Clear();
        foreach (var rule in scan.Inbound) InboundRules.Add(rule);
        foreach (var rule in scan.Outbound) OutboundRules.Add(rule);

        ListeningServices.Clear();
        foreach (var listener in scan.Listeners) ListeningServices.Add(listener);

        // Every sentence below is built the same way in the web console's
        // renderFirewallConfig(), from the same fields, so an operator moving between
        // the two front-ends reads the same page about the same firewall.
        var total = scan.Inbound.Count + scan.Outbound.Count;
        var mine = scan.Inbound.Concat(scan.Outbound).Count(r => !r.IsForeign);
        var folded = scan.Inbound.Concat(scan.Outbound).Sum(r => r.Copies) - total;
        FirewallConfigSummary =
            $"{scan.HostLabel} · {scan.Backend} · {scan.Status} · {scan.RulesSummary} " +
            $"({mine} from Network Sentinel, {total - mine} from the rest of the host)" +
            (folded > 0 ? $" · {folded} duplicate rules folded into the rows they repeat" : "") +
            (scan.DisabledRules > 0 ? $" · {scan.DisabledRules} disabled rules not listed" : "") +
            $" · Scanned {scan.ScannedUtc.ToLocalTime():HH:mm:ss}, not live — Rescan to re-read the firewall.";

        var openCount = scan.Listeners.Count(l => l.Covered == "Open");
        FirewallConfigListenerText = scan.Listeners.Count == 0
            ? "No listening sockets were readable."
            : $"{scan.Listeners.Count} listening socket{(scan.Listeners.Count == 1 ? "" : "s")} · " +
              $"{openCount} reachable from anywhere";

        FirewallConfigPolicyText =
            $"Default policy: {scan.DefaultInbound} inbound, {scan.DefaultOutbound} outbound. " +
            (scan.DefaultInbound.Equals("Allow", StringComparison.OrdinalIgnoreCase)
                ? "Inbound traffic no rule matches is allowed, so an Allow rule opens a path through the rules " +
                  "above it rather than granting access on its own. "
                : "Inbound traffic no rule matches is blocked, so a service is only reachable if a rule admits it. ") +
            "Windows evaluates block rules before allow rules, so an Allow rule here can never reopen an " +
            "address auto-block just closed. " + scan.PrivilegeNote;

        FirewallConfigMessage = scan.Errors.Count > 0 ? string.Join("  ", scan.Errors) : "";
    }

    [RelayCommand]
    private void AddInboundRule() => OpenRuleEditor(null, FirewallRuleSpecs.DirectionInbound);

    [RelayCommand]
    private void AddOutboundRule() => OpenRuleEditor(null, FirewallRuleSpecs.DirectionOutbound);

    /// <summary>
    /// Starts an inbound rule from a row of the listening-services list — those
    /// sockets are what a rule on this page is written against, so the page shows
    /// them rather than making you read them off <c>netstat -ano</c> in a terminal.
    ///
    /// Protocol and port carry over; the bind address deliberately does not.
    /// Sources matches the far end of a connection, so seeding it with 0.0.0.0,
    /// ::, or this host's own LAN address would produce a rule that matches
    /// nothing an attacker sends.
    /// </summary>
    [RelayCommand]
    private void NewRuleForListener(HostListener? listener)
    {
        if (listener == null) return;
        if (!int.TryParse(listener.Port, NumberStyles.Integer, CultureInfo.InvariantCulture, out var port))
        {
            FirewallConfigMessage =
                $"“{listener.Port}” is not a single port number, so there is nothing to prefill — " +
                "write the rule by hand with Add an Inbound Rule.";
            return;
        }

        OpenRuleEditor(null, FirewallRuleSpecs.DirectionInbound);
        RuleProtocol = listener.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase) ? "UDP" : "TCP";
        RulePortRange = port.ToString(CultureInfo.InvariantCulture);
        RuleEditorNote =
            $"Writes a rule for {RuleProtocol} port {port}, which {DescribeListener(listener)} is listening on. " +
            "Sources is left empty (every address) — it matches the remote end, not the address the " +
            "service is bound to. Needs Administrator rights.";
    }

    private static string DescribeListener(HostListener listener)
    {
        var name = string.IsNullOrWhiteSpace(listener.Process) || listener.Process == "—"
            ? "an unidentified process"
            : listener.Process;
        var where = string.IsNullOrWhiteSpace(listener.Address)
            ? $"port {listener.Port}"
            : $"{listener.Address}:{listener.Port}";
        return $"{name} on {where}";
    }

    /// <summary>
    /// The rule being edited when this app did not write it. Windows Defender
    /// Firewall has no edit-in-place for a rule owned by something else — and
    /// rewriting one under its own name would leave two rules claiming it — so, as
    /// FireWallConfig does, saving deletes the original where it lives and writes
    /// the new values as a rule of ours.
    /// </summary>
    private FirewallRuleInfo? _editingForeignRule;

    [RelayCommand]
    private void EditConfigRule(FirewallRuleInfo? rule)
    {
        if (rule == null) return;

        // Auto-block's rules and the web console's own are ours, but they are not
        // config rules: SaveCustomRule refuses to rewrite one, so opening the form
        // over it would only fail at the Save button.
        if (!rule.IsForeign && !rule.IsCustom)
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
            _editingRuleName = existing is { IsForeign: false } ? existing.Name : "";
            _editingForeignRule = existing is { IsForeign: true } ? existing : null;
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
            ? (_editingForeignRule != null
                ? $"“{existing!.LabelText}” was created by {existing.OriginText}. " +
                  "Saving removes it from Windows Defender Firewall and writes these values as a rule of " +
                  "Network Sentinel's — there is no way to edit somebody else's rule in place."
                : "Replaces the loaded rule with these values.")
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
        _editingForeignRule = null;
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

        // Editing a rule this app did not write: remove the original where it lives
        // first. If that fails the save stops, because writing the replacement on top
        // would leave both rules in force — and on Windows the block of the two wins,
        // whichever the operator meant.
        var foreign = _editingForeignRule;
        if (foreign != null)
        {
            var removed = await Task.Run(() => _firewall.DeleteHostRule(foreign));
            if (!removed.Success)
            {
                RuleEditorError = $"The original rule could not be removed, so it was not replaced: {removed.Message}";
                FirewallConfigMessage = RuleEditorError;
                return;
            }
        }

        var replace = string.IsNullOrEmpty(_editingRuleName) ? null : _editingRuleName;
        var result = await Task.Run(() => _firewall.SaveCustomRule(spec, replace));

        FirewallConfigMessage = foreign != null && result.Success
            ? $"{result.Message} The rule it replaced was removed from {foreign.OriginText}."
            : result.Message;
        if (!result.Success)
        {
            RuleEditorError = foreign != null
                ? $"{result.Message} The original rule was already removed."
                : result.Message;
            return;
        }

        // Reflect the values the firewall actually took, so the label the operator
        // sees in the list is the one that was minted if they left the field blank.
        IsRuleEditorOpen = false;
        _editingRuleName = "";
        _editingForeignRule = null;
        await RefreshFirewallConfigAsync();
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
                      "the remaining rules and the profile default decide, which may be a block. If you " +
                      "administer this host over RDP, that can end the session you are using now.";
        }
        else if (rule.IsForeign)
        {
            warning = $"\n\nThis rule belongs to {rule.OriginText}, not to Network Sentinel. " +
                      "Deleting it removes it from Windows Defender Firewall for good.";
        }
        else if (!rule.IsCustom)
        {
            warning = $"\n\nThis rule came from {rule.OriginText.ToLowerInvariant()}. Deleting it here " +
                      "unblocks that traffic until something detects it again.";
        }

        // One row can stand for a set of identical rules, and the delete takes all of
        // them — which is the point on a host carrying hundreds of copies, but not
        // something to discover afterwards.
        if (rule.Copies > 1)
        {
            warning += $"\n\nWindows holds {rule.Copies} identical copies of this rule. " +
                       "Deleting it removes every one of them.";
        }

        var confirmed = MessageBox.Show(
            $"Delete \"{rule.LabelText}\"?\n\n" +
            $"{rule.ActionText} · {rule.DirectionText} · {rule.ProtocolText} · {rule.PortRangeText} · {rule.AddressListText}" +
            warning,
            "Delete rule",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question) == MessageBoxResult.Yes;
        if (!confirmed) return;

        var result = await Task.Run(() => _firewall.DeleteHostRule(rule));
        FirewallConfigMessage = result.Message;

        // An IP block removed here is a deliberate release, exactly as it is on the
        // Firewall page — without this, auto-block would recreate it on the next hit.
        if (result.Success && rule.Kind == FirewallRuleKind.IpBlock &&
            FirewallService.TryExtractIpFromManagedRule(rule.Name, rule.RemoteAddresses, out var ip))
        {
            _prevention.NoteUnblocked(ip);
        }

        await RefreshFirewallConfigAsync();
        RefreshFirewallRules();
    }

    partial void OnRuleDirectionChanged(string value)
    {
        OnPropertyChanged(nameof(RuleAddressLabel));

        // Retitle a form the operator re-pointed with the Direction combo.
        var side = value == FirewallRuleSpecs.DirectionOutbound ? "Outbound" : "Inbound";
        RuleEditorTitle = string.IsNullOrEmpty(_editingRuleName) && _editingForeignRule == null
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
