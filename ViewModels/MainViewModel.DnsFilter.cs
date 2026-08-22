using System.Collections.ObjectModel;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetworkSentinel.Services;

namespace NetworkSentinel.ViewModels;

/// <summary>
/// The DNS filtering switch and the Blocked Sites view.
///
/// This is the one control in the app that can stop a connection from ever being
/// attempted. Everything else acts on a flow that already exists — and on a VPN
/// gateway a client's forwarded traffic never becomes a tracked connection at all,
/// so nothing else in this app can block where a client goes. A resolver refuses to
/// answer, so the client learns no address and dials nothing.
///
/// **The switch is the whole interface.** The sibling POSIX build has an operator run
/// a shell script by hand and only then does the switch mean anything. Here, turning
/// it on with nothing installed offers to install — see <see cref="DnsFilterSetup"/>
/// — so the feature has exactly one entry point and no README step in the middle.
/// The TUI and the web console deliberately do not do this: setup needs Administrator
/// consent at the machine's own desktop, which is precisely what is not there when
/// the console is being driven over the network. They name the command instead.
/// </summary>
public partial class MainViewModel
{
    [ObservableProperty] private bool _showDnsBlocked;

    /// <summary>
    /// Whether a filtering resolver is configured at all. The blocked-sites rail item
    /// is bound to this: without a resolver the view has nothing to read, and an item
    /// that only ever says "not configured" is a worse answer than no item.
    /// </summary>
    [ObservableProperty] private bool _dnsFilterConfigured;

    [ObservableProperty] private string _dnsFilterUrl = "";
    [ObservableProperty] private string _dnsFilterUsername = "";
    [ObservableProperty] private string _dnsFilterPassword = "";
    [ObservableProperty] private string _blockedSitesStatus = "";

    /// <summary>True while setup is running, so the switch cannot be flipped again mid-install.</summary>
    [ObservableProperty] private bool _dnsFilterSetupRunning;

    /// <summary>Names the resolver refused, newest first. Empty when it cannot be read.</summary>
    public ObservableCollection<DnsFilterService.BlockedQuery> BlockedSites { get; } = new();

    private bool _dnsFilterEnabled;

    /// <summary>
    /// Set while setup writes its results into the three address fields, so the
    /// per-keystroke handlers below do not each re-save settings and reconfigure the
    /// service for values that were just saved together. Same shape as
    /// <c>_suppressProbeLogHandler</c>.
    /// </summary>
    private bool _suppressDnsFilterHandlers;

    /// <summary>
    /// The DNS filtering switch. Written from two directions that must not be confused:
    /// the user flipping it, which has to reach the resolver, and the background read
    /// discovering what the resolver actually says, which must not. A generated
    /// [ObservableProperty] gives one setter for both, and the sync path would then
    /// push a write back for a state it had just been told — so this one is by hand.
    /// </summary>
    public bool DnsFilterEnabled
    {
        get => _dnsFilterEnabled;
        set
        {
            if (_dnsFilterEnabled == value) return;
            _dnsFilterEnabled = value;
            OnPropertyChanged();

            // Turning it on with no resolver is not an error to report — it is the
            // request to set one up. Everything else is the ordinary toggle.
            if (value && !_dnsFilter.Configured)
            {
                _ = OfferSetupAsync();
                return;
            }

            // Nothing is persisted: the resolver owns this state. Only the address is ours.
            var (ok, message) = _dnsFilter.SetProtection(value);
            SettingsMessage = message;
            if (!ok)
            {
                // Put the switch back where reality is, or it sits lit over a resolver
                // that never changed.
                _dnsFilterEnabled = !value;
                OnPropertyChanged();
            }
            OnPropertyChanged(nameof(DnsFilterStatus));
        }
    }

    /// <summary>
    /// Asks before installing anything, then runs setup and adopts what it reports.
    ///
    /// The confirmation is not a formality: this registers a service, takes port 53,
    /// and repoints the machine's own resolver. Someone who flipped a switch labelled
    /// "filter names" has not yet agreed to any of that, so it is all named before
    /// consent, and Windows asks again for elevation on top.
    /// </summary>
    private async Task OfferSetupAsync()
    {
        if (!DnsFilterSetup.Available)
        {
            SettingsMessage = "The setup script is not installed beside this build. Point the resolver " +
                              "address below at an AdGuard Home you have installed yourself.";
            RevertSwitch();
            return;
        }

        var answer = MessageBox.Show(
            DnsFilterSetup.DescribePlan(),
            "Set up DNS filtering",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (answer != MessageBoxResult.Yes)
        {
            SettingsMessage = "DNS filtering was not set up, so nothing was changed.";
            RevertSwitch();
            return;
        }

        DnsFilterSetupRunning = true;
        SettingsMessage = "Setting up the filtering resolver — this can take a few minutes.";
        try
        {
            var result = await DnsFilterSetup.RunAsync().ConfigureAwait(true);
            if (!result.Ok || result.Url.Length == 0)
            {
                SettingsMessage = result.Message.Length > 0
                    ? result.Message
                    : "Setup did not complete, so DNS filtering was not turned on.";
                RevertSwitch();
                return;
            }

            // Adopt what the script actually built, rather than what we asked for.
            _settings.DnsFilterUrl = result.Url;
            _settings.DnsFilterUsername = result.Username;
            _settings.DnsFilterPassword = result.Password;
            _settings.Save();

            // Suppressed rather than assigned to the backing fields: the handlers below
            // would each save settings again and reconfigure the service mid-flight, and
            // the three values were just written together above.
            _suppressDnsFilterHandlers = true;
            try
            {
                DnsFilterUrl = result.Url;
                DnsFilterUsername = result.Username;
                DnsFilterPassword = result.Password;
            }
            finally
            {
                _suppressDnsFilterHandlers = false;
            }

            _dnsFilter.Configure(result.Url, result.Username, result.Password);
            DnsFilterConfigured = true;

            // A resolver the script just installed is already filtering; confirm it
            // rather than assume, so the switch reflects the resolver either way.
            await _dnsFilter.RefreshAsync().ConfigureAwait(true);
            var live = _dnsFilter.ProtectionEnabled == true;
            if (!live)
            {
                var (ok, message) = await _dnsFilter.SetProtectionAsync(true).ConfigureAwait(true);
                live = ok;
                if (!ok) SettingsMessage = message;
            }

            _dnsFilterEnabled = live;
            OnPropertyChanged(nameof(DnsFilterEnabled));
            if (live)
                SettingsMessage = result.Message.Length > 0
                    ? result.Message
                    : $"DNS filtering is on, at {result.Url}.";
            OnPropertyChanged(nameof(DnsFilterStatus));
        }
        finally
        {
            DnsFilterSetupRunning = false;
        }
    }

    /// <summary>Puts the switch back to off after a setup that did not happen.</summary>
    private void RevertSwitch()
    {
        _dnsFilterEnabled = false;
        OnPropertyChanged(nameof(DnsFilterEnabled));
        OnPropertyChanged(nameof(DnsFilterStatus));
    }

    /// <summary>
    /// Adopts the resolver's own answer without calling back out to it — the read path
    /// of <see cref="DnsFilterEnabled"/>.
    /// </summary>
    private void SyncDnsFilterFromResolver(bool live)
    {
        if (_dnsFilterEnabled == live) return;
        _dnsFilterEnabled = live;
        OnPropertyChanged(nameof(DnsFilterEnabled));
    }

    /// <summary>
    /// Live filtering state, read back from the resolver rather than from settings.json —
    /// anyone can flip protection in AdGuard's own UI, and a switch that claims "on"
    /// while nothing is filtered is worse than no switch. Refreshed in the background.
    /// </summary>
    public string DnsFilterStatus
    {
        get
        {
            // Mid-install the resolver does not exist yet, and a background read would
            // overwrite the progress line with "unreachable".
            if (DnsFilterSetupRunning) return "Setting up the filtering resolver…";

            _dnsFilter.EnsureFresh();
            SyncDnsFilterFromResolver(_dnsFilter.ProtectionEnabled == true);
            return _dnsFilter.Status;
        }
    }

    [RelayCommand]
    private async Task RefreshBlockedSitesAsync()
    {
        BlockedSitesStatus = "Reading the resolver…";
        var (ok, message, entries) = await _dnsFilter.GetBlockedAsync().ConfigureAwait(true);
        BlockedSites.Clear();
        if (ok)
        {
            foreach (var entry in entries)
                BlockedSites.Add(entry);
        }
        BlockedSitesStatus = message;
    }

    partial void OnDnsFilterUrlChanged(string value)
    {
        if (_suppressDnsFilterHandlers) return;

        var normalised = DnsFilterService.NormalizeBaseUrl(value);
        if (value.Trim().Length > 0 && normalised.Length == 0)
        {
            SettingsMessage = "Enter the resolver's admin address, e.g. 10.8.0.1:3000 or http://10.8.0.1:3000.";
            return;
        }

        // The TextBox reports every keystroke, so only act when the address actually
        // settled somewhere new — otherwise typing one URL rewrites settings.json a
        // character at a time.
        if (normalised == _settings.DnsFilterUrl) return;

        _settings.DnsFilterUrl = normalised;
        _settings.Save();
        _dnsFilter.Configure(normalised, _settings.DnsFilterUsername, _settings.DnsFilterPassword);
        DnsFilterConfigured = normalised.Length > 0;
        if (!DnsFilterConfigured && ShowDnsBlocked)
            Navigate("Dashboard");
        SettingsMessage = normalised.Length == 0
            ? "DNS filter resolver cleared — the switch has nothing to control."
            : $"DNS filter resolver: {normalised}";
        OnPropertyChanged(nameof(DnsFilterStatus));
    }

    partial void OnDnsFilterUsernameChanged(string value)
    {
        if (_suppressDnsFilterHandlers) return;

        var trimmed = value.Trim();
        // Same keystroke guard as the address above: a TextBox reports every character,
        // and each one would otherwise be a settings.json write and an API reconfigure.
        if (trimmed == _settings.DnsFilterUsername) return;

        _settings.DnsFilterUsername = trimmed;
        _settings.Save();
        _dnsFilter.Configure(_settings.DnsFilterUrl, _settings.DnsFilterUsername, _settings.DnsFilterPassword);
        SettingsMessage = trimmed.Length == 0
            ? "DNS filter user cleared — the resolver is assumed to need no login."
            : $"DNS filter user: {trimmed}";
        OnPropertyChanged(nameof(DnsFilterStatus));
    }

    partial void OnDnsFilterPasswordChanged(string value)
    {
        if (_suppressDnsFilterHandlers) return;
        if (value == _settings.DnsFilterPassword) return;

        _settings.DnsFilterPassword = value;
        _settings.Save();
        _dnsFilter.Configure(_settings.DnsFilterUrl, _settings.DnsFilterUsername, _settings.DnsFilterPassword);
        SettingsMessage = value.Length == 0
            ? "DNS filter password cleared."
            : "DNS filter password saved.";
        OnPropertyChanged(nameof(DnsFilterStatus));
    }
}
