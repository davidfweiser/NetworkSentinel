using System.Windows;
using System.Windows.Media.Animation;
using NetworkSentinel.ViewModels;

namespace NetworkSentinel;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Closed += OnClosed;
    }

    /// <summary>Set while the DuckDNS token box is being filled from the view model, so the
    /// resulting PasswordChanged does not write the same value straight back and re-save.</summary>
    private bool _syncingDuckDnsToken;

    /// <summary>Same guard for the resolver password box, which DNS filter setup also fills in.</summary>
    private bool _syncingDnsFilterPassword;

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (Resources["PulseStoryboard"] is Storyboard pulse)
            pulse.Begin();

        // PasswordBox.Password is not a DependencyProperty (by design — it would leave the
        // secret in the binding system), so the initial value is pushed across by hand.
        if (DataContext is MainViewModel vm)
        {
            _syncingDuckDnsToken = true;
            DuckDnsTokenBox.Password = vm.DuckDnsToken;
            _syncingDuckDnsToken = false;

            _syncingDnsFilterPassword = true;
            DnsFilterPasswordBox.Password = vm.DnsFilterPassword;
            _syncingDnsFilterPassword = false;

            // Unsubscribe first: Loaded fires again if the window is ever re-shown,
            // and a second subscription would scroll twice for one open.
            vm.PropertyChanged -= OnViewModelPropertyChanged;
            vm.PropertyChanged += OnViewModelPropertyChanged;
        }
    }

    /// <summary>
    /// The rule editor sits above the rule lists, so "New rule" on a listening-services
    /// row near the bottom of a scrolled page would otherwise fill in a form the
    /// operator cannot see and read as a button that did nothing. Posted, not called:
    /// the Border is still collapsed at the moment IsRuleEditorOpen flips, and a
    /// control with no layout slot cannot be scrolled to.
    /// </summary>
    private void OnViewModelPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        // DNS filter setup writes the resolver password into the view model itself, and
        // a PasswordBox cannot be bound, so the box has to be told. Without this the
        // field sits empty over a password that is stored and working, which reads as
        // setup having failed to save it.
        if (e.PropertyName == nameof(MainViewModel.DnsFilterPassword) && sender is MainViewModel source)
        {
            _syncingDnsFilterPassword = true;
            try { DnsFilterPasswordBox.Password = source.DnsFilterPassword; }
            finally { _syncingDnsFilterPassword = false; }
            return;
        }

        if (e.PropertyName != nameof(MainViewModel.IsRuleEditorOpen)) return;
        if (sender is not MainViewModel vm || !vm.IsRuleEditorOpen) return;

        Dispatcher.BeginInvoke(
            new Action(() => RuleEditorCard?.BringIntoView()),
            System.Windows.Threading.DispatcherPriority.Loaded);
    }

    private void OnDuckDnsTokenChanged(object sender, RoutedEventArgs e)
    {
        if (_syncingDuckDnsToken || DataContext is not MainViewModel vm)
            return;
        vm.DuckDnsToken = DuckDnsTokenBox.Password;
    }

    private void OnDnsFilterPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (_syncingDnsFilterPassword || DataContext is not MainViewModel vm)
            return;
        vm.DnsFilterPassword = DnsFilterPasswordBox.Password;
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        if (DataContext is MainViewModel vm)
            vm.Dispose();
    }
}
