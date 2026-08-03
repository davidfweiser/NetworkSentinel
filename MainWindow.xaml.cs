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
        }
    }

    private void OnDuckDnsTokenChanged(object sender, RoutedEventArgs e)
    {
        if (_syncingDuckDnsToken || DataContext is not MainViewModel vm)
            return;
        vm.DuckDnsToken = DuckDnsTokenBox.Password;
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        if (DataContext is MainViewModel vm)
            vm.Dispose();
    }
}
