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

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (Resources["PulseStoryboard"] is Storyboard pulse)
            pulse.Begin();
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        if (DataContext is MainViewModel vm)
            vm.Dispose();
    }
}
