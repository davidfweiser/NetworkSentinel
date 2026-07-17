using Avalonia.Controls;
using NetworkSentinel.ViewModels;

namespace NetworkSentinel;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Closed += (_, _) =>
        {
            if (DataContext is MainViewModel vm)
                vm.Dispose();
        };
    }
}
