using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;

namespace NetworkSentinel.Services;

/// <summary>Simple Avalonia message/confirm dialogs (no WPF MessageBox).</summary>
public static class DialogService
{
    public static async Task ShowInfoAsync(string message, string title = "Network Sentinel")
        => await ShowAsync(title, message, showCancel: false);

    public static async Task ShowWarningAsync(string message, string title = "Network Sentinel")
        => await ShowAsync(title, message, showCancel: false);

    public static async Task<bool> ConfirmAsync(string message, string title = "Confirm")
        => await ShowAsync(title, message, showCancel: true);

    private static async Task<bool> ShowAsync(string title, string message, bool showCancel)
    {
        if (Dispatcher.UIThread.CheckAccess())
            return await ShowCoreAsync(title, message, showCancel);

        return await Dispatcher.UIThread.InvokeAsync(() => ShowCoreAsync(title, message, showCancel));
    }

    private static async Task<bool> ShowCoreAsync(string title, string message, bool showCancel)
    {
        var lifetime = Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime;
        var owner = lifetime?.MainWindow;

        var result = false;
        var dialog = new Window
        {
            Title = title,
            Width = 460,
            Height = 220,
            CanResize = false,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Background = new SolidColorBrush(Color.Parse("#0E1628")),
            Foreground = new SolidColorBrush(Color.Parse("#F2F7FF"))
        };

        var text = new TextBlock
        {
            Text = message,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(20, 20, 20, 12)
        };

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(20, 0, 20, 16),
            Spacing = 8
        };

        var ok = new Button
        {
            Content = showCancel ? "Yes" : "OK",
            MinWidth = 88,
            Padding = new Thickness(14, 8)
        };
        ok.Click += (_, _) =>
        {
            result = true;
            dialog.Close();
        };
        buttons.Children.Add(ok);

        if (showCancel)
        {
            var cancel = new Button
            {
                Content = "No",
                MinWidth = 88,
                Padding = new Thickness(14, 8)
            };
            cancel.Click += (_, _) =>
            {
                result = false;
                dialog.Close();
            };
            buttons.Children.Add(cancel);
        }

        dialog.Content = new DockPanel
        {
            LastChildFill = true,
            Children =
            {
                buttons.Also(b => DockPanel.SetDock(b, Dock.Bottom)),
                text
            }
        };

        if (owner != null)
            await dialog.ShowDialog(owner);
        else
        {
            dialog.Show();
            var tcs = new TaskCompletionSource();
            dialog.Closed += (_, _) => tcs.TrySetResult();
            await tcs.Task;
        }

        return result;
    }

    private static T Also<T>(this T value, Action<T> action)
    {
        action(value);
        return value;
    }
}
