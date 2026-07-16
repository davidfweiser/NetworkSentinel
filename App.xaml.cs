using System.IO;
using System.Windows;

namespace NetworkSentinel;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        DispatcherUnhandledException += (_, args) =>
        {
            LogError(args.Exception);
            MessageBox.Show(
                $"Unexpected error:\n{args.Exception.Message}\n\nDetails were written to error.log in %LocalAppData%\\NetworkSentinel.",
                "Network Sentinel",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            args.Handled = true;
        };

        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            LogError(args.Exception);
            args.SetObserved();
        };

        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            LogError(args.ExceptionObject as Exception);
    }

    private static void LogError(Exception? ex)
    {
        if (ex == null) return;
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "NetworkSentinel");
            Directory.CreateDirectory(dir);
            File.AppendAllText(
                Path.Combine(dir, "error.log"),
                $"[{DateTime.Now:u}] {ex}{Environment.NewLine}{Environment.NewLine}");
        }
        catch
        {
            // never let logging itself crash the app
        }
    }
}
