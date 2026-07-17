using System;
using System.IO;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using NetworkSentinel.Services;

namespace NetworkSentinel;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = new MainWindow();

            AppDomain.CurrentDomain.UnhandledException += (_, args) =>
                LogError(args.ExceptionObject as Exception);

            TaskScheduler.UnobservedTaskException += (_, args) =>
            {
                LogError(args.Exception);
                args.SetObserved();
            };
        }

        base.OnFrameworkInitializationCompleted();
    }

    private static void LogError(Exception? ex)
    {
        if (ex == null) return;
        try
        {
            File.AppendAllText(
                Path.Combine(AppPaths.DataDirectory, "error.log"),
                $"[{DateTime.Now:u}] {ex}{Environment.NewLine}{Environment.NewLine}");
        }
        catch
        {
            // never let logging itself crash the app
        }
    }
}
