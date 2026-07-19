using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using NetworkSentinel.Tui;
using NetworkSentinel.Web;

namespace NetworkSentinel;

/// <summary>
/// Entry point — desktop GUI (default), terminal UI (--tui), or headless web (-w).
/// Mirrors the Linux Network Sentinel server modes on Windows.
/// </summary>
internal static class Program
{
    private const int AttachParentProcess = -1;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AllocConsole();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeConsole();

    [STAThread]
    public static void Main(string[] args)
    {
        // Any fatal error must leave evidence: %ProgramData%\NetworkSentinel\logs\crash.log
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            LogCrash("unhandled", e.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            LogCrash("unobserved-task", e.Exception);
            e.SetObserved();
        };

        if (WantsHelp(args))
        {
            EnsureConsole();
            PrintUsage();
            return;
        }

        if (WantsWeb(args, out var webPort))
        {
            EnsureConsole();
            RunWeb(webPort);
            return;
        }

        if (WantsTui(args))
        {
            EnsureConsole();
            RunTui();
            return;
        }

        // Desktop WPF GUI
        var app = new App();
        app.InitializeComponent();
        app.Run();
    }

    private static void LogCrash(string kind, Exception? ex)
    {
        try
        {
            var dir = Path.Combine(Services.AppPaths.DataDirectory, "logs");
            Directory.CreateDirectory(dir);
            File.AppendAllText(
                Path.Combine(dir, "crash.log"),
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {kind}:{Environment.NewLine}{ex}{Environment.NewLine}{Environment.NewLine}");
        }
        catch
        {
            // never let crash logging crash
        }
    }

    private static void RunTui()
    {
        try
        {
            using var app = new TuiApp();
            app.RunAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Network Sentinel TUI failed:");
            Console.Error.WriteLine(ex);
            Environment.Exit(1);
        }
    }

    private static void RunWeb(int? port)
    {
        try
        {
            using var app = new WebApp(port);
            app.RunAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            LogCrash("web-host", ex);
            Console.Error.WriteLine("Network Sentinel web UI failed:");
            Console.Error.WriteLine(ex.Message);
            if (ex.InnerException != null)
                Console.Error.WriteLine(ex.InnerException.Message);
            Environment.Exit(1);
        }
    }

    private static bool WantsHelp(string[] args)
        => args.Any(a => a is "-h" or "--help" or "-?" or "help");

    /// <summary>
    /// Headless browser UI when: -w / --web, optional port as -w PORT, -w=PORT, --web=PORT.
    /// </summary>
    private static bool WantsWeb(string[] args, out int? port)
    {
        port = null;
        for (var i = 0; i < args.Length; i++)
        {
            var a = args[i];

            if (a is "-w" or "--web" or "web")
            {
                if (i + 1 < args.Length && int.TryParse(args[i + 1], out var p) && p is >= 1 and <= 65535)
                    port = p;
                return true;
            }

            if (a.StartsWith("-w=", StringComparison.Ordinal) ||
                a.StartsWith("--web=", StringComparison.Ordinal))
            {
                var value = a[(a.IndexOf('=') + 1)..];
                if (int.TryParse(value, out var p) && p is >= 1 and <= 65535)
                    port = p;
                else
                {
                    Console.Error.WriteLine($"Invalid web port in '{a}'. Use e.g. -w=18765");
                    Environment.Exit(2);
                }
                return true;
            }

            if (a.Length > 2 && a.StartsWith("-w", StringComparison.Ordinal) &&
                int.TryParse(a.AsSpan(2), out var glued) && glued is >= 1 and <= 65535)
            {
                port = glued;
                return true;
            }
        }

        var env = Environment.GetEnvironmentVariable("NETWORKSENTINEL_WEB");
        if (string.Equals(env, "1", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(env, "true", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(env, "yes", StringComparison.OrdinalIgnoreCase))
        {
            for (var i = 0; i < args.Length; i++)
            {
                if ((args[i] is "--port" or "-p") && i + 1 < args.Length &&
                    int.TryParse(args[i + 1], out var p) && p is >= 1 and <= 65535)
                {
                    port = p;
                    break;
                }
            }
            return true;
        }

        return false;
    }

    private static bool WantsTui(string[] args)
    {
        if (args.Any(a => a is "--tui" or "-t" or "tui" or "--console"))
            return true;

        var env = Environment.GetEnvironmentVariable("NETWORKSENTINEL_TUI");
        if (string.Equals(env, "1", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(env, "true", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(env, "yes", StringComparison.OrdinalIgnoreCase))
            return true;

        // On a Windows Server session without interactive desktop, prefer TUI
        // only when explicitly requested or NETWORKSENTINEL_TUI is set —
        // do not auto-switch (GUI is still the desktop default).
        return false;
    }

    private static void EnsureConsole()
    {
        // Attach to parent console (cmd/PowerShell) when launched from a terminal;
        // otherwise allocate a new console window for TUI/web logs.
        if (!AttachConsole(AttachParentProcess))
            AllocConsole();

        try
        {
            var utf8 = new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
            Console.OutputEncoding = utf8;
            Console.InputEncoding = utf8;
            Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
            Console.SetError(new StreamWriter(Console.OpenStandardError()) { AutoFlush = true });
            Console.SetIn(new StreamReader(Console.OpenStandardInput()));
        }
        catch
        {
            // best-effort
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine(
            """
            Network Sentinel — Windows network monitor & intrusion awareness

            Usage:
              NetworkSentinel [options]

            Options:
              (default)          Desktop GUI (WPF)
              --tui, -t, tui     Terminal UI (Spectre.Console) — good for Server Core / RDP console
              --console          Same as --tui
              -w, --web [PORT]   Headless web UI (browser). Auto-picks a free high port
                                 if PORT is omitted (prefers 18765, then nearby alternatives)
              -h, --help         Show this help

            Environment:
              NETWORKSENTINEL_TUI=1   Force TUI
              NETWORKSENTINEL_WEB=1   Force headless web UI

            TUI keys (once running):
              1-7 / Tab   views    p pause    a auto-block    b block
              x unblock   u admin  / filter   h help          q quit

            Examples:
              NetworkSentinel
              NetworkSentinel --tui
              NetworkSentinel -w
              NetworkSentinel -w 18765
              dotnet run -c Release -- --tui
              dotnet run -c Release -- -w 18765

            Firewall block/unblock requires Administrator (UAC). Web UI creates a
            master password on first browser visit (stored under %LocalAppData%\NetworkSentinel).
            """);
    }
}
