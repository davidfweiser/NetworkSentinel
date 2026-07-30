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

        if (WantsSetMasterPassword(args))
        {
            // Owns its console when launched without one (Start-Process, shortcut),
            // so the masked prompt is not competing with a parent shell for keys.
            var ownConsole = EnsureConsole();
            RunSetMasterPassword();
            if (ownConsole) WaitBeforeClosing();
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

    private static bool WantsSetMasterPassword(string[] args)
        => args.Any(a => a is "--set-master-password" or "--reset-master-password");

    /// <summary>
    /// Sets the web UI master password from the terminal, for servers where the
    /// browser flow is not reachable (or the password was lost). Writes to the
    /// shared data directory the web service reads — never a per-user copy, which
    /// the service (running as SYSTEM) would silently ignore.
    /// </summary>
    private static void RunSetMasterPassword()
    {
        try
        {
            var dataDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "NetworkSentinel");

            if (!TryPrepareSharedDirectory(dataDir, out var prepareError))
            {
                Console.Error.WriteLine($"Cannot write to the shared data directory: {dataDir}");
                Console.Error.WriteLine(prepareError);
                Console.Error.WriteLine();
                Console.Error.WriteLine("Re-run this from an elevated prompt (Run as administrator) so the");
                Console.Error.WriteLine("password lands where the web service reads it.");
                Environment.Exit(1);
                return;
            }

            var store = new Web.WebAuthStore(dataDir);
            Console.WriteLine(store.IsConfigured
                ? "A master password is already set — this will overwrite it."
                : "No master password is set yet — creating one.");
            Console.WriteLine($"Data directory: {dataDir}");
            Console.WriteLine();

            var password = ReadPassword($"New master password (min {Web.WebAuthStore.MinPasswordLength} characters): ");
            var confirm = ReadPassword("Confirm master password: ");

            if (!store.SetPassword(password, confirm, out var message))
            {
                Console.Error.WriteLine($"Failed: {message}");
                Environment.Exit(1);
                return;
            }

            Console.WriteLine(message);
            Console.WriteLine();
            Console.WriteLine("If the web service is currently running, restart it to pick up the change:");
            Console.WriteLine("  schtasks /End /TN \"NetworkSentinel-Web\"");
            Console.WriteLine("  schtasks /Run /TN \"NetworkSentinel-Web\"");
        }
        catch (Exception ex)
        {
            LogCrash("set-master-password", ex);
            Console.Error.WriteLine("Failed to set master password:");
            Console.Error.WriteLine(ex.Message);
            Environment.Exit(1);
        }
    }

    private static bool TryPrepareSharedDirectory(string dir, out string error)
    {
        try
        {
            Directory.CreateDirectory(dir);
            var probe = Path.Combine(dir, $".write-test-{Environment.ProcessId}");
            File.WriteAllText(probe, "");
            File.Delete(probe);
            error = "";
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>Reads a line with each character masked as '*'; falls back to plain ReadLine when input is redirected (e.g. piped/non-interactive).</summary>
    private static string ReadPassword(string prompt)
    {
        Console.Write(prompt);

        if (Console.IsInputRedirected)
            return Console.ReadLine() ?? "";

        var buffer = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return buffer.ToString();
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (buffer.Length > 0)
                {
                    buffer.Length--;
                    Console.Write("\b \b");
                }
                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                buffer.Append(key.KeyChar);
                Console.Write('*');
            }
        }
    }

    /// <summary>Keeps an app-owned console window open long enough to read the result.</summary>
    private static void WaitBeforeClosing()
    {
        if (Console.IsInputRedirected) return;
        Console.WriteLine();
        Console.Write("Press any key to close…");
        try { Console.ReadKey(intercept: true); } catch { /* no console input */ }
        Console.WriteLine();
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

    /// <summary>
    /// Attaches to the parent console (cmd/PowerShell) when launched from a terminal;
    /// otherwise allocates a new console window for TUI/web logs. Returns true when
    /// this process owns the console — i.e. closing it would take the output with it.
    /// </summary>
    private static bool EnsureConsole()
    {
        var owned = false;
        if (!AttachConsole(AttachParentProcess))
            owned = AllocConsole();

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

        return owned;
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
              --set-master-password    Set/reset the web UI master password from the
                                        terminal (no browser needed). Writes to
                                        %ProgramData%\NetworkSentinel, so run it elevated
                                        if that folder is not writable, then restart the
                                        web service. From PowerShell, launch it with
                                        Start-Process -Wait so the prompt owns the console.
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
