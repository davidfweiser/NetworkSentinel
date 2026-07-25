using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Avalonia;
using NetworkSentinel.Tui;
using NetworkSentinel.Web;

namespace NetworkSentinel;

internal static class Program
{
    [DllImport("libc")]
    private static extern uint geteuid();

    [DllImport("libc", SetLastError = true)]
    private static extern int chown(string pathname, uint owner, uint group);

    [STAThread]
    public static void Main(string[] args)
    {
        // Any fatal error must leave evidence: <data dir>/logs/crash.log
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            LogCrash("unhandled", e.ExceptionObject as Exception);
        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            LogCrash("unobserved-task", e.Exception);
            e.SetObserved();
        };

        if (WantsHelp(args))
        {
            PrintUsage();
            return;
        }

        if (WantsSetMasterPassword(args))
        {
            RunSetMasterPassword();
            return;
        }

        if (WantsWeb(args, out var webPort))
        {
            RunWeb(webPort);
            return;
        }

        if (WantsTui(args))
        {
            RunTui();
            return;
        }

        // Root + Wayland/X11 almost always fails (no X authorization for root).
        // Prefer elevating only nft/iptables via pkexec while the GUI stays as the user.
        if (IsRunningAsRoot() && string.IsNullOrEmpty(Environment.GetEnvironmentVariable("NETWORKSENTINEL_ALLOW_ROOT_GUI")))
        {
            var display = Environment.GetEnvironmentVariable("DISPLAY");
            var wayland = Environment.GetEnvironmentVariable("WAYLAND_DISPLAY");
            if (!string.IsNullOrEmpty(wayland) || string.IsNullOrEmpty(display))
            {
                Console.Error.WriteLine(
                    """
                    Network Sentinel: refusing to start the GUI as root.

                    On Wayland (and most modern desktops), root cannot open your
                    display — that causes:  XOpenDisplay failed

                    Run as your normal user instead:

                        ./NetworkSentinel
                        # or:  dotnet run -c Release

                    For a terminal UI (works over SSH / without a display):

                        ./NetworkSentinel --tui

                    Firewall changes will prompt for your password via pkexec.
                    Only set NETWORKSENTINEL_ALLOW_ROOT_GUI=1 if you know you
                    have a working root display (rare; X11 + xhost only).
                    """);
                Environment.Exit(2);
                return;
            }
        }

        try
        {
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception ex) when (ex.Message.Contains("XOpenDisplay", StringComparison.OrdinalIgnoreCase)
                                   || ex.ToString().Contains("XOpenDisplay", StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine(
                """
                Failed to open the display (XOpenDisplay).

                If you used sudo, stop — do not run this GUI as root on Wayland:

                    # wrong:
                    sudo ./NetworkSentinel

                    # right:
                    ./NetworkSentinel

                Or use the terminal UI (no display required):

                    ./NetworkSentinel --tui
                    # or:  NETWORKSENTINEL_TUI=1 ./NetworkSentinel

                Then use “Authorize firewall” or allow the pkexec password prompt
                when blocking IPs/ports.
                """);
            Console.Error.WriteLine(ex);
            Environment.Exit(1);
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

    private static void RunSetMasterPassword()
    {
        if (!IsRunningAsRoot())
        {
            Console.Error.WriteLine("--set-master-password requires root — re-run with sudo:");
            Console.Error.WriteLine("  sudo networksentinel --set-master-password");
            Environment.Exit(1);
            return;
        }

        try
        {
            var target = ResolveMasterPasswordTarget();
            var dataDir = Path.Combine(target.Home, ".local", "share", "NetworkSentinel");
            Directory.CreateDirectory(dataDir);
            if (target.NeedsChown)
                TryChown(dataDir, target.Uid, target.Gid);

            var store = new Web.WebAuthStore(dataDir);
            Console.WriteLine(store.IsConfigured
                ? "A master password is already set for this user — this will overwrite it."
                : "No master password is set yet for this user — creating one.");
            Console.WriteLine($"Data directory: {dataDir}");
            Console.WriteLine();

            var password = ReadPassword("New master password (min 8 characters): ");
            var confirm = ReadPassword("Confirm master password: ");

            if (!store.SetPassword(password, confirm, out var message))
            {
                Console.Error.WriteLine($"Failed: {message}");
                Environment.Exit(1);
                return;
            }

            if (target.NeedsChown)
                TryChown(Path.Combine(dataDir, "web-master.json"), target.Uid, target.Gid);

            Console.WriteLine(message);
            Console.WriteLine();
            Console.WriteLine("If the web service is currently running, restart it to pick up the change:");
            Console.WriteLine("  sudo systemctl restart networksentinel-web   # system install");
            Console.WriteLine("  systemctl --user restart networksentinel-web # --user install");
        }
        catch (Exception ex)
        {
            LogCrash("set-master-password", ex);
            Console.Error.WriteLine("Failed to set master password:");
            Console.Error.WriteLine(ex.Message);
            Environment.Exit(1);
        }
    }

    /// <summary>
    /// The web service runs as SUDO_USER, not root (see README), so `sudo networksentinel
    /// --set-master-password` must target that user's home — not root's — or the file lands
    /// somewhere the running service never reads. Mirrors the SERVICE_USER/SERVICE_HOME
    /// resolution in scripts/install-from-package.sh.
    /// </summary>
    private static (string Home, uint Uid, uint Gid, bool NeedsChown) ResolveMasterPasswordTarget()
    {
        var sudoUser = Environment.GetEnvironmentVariable("SUDO_USER");
        if (!string.IsNullOrWhiteSpace(sudoUser) && sudoUser != "root")
        {
            var entry = RunGetentPasswd(sudoUser);
            if (entry != null)
            {
                var parts = entry.Split(':');
                if (parts.Length >= 6 && uint.TryParse(parts[2], out var uid) && uint.TryParse(parts[3], out var gid)
                    && !string.IsNullOrWhiteSpace(parts[5]))
                {
                    return (parts[5], uid, gid, true);
                }
            }

            Console.Error.WriteLine($"Warning: could not resolve home directory for SUDO_USER '{sudoUser}' — falling back to root's own home.");
        }

        var rootHome = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(rootHome))
            rootHome = "/root";
        return (rootHome, 0, 0, false);
    }

    private static string? RunGetentPasswd(string user)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "getent",
                RedirectStandardOutput = true,
                UseShellExecute = false
            };
            psi.ArgumentList.Add("passwd");
            psi.ArgumentList.Add(user);

            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null)
                return null;

            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);
            return proc.ExitCode == 0 ? output.Trim() : null;
        }
        catch
        {
            return null;
        }
    }

    private static void TryChown(string path, uint uid, uint gid)
    {
        try
        {
            chown(path, uid, gid);
        }
        catch
        {
            // best-effort — worst case the target user needs a manual chown
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

    private static bool WantsHelp(string[] args)
        => args.Any(a => a is "-h" or "--help" or "-?" or "help");

    /// <summary>
    /// Headless browser UI when: -w / --web, optional port as -w PORT, -w=PORT, --web=PORT, or --port PORT.
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

            // -w18765 (no space / equals)
            if (a.Length > 2 && a.StartsWith("-w", StringComparison.Ordinal) &&
                int.TryParse(a.AsSpan(2), out var glued) && glued is >= 1 and <= 65535)
            {
                port = glued;
                return true;
            }
        }

        // --port only counts when web mode is also requested elsewhere — ignore alone.
        // NETWORKSENTINEL_WEB=1 forces web mode.
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

    /// <summary>
    /// TUI when: --tui / -t / tui arg, NETWORKSENTINEL_TUI=1, or no graphical display
    /// (SSH / headless) and not forced GUI via NETWORKSENTINEL_GUI=1.
    /// </summary>
    private static bool WantsTui(string[] args)
    {
        if (args.Any(a => a is "--tui" or "-t" or "tui" or "--console"))
            return true;

        var env = Environment.GetEnvironmentVariable("NETWORKSENTINEL_TUI");
        if (string.Equals(env, "1", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(env, "true", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(env, "yes", StringComparison.OrdinalIgnoreCase))
            return true;

        if (string.Equals(Environment.GetEnvironmentVariable("NETWORKSENTINEL_GUI"), "1", StringComparison.OrdinalIgnoreCase))
            return false;

        // Auto-select TUI when there is no display (common on SSH / servers).
        var display = Environment.GetEnvironmentVariable("DISPLAY");
        var wayland = Environment.GetEnvironmentVariable("WAYLAND_DISPLAY");
        var hasDisplay = !string.IsNullOrEmpty(display) || !string.IsNullOrEmpty(wayland);
        return !hasDisplay && Console.IsInputRedirected == false;
    }

    private static void PrintUsage()
    {
        Console.WriteLine(
            """
            Network Sentinel — Linux network monitor & intrusion awareness

            Usage:
              NetworkSentinel [options]

            Options:
              (default)          Avalonia GUI (requires display)
              --tui, -t, tui     Terminal UI (Spectre.Console)
              --console          Same as --tui
              -w, --web [PORT]   Headless web UI (browser). Auto-picks a free high port
                                 if PORT is omitted (prefers 18765, then nearby alternatives)
              --set-master-password    Set/reset the web UI master password from the
                                        terminal (no browser needed). Requires root:
                                        sudo networksentinel --set-master-password
                                        Restart the web service afterwards.
              -h, --help         Show this help

            Environment:
              NETWORKSENTINEL_TUI=1              Force TUI
              NETWORKSENTINEL_WEB=1              Force headless web UI
              NETWORKSENTINEL_GUI=1              Force GUI even without DISPLAY
              NETWORKSENTINEL_ALLOW_ROOT_GUI=1   Allow root GUI (rare; X11 only)

            TUI keys (once running):
              1-6 / Tab   views    p pause    a auto-block    b block
              x unblock   u auth   / filter   h help          q quit

            Examples:
              dotnet run -c Release
              dotnet run -c Release -- --tui
              dotnet run -c Release -- -w
              ./NetworkSentinel --tui
              ./NetworkSentinel -w
              ./NetworkSentinel -w 18765
            """);
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();

    private static bool IsRunningAsRoot()
    {
        try
        {
            return geteuid() == 0;
        }
        catch
        {
            try
            {
                var uid = File.ReadAllText("/proc/self/status")
                    .Split('\n')
                    .FirstOrDefault(l => l.StartsWith("Uid:", StringComparison.Ordinal));
                if (uid == null) return false;
                var parts = uid.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                // Uid: real effective saved fs  → effective is index 2
                return parts.Length >= 3 && parts[2] == "0";
            }
            catch
            {
                return false;
            }
        }
    }
}
