using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Avalonia;
using NetworkSentinel.Tui;

namespace NetworkSentinel;

internal static class Program
{
    [DllImport("libc")]
    private static extern uint geteuid();

    [STAThread]
    public static void Main(string[] args)
    {
        if (WantsHelp(args))
        {
            PrintUsage();
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

    private static bool WantsHelp(string[] args)
        => args.Any(a => a is "-h" or "--help" or "-?" or "help");

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
              -h, --help         Show this help

            Environment:
              NETWORKSENTINEL_TUI=1              Force TUI
              NETWORKSENTINEL_GUI=1              Force GUI even without DISPLAY
              NETWORKSENTINEL_ALLOW_ROOT_GUI=1   Allow root GUI (rare; X11 only)

            TUI keys (once running):
              1-6 / Tab   views    p pause    a auto-block    b block
              x unblock   u auth   / filter   h help          q quit

            Examples:
              dotnet run -c Release
              dotnet run -c Release -- --tui
              ./NetworkSentinel --tui
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
