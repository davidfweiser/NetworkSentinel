using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Avalonia;

namespace NetworkSentinel;

internal static class Program
{
    [DllImport("libc")]
    private static extern uint geteuid();

    [STAThread]
    public static void Main(string[] args)
    {
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

                Then use “Authorize firewall” or allow the pkexec password prompt
                when blocking IPs/ports.
                """);
            Console.Error.WriteLine(ex);
            Environment.Exit(1);
        }
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
