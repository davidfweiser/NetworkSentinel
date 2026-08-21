using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using NetworkSentinel.Services;
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

        if (WantsSetDuckDns(args))
        {
            var ownConsole = EnsureConsole();
            RunSetDuckDns();
            if (ownConsole) WaitBeforeClosing();
            return;
        }

        if (WantsWeb(args, out var webPort))
        {
            EnsureConsole();
            RunWeb(webPort, ParseTlsOptions(args));
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
        // Decides what can be said about a missing privilege: UAC can be approved from
        // the session that launched a TUI or the GUI, and from nowhere at all under the
        // web console.
        FirewallService.Surface = FirewallUiSurface.Terminal;
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

    /// <summary>
    /// TLS flags for the web console. Values given here win over settings.json for this run
    /// but are not persisted, so `--https` is safe to try without committing to it.
    /// </summary>
    private static WebTlsOptions? ParseTlsOptions(string[] args)
    {
        var o = new WebTlsOptions();

        for (var i = 0; i < args.Length; i++)
        {
            var a = args[i];
            string? Inline(string prefix)
                => a.StartsWith(prefix + "=", StringComparison.Ordinal) ? a[(prefix.Length + 1)..] : null;
            string? Next() => i + 1 < args.Length && !args[i + 1].StartsWith('-') ? args[++i] : null;

            switch (a)
            {
                case "--https":
                    o.Enabled = true;
                    continue;
                case "--no-https":
                    o.Enabled = false;
                    continue;
                case "--https-port":
                    if (int.TryParse(Next(), out var hp) && hp is >= 1 and <= 65535)
                    {
                        o.Enabled ??= true;
                        o.Port = hp;
                    }
                    else
                    {
                        Fail("--https-port needs a port number, e.g. --https-port 18443");
                    }
                    continue;
                case "--tls-cert":
                    o.CertPath = Next() ?? Fail("--tls-cert needs a path to a PEM or .pfx certificate");
                    o.Enabled ??= true;
                    continue;
                case "--tls-key":
                    o.KeyPath = Next() ?? Fail("--tls-key needs a path to the PEM private key");
                    continue;
                case "--tls-password":
                    o.PfxPassword = Next() ?? Fail("--tls-password needs the .pfx password");
                    continue;
            }

            if (Inline("--https-port") is { } hpInline)
            {
                if (int.TryParse(hpInline, out var p) && p is >= 1 and <= 65535)
                {
                    o.Enabled ??= true;
                    o.Port = p;
                }
                else
                {
                    Fail($"Invalid HTTPS port in '{a}'");
                }
            }
            else if (Inline("--tls-cert") is { } cert)
            {
                o.CertPath = cert;
                o.Enabled ??= true;
            }
            else if (Inline("--tls-key") is { } key)
            {
                o.KeyPath = key;
            }
            else if (Inline("--tls-password") is { } pw)
            {
                o.PfxPassword = pw;
            }
        }

        return o.HasAny ? o : null;
    }

    private static string Fail(string message)
    {
        Console.Error.WriteLine(message);
        Environment.Exit(2);
        return "";
    }

    private static bool WantsSetDuckDns(string[] args)
        => args.Any(a => a is "--set-duckdns" or "--duckdns");

    /// <summary>
    /// Interactive DuckDNS setup. The token is prompted for rather than passed as a flag so it
    /// does not end up in shell history or the process list.
    /// </summary>
    private static void RunSetDuckDns()
    {
        try
        {
            var updater = new Services.DuckDnsUpdater();
            var current = updater.Config;

            Console.WriteLine("DuckDNS dynamic DNS — keeps a duckdns.org name pointed at this machine.");
            Console.WriteLine($"Config file: {Path.Combine(Services.AppPaths.DataDirectory, "duckdns.json")}");
            if (current.Domain.Length > 0)
                Console.WriteLine($"Current subdomain: {current.Domain}.duckdns.org");
            Console.WriteLine();

            Console.Write("Subdomain (just the label, e.g. 'myhost'): ");
            var domain = Services.DuckDnsUpdater.NormalizeDomain(Console.ReadLine() ?? "");
            if (domain.Length == 0)
            {
                Console.Error.WriteLine("No subdomain entered — nothing changed.");
                Environment.Exit(1);
                return;
            }

            var token = ReadPassword("DuckDNS token (from duckdns.org, hidden): ");
            if (string.IsNullOrWhiteSpace(token))
            {
                Console.Error.WriteLine("No token entered — nothing changed.");
                Environment.Exit(1);
                return;
            }

            var status = updater.Apply(new Services.DuckDnsConfig
            {
                Enabled = true,
                Domain = domain,
                Token = token.Trim(),
                IntervalMinutes = current.IntervalMinutes <= 0 ? 5 : current.IntervalMinutes
            });

            Console.WriteLine();
            Console.WriteLine("Testing the update…");
            var ok = updater.UpdateOnceAsync().GetAwaiter().GetResult();
            Console.WriteLine("  " + updater.Status);
            updater.Dispose();

            if (!ok)
            {
                Console.Error.WriteLine();
                Console.Error.WriteLine("Saved, but DuckDNS rejected the update. Check the subdomain and token.");
                Environment.Exit(1);
                return;
            }

            Console.WriteLine();
            Console.WriteLine($"Saved. The web console refreshes {domain}.duckdns.org every few minutes while it runs.");
            Console.WriteLine(@"Next: issue a certificate with scripts\issue-duckdns-cert.ps1, then start with --https.");
            _ = status;
        }
        catch (Exception ex)
        {
            LogCrash("set-duckdns", ex);
            Console.Error.WriteLine("Failed to configure DuckDNS:");
            Console.Error.WriteLine(ex.Message);
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

    private static void RunWeb(int? port, WebTlsOptions? tls)
    {
        FirewallService.Surface = FirewallUiSurface.Web;
        try
        {
            using var app = new WebApp(port, bindAll: true, tlsOverrides: tls);
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
              --set-duckdns      Configure DuckDNS dynamic DNS (subdomain + token, prompted).
                                 The web service then keeps the record pointed here.
              -h, --help         Show this help

            Web console over HTTPS (used with -w):
              --https            Serve TLS as well as HTTP (needs a certificate)
              --https-port PORT  TLS port (default 18443; below 1024 needs Administrator)
              --tls-cert PATH    PEM fullchain, or a .pfx / .p12 bundle
              --tls-key PATH     PEM private key (omit for .pfx)
              --tls-password PW  Password for a .pfx / .p12 certificate
              --no-https         Force plain HTTP for this run
                                 Flags override settings.json without overwriting it.
                                 Get a trusted certificate for a duckdns.org name with:
                                 scripts\issue-duckdns-cert.ps1

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
              NetworkSentinel -w --https ^
                  --tls-cert %ProgramData%\NetworkSentinel\tls\myhost.duckdns.org.fullchain.cer ^
                  --tls-key  %ProgramData%\NetworkSentinel\tls\myhost.duckdns.org.key
              dotnet run -c Release -- --tui
              dotnet run -c Release -- -w 18765

            Firewall block/unblock requires Administrator (UAC). Web UI creates a
            master password on first browser visit (stored under %LocalAppData%\NetworkSentinel).
            """);
    }
}
