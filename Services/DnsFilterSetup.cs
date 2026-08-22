using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace NetworkSentinel.Services;

/// <summary>
/// Runs <c>scripts/setup-dns-filter.ps1</c> on behalf of the DNS filtering switch.
///
/// This has no counterpart in the sibling POSIX build, and the difference is
/// deliberate. There, setup is a shell script an administrator runs by hand and the
/// switch only means anything afterwards. Here the switch is the whole interface:
/// flipping it on with nothing installed offers to install, and a Windows operator
/// never has to know a .ps1 exists. That is the one place this feature is turned on.
///
/// **Why a separate process rather than doing the work in C#.** Installing a resolver
/// is installer work — a service registration, firewall rules, a config file, and an
/// uninstall path that puts all of it back. Keeping it in a script means it can be
/// read before it is run, run without the app, and audited afterwards; none of which
/// is true of the same logic compiled into the binary. It also keeps the app's own
/// process free of the elevation this needs.
///
/// **How the result comes back.** An elevated child cannot have its output redirected:
/// <c>Verb = "runas"</c> requires <c>UseShellExecute</c>, which forbids
/// <c>RedirectStandardOutput</c>. So the app names a file, the script writes one JSON
/// object into it, and the app reads it once the process exits. The file holds the
/// resolver's admin password for as long as it exists, so it is deleted as soon as it
/// is read — including on every failure path.
/// </summary>
public static class DnsFilterSetup
{
    /// <summary>
    /// How long to wait for the script before giving up on it. Generous: it downloads
    /// an AdGuard Home release over whatever the server's link is, and a slow but
    /// working install must not be reported as a failure.
    /// </summary>
    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(15);

    /// <summary>What the script writes back, and all this needs from it.</summary>
    public sealed record Result
    {
        public bool Ok { get; init; }
        public string Url { get; init; } = "";
        public string Username { get; init; } = "";
        public string Password { get; init; } = "";
        public string Message { get; init; } = "";
    }

    /// <summary>
    /// Where the setup script is, or null if it is not shipped beside this build.
    /// A packaged install puts it next to the binary; a source checkout has it under
    /// scripts\. Both are checked because both are real: the server runs the package,
    /// and the machine this is developed on runs the checkout.
    /// </summary>
    public static string? ScriptPath()
    {
        try
        {
            var baseDir = AppContext.BaseDirectory;
            var candidates = new[]
            {
                Path.Combine(baseDir, "setup-dns-filter.ps1"),
                Path.Combine(baseDir, "scripts", "setup-dns-filter.ps1"),
                // A source checkout runs out of bin\Debug\net8.0-windows\, three deep.
                Path.Combine(baseDir, "..", "..", "..", "scripts", "setup-dns-filter.ps1")
            };

            foreach (var candidate in candidates)
            {
                if (File.Exists(candidate))
                    return Path.GetFullPath(candidate);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            // A missing script is a normal answer; an exception looking for it is not
            // worth propagating into a settings toggle.
        }

        return null;
    }

    /// <summary>True when setup can be offered at all.</summary>
    public static bool Available => ScriptPath() != null;

    /// <summary>
    /// What the confirmation dialog says. Written to be readable by someone who has not
    /// read the script: every irreversible-sounding thing it does, named, plus the fact
    /// that it is reversible. Kept here rather than in the view so the TUI and the web
    /// console describe the same operation in the same words.
    /// </summary>
    public static string DescribePlan() =>
        "No filtering resolver is set up on this node yet.\n\n" +
        "Setting one up will:\n" +
        "  • download AdGuard Home and register it as a Windows service\n" +
        "  • bind its admin UI to this node's tunnel address (port 3000)\n" +
        "  • serve DNS on port 53 to tunnel clients only\n" +
        "  • add Windows Firewall rules for both\n" +
        "  • point this machine's own resolver at it\n\n" +
        "Everything it replaces is backed up first, and it can be reversed with " +
        "-Uninstall. This needs Administrator, so Windows will ask for consent.\n\n" +
        "Set up a filtering resolver now?";

    /// <summary>
    /// Runs setup and returns what the script reported. Never throws: a settings toggle
    /// is not a place to surface an exception, and every failure here already has a
    /// sentence fit to show the operator.
    /// </summary>
    /// <param name="tunnelAddress">
    /// Address to bind to, or empty to let the script detect the tunnel. The app knows
    /// no better than the script does, so this exists for the case where an operator
    /// has told it which interface to use.
    /// </param>
    public static async Task<Result> RunAsync(string tunnelAddress = "", CancellationToken ct = default)
    {
        var script = ScriptPath();
        if (script == null)
        {
            return new Result
            {
                Message = "The setup script is not installed beside this build, so DNS filtering " +
                          "cannot be set up from here. Reinstall from the package, or point the " +
                          "resolver address at an AdGuard Home you have installed yourself."
            };
        }

        // Named per run, in the data directory the app already owns. It exists for the
        // seconds between the script writing it and the read below, and holds the
        // resolver's admin password for that window.
        var resultPath = Path.Combine(
            AppPaths.DataDirectory,
            $"dns-filter-setup.{Environment.ProcessId}.{Environment.TickCount64}.json");

        try
        {
            var arguments = $"-NoProfile -ExecutionPolicy Bypass -File \"{script}\" -ResultPath \"{resultPath}\"";
            if (!string.IsNullOrWhiteSpace(tunnelAddress))
                arguments += $" -TunnelAddress \"{tunnelAddress.Trim()}\"";

            var start = new ProcessStartInfo("powershell.exe")
            {
                Arguments = arguments,
                // Both are required together for elevation, and together they rule out
                // redirecting output — which is why the result comes back in a file.
                UseShellExecute = true,
                Verb = "runas"
            };

            using var process = Process.Start(start);
            if (process == null)
                return new Result { Message = "Setup could not be started." };

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(Timeout);

            try
            {
                await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // The script is still running elevated and this cannot stop it. Say so
                // rather than reporting a failure that might yet succeed.
                return new Result
                {
                    Message = "Setup is taking longer than 15 minutes and is still running in its own " +
                              "window. Leave it to finish, then set the resolver address here."
                };
            }

            var reported = ReadResult(resultPath);
            if (reported != null)
                return reported;

            // No result file. The usual reason is the UAC prompt being declined, which
            // exits before the script runs at all.
            return new Result
            {
                Message = process.ExitCode == 0
                    ? "Setup finished but reported nothing back, so the resolver address is unknown. " +
                      "Check whether AdGuard Home is running, then set the address here."
                    : "Setup did not complete — it was cancelled, or Administrator consent was declined."
            };
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // 1223 = ERROR_CANCELLED, the UAC prompt being dismissed. Anything else here
            // is PowerShell itself failing to launch, which reads the same to the user.
            return new Result
            {
                Message = "Setup needs Administrator, and consent was declined. " +
                          "DNS filtering was not changed."
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new Result { Message = $"Setup could not be started — {ex.Message}" };
        }
        finally
        {
            TryDelete(resultPath);
        }
    }

    /// <summary>
    /// Parses the script's result document. Split from the run so it is testable without
    /// installing a resolver, the same split the status and query-log parses use.
    /// </summary>
    internal static Result? ParseResult(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return null;

            var ok = root.TryGetProperty("ok", out var okElement)
                     && okElement.ValueKind == JsonValueKind.True;

            return new Result
            {
                Ok = ok,
                Url = DnsFilterService.NormalizeBaseUrl(Text(root, "url")),
                Username = Text(root, "username"),
                Password = Text(root, "password"),
                Message = Text(root, "message")
            };
        }
        catch (JsonException)
        {
            return null;
        }

        static string Text(JsonElement parent, string name)
            => parent.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString() ?? ""
                : "";
    }

    private static Result? ReadResult(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            return ParseResult(File.ReadAllText(path));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Nothing useful to do. The file is in the app's own data directory and
            // will be overwritten by name on the next run.
        }
    }
}
