using System.Diagnostics;
using System.IO;
using System.Text;

namespace NetworkSentinel.Services;

/// <summary>Outcome of one issuance run, including the paths the console should use.</summary>
public sealed class CertIssuanceResult
{
    public bool Success { get; init; }

    /// <summary>Short line for the Settings status area — already user-facing.</summary>
    public string Message { get; init; } = "";

    /// <summary>Full script output, kept for the detail pane when something fails.</summary>
    public string Output { get; init; } = "";

    public string CertPath { get; init; } = "";
    public string KeyPath { get; init; } = "";
}

/// <summary>
/// Runs scripts/issue-duckdns-cert.sh on behalf of the desktop Settings view.
/// The script is the single implementation of issuance — duplicating the ACME
/// flow in C# would mean two things to keep correct at renewal time.
/// </summary>
public sealed class CertIssuanceService
{
    /// <summary>
    /// Issuance waits on DuckDNS TXT propagation (--dnssleep 120) plus Let's Encrypt,
    /// and installing acme.sh on first run adds to that. Long, but not unbounded —
    /// a hung run should surface as a failure rather than a permanently stuck button.
    /// </summary>
    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Where the helper can be: beside the binary after an install, or in the repo
    /// when running from a source checkout (bin/Debug/net8.0 → three levels up).
    /// </summary>
    public static string? FindScript()
    {
        var baseDir = AppContext.BaseDirectory;
        var candidates = new List<string>
        {
            Path.Combine(baseDir, "issue-duckdns-cert.sh"),
            Path.Combine(baseDir, "scripts", "issue-duckdns-cert.sh"),
        };

        // Walk up from the binary so a source-tree run finds ./scripts without
        // hard-coding how deep bin/<config>/<tfm> happens to be.
        var dir = new DirectoryInfo(baseDir);
        for (var i = 0; i < 5 && dir != null; i++, dir = dir.Parent)
            candidates.Add(Path.Combine(dir.FullName, "scripts", "issue-duckdns-cert.sh"));

        return candidates.FirstOrDefault(File.Exists);
    }

    /// <summary>
    /// Issue a certificate for <paramref name="domainLabel"/> without a terminal.
    /// <paramref name="acmeEmail"/> is only consulted the first time, when acme.sh
    /// still has to be installed and registered.
    /// </summary>
    public static async Task<CertIssuanceResult> IssueAsync(
        string domainLabel, string token, string acmeEmail, CancellationToken ct = default)
    {
        var script = FindScript();
        if (script == null)
        {
            return new CertIssuanceResult
            {
                Message = "Could not find issue-duckdns-cert.sh — run it from a terminal instead.",
            };
        }

        var psi = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add(script);
        psi.ArgumentList.Add(domainLabel);

        // No TTY here, so the script must not prompt. The token goes through the
        // environment rather than the argument list: arguments are world-readable
        // in /proc while a child's environment is not.
        psi.Environment["NS_ASSUME_YES"] = "1";
        psi.Environment["DuckDNS_Token"] = token;
        if (!string.IsNullOrWhiteSpace(acmeEmail))
            psi.Environment["NS_ACME_EMAIL"] = acmeEmail.Trim();

        var output = new StringBuilder();

        try
        {
            using var proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
            proc.OutputDataReceived += (_, e) => { if (e.Data != null) lock (output) output.AppendLine(e.Data); };
            proc.ErrorDataReceived += (_, e) => { if (e.Data != null) lock (output) output.AppendLine(e.Data); };

            proc.Start();
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(Timeout);

            try
            {
                await proc.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException)
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* already gone */ }
                return Failure(output, ct.IsCancellationRequested
                    ? "Certificate issuance cancelled."
                    : $"Certificate issuance timed out after {Timeout.TotalMinutes:0} minutes.");
            }

            var text = output.ToString();
            // Keep the whole run somewhere readable: the status line only has room for a
            // summary, and a failed ACME run is exactly when the detail is wanted.
            SaveLog(text);

            if (proc.ExitCode != 0)
                return Failure(output, FirstError(text) ?? $"Certificate issuance failed (exit {proc.ExitCode}).");

            var cert = ValueOf(text, "NS_CERT_FILE=");
            var key = ValueOf(text, "NS_KEY_FILE=");
            if (cert.Length == 0 || !File.Exists(cert))
                return Failure(output, "Issuance reported success but no certificate file was produced.");

            return new CertIssuanceResult
            {
                Success = true,
                Message = $"Certificate issued for {domainLabel}.duckdns.org.",
                Output = text,
                CertPath = cert,
                KeyPath = key,
            };
        }
        catch (Exception ex)
        {
            return Failure(output, $"Could not run the certificate script: {ex.Message}");
        }
    }

    private static CertIssuanceResult Failure(StringBuilder output, string message)
    {
        var text = output.ToString();
        return new CertIssuanceResult
        {
            Success = false,
            Message = Explain(message, text),
            Output = text,
        };
    }

    /// <summary>
    /// The script's own failure line ends with "see the acme.sh output above", which is
    /// true in a terminal and meaningless behind a button. Replace that pointer with the
    /// output it was pointing at, and name the cause outright when acme.sh's wording
    /// identifies one — a wrong DuckDNS token is by far the most common.
    /// </summary>
    private static string Explain(string message, string text)
    {
        var cause = Diagnose(text);
        var trimmed = message.Replace(" (see the acme.sh output above)", "", StringComparison.OrdinalIgnoreCase);

        var parts = new List<string> { trimmed };
        if (cause.Length > 0)
            parts.Add(cause);

        var tail = Tail(text);
        if (tail.Length > 0)
            parts.Add("acme.sh said: " + tail);

        if (text.Length > 0)
            parts.Add($"full output in {LogPath}");

        return string.Join(" — ", parts);
    }

    /// <summary>Turn the common acme.sh failures into something actionable.</summary>
    private static string Diagnose(string text)
    {
        if (text.Contains("invalid domain", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("Error add txt for domain", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("invalid response from duckdns", StringComparison.OrdinalIgnoreCase))
            return "DuckDNS refused the DNS record, which usually means the token or subdomain is wrong";

        if (text.Contains("Timeout", StringComparison.OrdinalIgnoreCase) &&
            text.Contains("dns", StringComparison.OrdinalIgnoreCase))
            return "the DNS record did not propagate in time; retrying often succeeds";

        if (text.Contains("rateLimited", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("too many certificates", StringComparison.OrdinalIgnoreCase))
            return "Let's Encrypt is rate-limiting this name; wait before retrying";

        if (text.Contains("Please add '--debug'", StringComparison.OrdinalIgnoreCase) &&
            text.Contains("urn:ietf:params:acme:error:unauthorized", StringComparison.OrdinalIgnoreCase))
            return "Let's Encrypt could not verify the DNS challenge";

        return "";
    }

    /// <summary>Last few meaningful output lines, for a status line rather than a log pane.</summary>
    private static string Tail(string text, int lines = 3)
    {
        var kept = text
            .Split('\n')
            .Select(l => l.Trim())
            .Where(l => l.Length > 0 && !l.StartsWith("NS_CERT_FILE=", StringComparison.Ordinal)
                                     && !l.StartsWith("NS_KEY_FILE=", StringComparison.Ordinal))
            .ToList();

        // The script's own "Error:" line is already the message; do not echo it twice.
        while (kept.Count > 0 && kept[^1].StartsWith("Error:", StringComparison.OrdinalIgnoreCase))
            kept.RemoveAt(kept.Count - 1);

        return kept.Count == 0 ? "" : string.Join(" | ", kept.TakeLast(lines));
    }

    private static string ValueOf(string text, string prefix)
    {
        foreach (var line in text.Split('\n'))
        {
            var t = line.Trim();
            if (t.StartsWith(prefix, StringComparison.Ordinal))
                return t[prefix.Length..].Trim();
        }
        return "";
    }

    /// <summary>Path of the issuance transcript, named in the failure message so it can be found.</summary>
    public static string LogPath => Path.Combine(AppPaths.DataDirectory, "logs", "cert-issue.log");

    private static void SaveLog(string text)
    {
        try
        {
            var path = LogPath;
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, text);
        }
        catch
        {
            // A missing transcript must not turn a working issuance into a failure.
        }
    }

    /// <summary>The script's own "Error: …" line says far more than an exit code.</summary>
    private static string? FirstError(string text)
    {
        foreach (var line in text.Split('\n'))
        {
            var t = line.Trim();
            if (t.StartsWith("Error:", StringComparison.OrdinalIgnoreCase))
                return t;
        }
        return null;
    }
}
