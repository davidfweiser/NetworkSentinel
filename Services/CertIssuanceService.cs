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
        => new() { Success = false, Message = message, Output = output.ToString() };

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
