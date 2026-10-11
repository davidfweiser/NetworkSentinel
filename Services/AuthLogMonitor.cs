using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Watches system authentication logs for failed remote logons (SSH, PAM) and
/// turns bursts into FailedLogonBurst threat events. This closes the gap the
/// connection-based heuristics cannot see: a brute-force that reuses one TCP
/// session, or paced attempts below the connection-rate thresholds.
///
/// Source preference: `journalctl --follow` (sshd / sshd-session / sudo / su /
/// login identifiers); if journald is unavailable or unreadable, falls back to
/// tailing /var/log/auth.log. Runs entirely without elevation — on systems
/// where neither source is readable it degrades to "unavailable" and says so
/// in <see cref="Status"/>.
/// </summary>
public sealed class AuthLogMonitor : IDisposable
{
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(2);
    private const int HighThreshold = 4;
    private const int CriticalThreshold = 10;

    // sshd puts the username — chosen by whoever is connecting, and allowed to contain
    // spaces — *before* the address it logs. An unanchored pattern takes the leftmost
    // "from <ip>", so a username such as "x from 8.8.8.8 port 22" named any address the
    // attacker liked as the culprit (the fail2ban/DenyHosts log-injection class). Every
    // pattern is therefore anchored on the tail sshd itself writes — "from <ip> port <n>",
    // then its fixed suffixes, then end of line — and lets the username run greedily up
    // to it, so the address is always the last one on the line.
    private const string Tail = @"(?: ssh2)?(?: \[preauth\])?\s*$";

    // "Failed password for invalid user admin from 203.0.113.7 port 51022 ssh2"
    private static readonly Regex FailedPassword = new(
        @"Failed (?:password|publickey|keyboard-interactive(?:/pam)?|none) for (?<invalid>invalid user )?(?<user>.*) from (?<ip>\S+) port \d+" + Tail,
        RegexOptions.Compiled);

    // "Invalid user oracle from 203.0.113.7 port 40122"
    private static readonly Regex InvalidUser = new(
        @"Invalid user (?<user>.*) from (?<ip>\S+) port \d+" + Tail,
        RegexOptions.Compiled);

    // "Connection closed by invalid user a 203.0.113.7 port 50110 [preauth]"
    private static readonly Regex PreauthAbandon = new(
        @"Connection (?:closed|reset) by (?:invalid |authenticating )user (?<user>.*) (?<ip>\S+) port \d+" + Tail,
        RegexOptions.Compiled);

    // PAM: "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.7  user=root"
    // Here the username comes *after* the address, so the fields before rhost= are spelled
    // out: a greedy ".*rhost=" would take an "rhost=" smuggled into the trailing user=.
    private static readonly Regex PamFailure = new(
        @"authentication failure; logname=\S* uid=\d+ euid=\d+ tty=\S* ruser=\S* rhost=(?<ip>\S+)(?:\s+user=(?<user>.*))?$",
        RegexOptions.Compiled);

    // "error: maximum authentication attempts exceeded for root from 203.0.113.7 port 33990 ssh2 [preauth]"
    private static readonly Regex MaxAttempts = new(
        @"maximum authentication attempts exceeded for (?:invalid user )?(?<user>.*) from (?<ip>\S+) port \d+" + Tail,
        RegexOptions.Compiled);

    private readonly object _gate = new();
    private readonly Dictionary<string, IpFailures> _failures = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _lastEmit = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<ThreatEvent> _pending = new();

    private Process? _journal;
    private CancellationTokenSource? _cts;
    private Task? _tailTask;
    private volatile string _status = "Auth log monitoring not started";

    /// <summary>Human-readable state of the log source ("journald", "auth.log", or why neither works).</summary>
    public string Status => _status;

    public void Start()
    {
        lock (_gate)
        {
            if (_cts != null) return;
            _cts = new CancellationTokenSource();
        }

        if (!TryStartJournal())
        {
            var ct = _cts!.Token;
            _tailTask = Task.Run(() => TailAuthLogAsync(ct));
        }
    }

    public void Stop()
    {
        CancellationTokenSource? cts;
        lock (_gate)
        {
            cts = _cts;
            _cts = null;
        }
        if (cts == null) return;

        cts.Cancel();
        try { _journal?.Kill(entireProcessTree: true); } catch { /* already gone */ }
        try { _tailTask?.Wait(1000); } catch { /* ignore */ }
        _journal?.Dispose();
        _journal = null;
        _tailTask = null;
        cts.Dispose();
        _status = "Auth log monitoring stopped";
    }

    /// <summary>Returns threats detected since the last drain (called from the monitor poll loop).</summary>
    public IReadOnlyList<ThreatEvent> DrainPending()
    {
        lock (_gate)
        {
            if (_pending.Count == 0) return Array.Empty<ThreatEvent>();
            var list = _pending.ToList();
            _pending.Clear();
            return list;
        }
    }

    private bool TryStartJournal()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "journalctl",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            // The identifier (-t) is whatever the sender says it is — `logger -t sshd` from
            // any local account matches it — so the lines must also come from root (_UID is
            // stamped by journald from the socket credentials and cannot be forged). sshd
            // logs as root: its unprivileged pre-auth child hands messages to the root monitor.
            foreach (var arg in new[]
            {
                "--follow", "--lines=0", "--output=cat", "--quiet",
                "-t", "sshd", "-t", "sshd-session", "-t", "sudo", "-t", "su", "-t", "login",
                "_UID=0"
            })
            {
                psi.ArgumentList.Add(arg);
            }

            var proc = Process.Start(psi);
            if (proc == null) return false;

            _journal = proc;
            proc.OutputDataReceived += (_, e) =>
            {
                if (e.Data != null) ProcessLine(e.Data, DateTime.Now);
            };
            proc.BeginOutputReadLine();
            _status = "Watching journald (sshd/sudo/login)";
            return true;
        }
        catch
        {
            _journal?.Dispose();
            _journal = null;
            return false;
        }
    }

    private async Task TailAuthLogAsync(CancellationToken ct)
    {
        const string path = "/var/log/auth.log";
        try
        {
            if (!File.Exists(path))
            {
                _status = "Auth log unavailable (no journalctl, no /var/log/auth.log) — logon monitoring off";
                return;
            }

            await using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            stream.Seek(0, SeekOrigin.End);
            using var reader = new StreamReader(stream);
            _status = "Watching /var/log/auth.log";

            while (!ct.IsCancellationRequested)
            {
                var line = await reader.ReadLineAsync(ct);
                if (line == null)
                {
                    // At EOF; if the file was rotated under us, reopen from the top.
                    if (stream.Position > new FileInfo(path).Length)
                        stream.Seek(0, SeekOrigin.Begin);
                    await Task.Delay(1000, ct);
                    continue;
                }
                ProcessLine(line, DateTime.Now);
            }
        }
        catch (OperationCanceledException)
        {
            // normal shutdown
        }
        catch (UnauthorizedAccessException)
        {
            _status = "Auth log not readable by this user — logon monitoring off (add user to the 'adm' group)";
        }
        catch (Exception ex)
        {
            _status = $"Auth log monitoring failed: {ex.Message}";
        }
    }

    /// <summary>Parses one log line; internal for tests / manual replay.</summary>
    internal void ProcessLine(string line, DateTime now)
    {
        string? ip = null, user = null;
        bool immediate = false;

        var m = MaxAttempts.Match(line);
        if (m.Success)
        {
            ip = m.Groups["ip"].Value;
            user = m.Groups["user"].Value;
            immediate = true;
        }
        else if ((m = FailedPassword.Match(line)).Success ||
                 (m = PreauthAbandon.Match(line)).Success ||
                 (m = InvalidUser.Match(line)).Success)
        {
            ip = m.Groups["ip"].Value;
            user = m.Groups["user"].Value;
        }
        else if ((m = PamFailure.Match(line)).Success)
        {
            ip = m.Groups["ip"].Value;
            user = m.Groups["user"].Success ? m.Groups["user"].Value : "";
        }

        if (string.IsNullOrWhiteSpace(ip) || !IPAddress.TryParse(ip, out _)) return;
        if (ip is "127.0.0.1" or "::1") return;

        lock (_gate)
        {
            if (!_failures.TryGetValue(ip, out var f))
            {
                f = new IpFailures();
                _failures[ip] = f;
            }

            f.Attempts.Enqueue(now);
            if (!string.IsNullOrWhiteSpace(user) && user != "from") f.Users.Add(user);
            while (f.Attempts.Count > 0 && now - f.Attempts.Peek() > Window)
                f.Attempts.Dequeue();

            var count = f.Attempts.Count;
            ThreatLevel? level = null;
            if (immediate || count >= CriticalThreshold) level = ThreatLevel.Critical;
            else if (count >= HighThreshold) level = ThreatLevel.High;
            if (level == null) return;

            // Per-IP cooldown, but let an escalation to Critical break through.
            string emitKey = $"{ip}|{level}";
            if (_lastEmit.TryGetValue(emitKey, out var last) && now - last < EmitCooldown)
                return;
            _lastEmit[emitKey] = now;

            var users = f.Users.Count > 0
                ? $" Accounts tried: {string.Join(", ", f.Users.Take(8))}{(f.Users.Count > 8 ? ", …" : "")}."
                : "";
            _pending.Add(new ThreatEvent
            {
                Timestamp = now,
                Type = ThreatType.FailedLogonBurst,
                Level = level.Value,
                SourceIp = ip,
                Title = immediate
                    ? "SSH max auth attempts exceeded"
                    : $"{count} failed logons in {Window.TotalMinutes:0} min",
                Detail = $"{ip} produced {count} failed authentication attempts within {Window.TotalMinutes:0} minutes.{users}",
                Origin = "Origin resolving…",
                Method = "System auth log (sshd / PAM)"
            });

            // Keep the per-IP tables from growing without bound.
            if (_failures.Count > 2000)
            {
                foreach (var stale in _failures
                             .Where(kv => kv.Value.Attempts.Count == 0 ||
                                          now - kv.Value.Attempts.Last() > Window)
                             .Select(kv => kv.Key).ToList())
                {
                    _failures.Remove(stale);
                }
            }
            if (_lastEmit.Count > 4000)
            {
                foreach (var stale in _lastEmit.Where(kv => now - kv.Value > EmitCooldown)
                             .Select(kv => kv.Key).ToList())
                {
                    _lastEmit.Remove(stale);
                }
            }
        }
    }

    public void Dispose() => Stop();

    private sealed class IpFailures
    {
        public Queue<DateTime> Attempts { get; } = new();
        public HashSet<string> Users { get; } = new(StringComparer.Ordinal);
    }
}
