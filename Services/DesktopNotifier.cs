using System.Diagnostics;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Sends OS desktop notifications for Critical threats so the user is warned even
/// when the window is minimized or sitting in the tray. Linux only for now
/// (notify-send / libnotify); other platforms report unavailable via StatusText.
/// </summary>
public sealed class DesktopNotifier
{
    /// <summary>Same source+type is not re-announced within this window.</summary>
    private static readonly TimeSpan RepeatAfter = TimeSpan.FromMinutes(5);

    private readonly object _gate = new();
    private readonly Dictionary<string, DateTime> _lastSent = new(StringComparer.OrdinalIgnoreCase);
    private readonly string? _channel;

    public DesktopNotifier()
    {
        // notify-send (libnotify) when present; otherwise gdbus (GLib, present on
        // any GNOME-based desktop) speaking org.freedesktop.Notifications directly.
        _channel = !OperatingSystem.IsLinux() ? null
            : ToolExists("notify-send") ? "notify-send"
            : ToolExists("gdbus") ? "gdbus"
            : null;
    }

    public bool IsAvailable => _channel is not null;

    public string StatusText => _channel is not null
        ? $"Desktop notifications ready ({_channel})."
        : OperatingSystem.IsLinux()
            ? "No notification tool found — install libnotify (e.g. sudo apt install libnotify-bin)."
            : "Desktop notifications are only supported on Linux for now.";

    /// <summary>
    /// One aggregated notification per batch of Critical threats.
    ///
    /// <paramref name="statusFor"/> answers "is this address being blocked?" for each
    /// threat — wire it to <see cref="PreventionService.DescribeEnforcement"/>. A warning
    /// that says an address attacked you and stops there sends the reader to the console
    /// to find out whether anything was done about it; the notification is the one place
    /// that question is cheap to answer. It returns null for threats with no blockable
    /// address, and those lines stay as they were.
    /// </summary>
    public void NotifyCritical(IReadOnlyList<ThreatEvent> threats,
                               Func<ThreatEvent, EnforcementStatus?>? statusFor = null)
    {
        if (_channel is null || threats.Count == 0)
            return;

        var fresh = new List<ThreatEvent>();
        lock (_gate)
        {
            var now = DateTime.UtcNow;
            foreach (var threat in threats)
            {
                var key = $"{threat.SourceIp}|{threat.Type}";
                if (_lastSent.TryGetValue(key, out var last) && now - last < RepeatAfter)
                    continue;
                _lastSent[key] = now;
                fresh.Add(threat);
            }

            if (_lastSent.Count > 512)
            {
                foreach (var stale in _lastSent.Where(kv => now - kv.Value > RepeatAfter)
                             .Select(kv => kv.Key).ToList())
                    _lastSent.Remove(stale);
            }
        }

        if (fresh.Count == 0)
            return;

        // Resolved once: the same verdict has to drive the title and the body lines.
        var statuses = fresh.Select(t => Resolve(statusFor, t)).ToList();
        var title = BuildTitle(fresh, statuses);
        var body = string.Join("\n", fresh.Take(4).Select((t, i) =>
        {
            var line = string.IsNullOrEmpty(t.SourceIp) ? t.Title : $"{t.Title} — {t.SourceIp}";
            return statuses[i] is { } status ? $"{line}\n  {status.Text}" : line;
        }));
        if (fresh.Count > 4)
            body += $"\n…and {fresh.Count - 4} more";
        // Notification daemons render the body as Pango markup.
        body = body.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");

        try
        {
            var psi = new ProcessStartInfo(_channel)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            if (_channel == "notify-send")
            {
                psi.ArgumentList.Add("--app-name=Network Sentinel");
                psi.ArgumentList.Add("--urgency=critical");
                psi.ArgumentList.Add("--icon=networksentinel");
                psi.ArgumentList.Add(title);
                psi.ArgumentList.Add(body);
            }
            else
            {
                psi.ArgumentList.Add("call");
                psi.ArgumentList.Add("--session");
                psi.ArgumentList.Add("--dest"); psi.ArgumentList.Add("org.freedesktop.Notifications");
                psi.ArgumentList.Add("--object-path"); psi.ArgumentList.Add("/org/freedesktop/Notifications");
                psi.ArgumentList.Add("--method"); psi.ArgumentList.Add("org.freedesktop.Notifications.Notify");
                psi.ArgumentList.Add("Network Sentinel");
                psi.ArgumentList.Add("0");
                psi.ArgumentList.Add("networksentinel");
                psi.ArgumentList.Add(title);
                psi.ArgumentList.Add(body);
                psi.ArgumentList.Add("[]");
                psi.ArgumentList.Add("{'urgency': <byte 2>}");
                psi.ArgumentList.Add("10000");
            }
            using var p = Process.Start(psi);
            p?.WaitForExit(3000);
        }
        catch
        {
            // Notifications are best-effort; never let them break monitoring.
        }
    }

    /// <summary>Never let a status lookup cost the user the warning itself.</summary>
    private static EnforcementStatus? Resolve(Func<ThreatEvent, EnforcementStatus?>? statusFor, ThreatEvent threat)
    {
        try
        {
            return statusFor?.Invoke(threat);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// The blocked/not-blocked verdict belongs in the title: on a phone-style popup that
    /// is often the only line the user reads before deciding whether to go to the machine.
    /// </summary>
    private static string BuildTitle(IReadOnlyList<ThreatEvent> fresh, IReadOnlyList<EnforcementStatus?> statuses)
    {
        if (fresh.Count == 1)
        {
            return statuses[0] switch
            {
                null => $"Critical threat: {fresh[0].TypeText}",
                { IsBlocked: true } => $"Blocked · critical threat: {fresh[0].TypeText}",
                _ => $"NOT blocked · critical threat: {fresh[0].TypeText}"
            };
        }

        var known = statuses.Count(s => s is not null);
        if (known == 0)
            return $"{fresh.Count} critical threats detected";

        var blocked = statuses.Count(s => s?.IsBlocked == true);
        return blocked == known
            ? $"{fresh.Count} critical threats — all blocked"
            : $"{fresh.Count} critical threats — {blocked} of {known} blocked";
    }

    private static bool ToolExists(string name)
    {
        try
        {
            var psi = new ProcessStartInfo("which", name)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(2000);
            return p is { ExitCode: 0 };
        }
        catch
        {
            return false;
        }
    }
}
