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

    /// <summary>One aggregated notification per batch of Critical threats.</summary>
    public void NotifyCritical(IReadOnlyList<ThreatEvent> threats)
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

        var title = fresh.Count == 1
            ? $"Critical threat: {fresh[0].TypeText}"
            : $"{fresh.Count} critical threats detected";
        var body = string.Join("\n", fresh.Take(4).Select(t =>
            string.IsNullOrEmpty(t.SourceIp) ? t.Title : $"{t.Title} — {t.SourceIp}"));
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
