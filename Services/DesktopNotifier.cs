using System.Diagnostics;
using System.IO;
using System.Text;
using Microsoft.Win32;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Sends OS desktop notifications for Critical threats so the user is warned even
/// when the window is minimized. Raises native Windows toasts through the Windows
/// PowerShell WinRT projection so the app keeps its plain net8.0-windows target
/// (no Windows-SDK TFM or toast NuGet package); unsupported systems report
/// unavailable via StatusText.
/// </summary>
public sealed class DesktopNotifier
{
    /// <summary>Same source+type is not re-announced within this window.</summary>
    private static readonly TimeSpan RepeatAfter = TimeSpan.FromMinutes(5);

    /// <summary>AppUserModelID the toasts are attributed to (registered per-user at startup).</summary>
    private const string AppId = "NetworkSentinel";

    private readonly object _gate = new();
    private readonly Dictionary<string, DateTime> _lastSent = new(StringComparer.OrdinalIgnoreCase);
    private readonly string? _powerShellPath;

    public DesktopNotifier()
    {
        // Toast notifications need Windows 10+. Windows PowerShell 5.1 always lives
        // at this System32 path there, and its WinRT projection can raise toasts on
        // behalf of an unpackaged desktop app.
        var ps = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        _powerShellPath = OperatingSystem.IsWindowsVersionAtLeast(10) && File.Exists(ps) ? ps : null;
        if (_powerShellPath is not null)
            RegisterAppId();
    }

    public bool IsAvailable => _powerShellPath is not null;

    public string StatusText => _powerShellPath is not null
        ? "Desktop notifications ready (Windows toast)."
        : OperatingSystem.IsWindowsVersionAtLeast(10)
            ? "Windows PowerShell not found — desktop notifications unavailable."
            : "Desktop notifications need Windows 10 or later.";

    /// <summary>
    /// One aggregated notification per batch of Critical threats.
    ///
    /// <paramref name="statusFor"/> answers "is this address being blocked?" for each
    /// threat — wire it to <see cref="PreventionService.DescribeEnforcement"/>. A warning
    /// that says an address attacked you and stops there sends the reader to the console
    /// to find out whether anything was done about it; the toast is the one place that
    /// question is cheap to answer. It returns null for threats with no blockable
    /// address, and those lines stay as they were.
    /// </summary>
    public void NotifyCritical(IReadOnlyList<ThreatEvent> threats,
                               Func<ThreatEvent, EnforcementStatus?>? statusFor = null)
    {
        if (_powerShellPath is null || threats.Count == 0)
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

        try
        {
            var psi = new ProcessStartInfo(_powerShellPath)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-NonInteractive");
            // -EncodedCommand sidesteps every quoting/escaping pitfall in the threat text.
            psi.ArgumentList.Add("-EncodedCommand");
            psi.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(BuildToastScript(title, body))));
            using var p = Process.Start(psi);
            p?.WaitForExit(10000);
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
    /// The blocked/not-blocked verdict belongs in the title: on a toast that is often the
    /// only line the user reads before deciding whether to go to the machine.
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

    /// <summary>
    /// Register the AppUserModelID under HKCU so toasts show "Network Sentinel" and
    /// our icon instead of the raising PowerShell process. Same registration the
    /// packaged-app toast libraries perform; per-user, idempotent, best-effort.
    /// </summary>
    private static void RegisterAppId()
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey($@"Software\Classes\AppUserModelId\{AppId}");
            key?.SetValue("DisplayName", "Network Sentinel");
            var icon = Path.Combine(AppContext.BaseDirectory, "Assets", "icon.png");
            if (File.Exists(icon))
                key?.SetValue("IconUri", icon);
        }
        catch
        {
            // Toasts still work (attributed to PowerShell) if this fails.
        }
    }

    private static string BuildToastScript(string title, string body)
    {
        static string X(string s) => s
            .Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")
            .Replace("\"", "&quot;").Replace("'", "&apos;");

        var toastXml =
            "<toast duration=\"long\"><visual><binding template=\"ToastGeneric\">" +
            $"<text>{X(title)}</text><text>{X(body)}</text>" +
            "</binding></visual><audio src=\"ms-winsoundevent:Notification.Default\"/></toast>";

        return
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null\n" +
            "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null\n" +
            "$doc = New-Object Windows.Data.Xml.Dom.XmlDocument\n" +
            $"$doc.LoadXml('{toastXml.Replace("'", "''")}')\n" +
            $"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{AppId}').Show((New-Object Windows.UI.Notifications.ToastNotification($doc)))\n";
    }
}
