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

    /// <summary>One aggregated notification per batch of Critical threats.</summary>
    public void NotifyCritical(IReadOnlyList<ThreatEvent> threats)
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

        var title = fresh.Count == 1
            ? $"Critical threat: {fresh[0].TypeText}"
            : $"{fresh.Count} critical threats detected";
        var body = string.Join("\n", fresh.Take(4).Select(t =>
            string.IsNullOrEmpty(t.SourceIp) ? t.Title : $"{t.Title} — {t.SourceIp}"));
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
