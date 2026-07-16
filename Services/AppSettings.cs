using System.IO;
using System.Text.Json;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

public sealed class AppSettings
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public bool AutoBlockEnabled { get; set; }
    public string AutoBlockMinLevel { get; set; } = nameof(ThreatLevel.High);
    public bool AutoBlockInbound { get; set; } = true;
    public bool AutoBlockOutbound { get; set; } = true;

    public ThreatLevel GetMinLevel()
    {
        return Enum.TryParse<ThreatLevel>(AutoBlockMinLevel, true, out var level)
            ? level
            : ThreatLevel.High;
    }

    public void SetMinLevel(ThreatLevel level) => AutoBlockMinLevel = level.ToString();

    private static string SettingsPath
    {
        get
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "NetworkSentinel");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "settings.json");
        }
    }

    public static AppSettings Load()
    {
        try
        {
            var path = SettingsPath;
            if (!File.Exists(path))
                return new AppSettings();

            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<AppSettings>(json, JsonOptions) ?? new AppSettings();
        }
        catch
        {
            return new AppSettings();
        }
    }

    public void Save()
    {
        try
        {
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(this, JsonOptions));
        }
        catch
        {
            // best-effort persistence
        }
    }
}
