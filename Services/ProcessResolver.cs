using System.Collections.Concurrent;
using System.Diagnostics;

namespace NetworkSentinel.Services;

public sealed class ProcessResolver
{
    private readonly ConcurrentDictionary<int, (string Name, DateTime CachedAt)> _cache = new();
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(20);

    public string Resolve(int pid)
    {
        if (pid <= 0) return "Kernel / unknown";

        if (_cache.TryGetValue(pid, out var entry) && DateTime.UtcNow - entry.CachedAt < CacheTtl)
            return entry.Name;

        string name;
        try
        {
            // Prefer /proc/pid/comm — works without full Process access
            var commPath = $"/proc/{pid}/comm";
            if (File.Exists(commPath))
            {
                name = File.ReadAllText(commPath).Trim();
                if (string.IsNullOrWhiteSpace(name))
                    name = $"PID {pid}";
            }
            else
            {
                using var process = Process.GetProcessById(pid);
                name = string.IsNullOrWhiteSpace(process.ProcessName) ? $"PID {pid}" : process.ProcessName;
            }
        }
        catch
        {
            name = pid == 0 ? "Kernel" : $"PID {pid}";
        }

        _cache[pid] = (name, DateTime.UtcNow);
        return name;
    }
}
