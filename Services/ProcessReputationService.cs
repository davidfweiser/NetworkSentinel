using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Reputation checks on the local processes behind network connections:
///
///  * shells / script interpreters holding an outbound connection to a public
///    address — the reverse-shell signature;
///  * binaries running from throwaway locations (/tmp, /dev/shm, ~/Downloads)
///    with network activity;
///  * fileless or deleted executables (memfd, unlinked binaries) — the payload
///    is only in memory, so nothing is left on disk to inspect;
///  * binaries no installed package owns, running from outside the distro's
///    own directories — the Linux stand-in for "unsigned": provenance unknown.
///
/// Path resolution reads /proc/PID/exe directly — no shelling out per poll.
/// The package-ownership query (dpkg / rpm / pacman / apk) runs once per unique
/// executable path on a background task and is cached, so the poll loop never
/// blocks on it.
/// </summary>
public sealed class ProcessReputationService
{
    [DllImport("libc", SetLastError = true)]
    private static extern int readlink(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        byte[] buf,
        int bufsiz);

    private static readonly HashSet<string> ShellNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "bash", "zsh", "sh", "dash", "ksh", "csh", "tcsh", "fish", "busybox",
        "python", "python3", "perl", "ruby", "php", "lua",
        "nc", "nc.openbsd", "nc.traditional", "ncat", "netcat", "socat", "telnet"
    };

    private static readonly string[] SuspiciousPathPrefixes =
    {
        "/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"
    };

    /// <summary>
    /// AppImages mount themselves under /tmp/.mount_* and self-extracting
    /// installers stage there too — running from /tmp is normal for both, so
    /// they would otherwise alert on every launch.
    /// </summary>
    private static readonly string[] SuspiciousPathExceptions =
    {
        "/tmp/.mount_", "/tmp/appimage", "/tmp/.org.chromium", "/tmp/snap."
    };

    /// <summary>
    /// Paths owned by the distribution, a sandbox runtime, or the container
    /// image — a package query there tells us nothing we don't already know.
    /// </summary>
    private static readonly string[] TrustedPathPrefixes =
    {
        "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib32/", "/usr/lib64/",
        "/usr/libexec/", "/usr/share/", "/bin/", "/sbin/", "/lib/", "/lib64/",
        "/snap/", "/var/lib/flatpak/", "/app/", "/nix/store/"
    };

    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(30);

    private readonly object _gate = new();
    private readonly List<ThreatEvent> _pending = new();
    private readonly Dictionary<string, DateTime> _lastEmit = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<int, string> _pidPaths = new();
    private readonly ConcurrentDictionary<string, PackageVerdict> _packages = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, byte> _packageQueued = new(StringComparer.Ordinal);
    private readonly int _ownPid = Environment.ProcessId;
    private readonly string _downloadsPrefix;
    private readonly Lazy<PackageQuery?> _packageQuery = new(FindPackageQuery);

    private enum PackageVerdict { Pending, Owned, Unowned }

    /// <summary>A distro package manager and the argv that answers "who owns this file?".</summary>
    private sealed record PackageQuery(string Program, string[] Args);

    public ProcessReputationService()
    {
        _downloadsPrefix = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads") + "/";
    }

    /// <summary>
    /// Feed one poll's connection snapshot. Threats surface via <see cref="DrainPending"/>.
    /// Only outbound connections to public remotes are considered — inbound and
    /// LAN traffic is covered by the other heuristics.
    /// </summary>
    public void Observe(IReadOnlyList<NetworkConnection> snapshot, IReadOnlySet<int> listeningTcpPorts, DateTime now)
    {
        foreach (var c in snapshot)
        {
            if (c.ProcessId <= 0 || c.ProcessId == _ownPid) continue;
            if (c.State != TcpConnectionState.Established) continue;
            if (string.IsNullOrWhiteSpace(c.RemoteAddress)) continue;
            if (GeoIpService.IsNonPublic(c.RemoteAddress)) continue;
            if (GeoIpService.IsMulticastOrBroadcast(c.RemoteAddress)) continue;
            // Inbound sessions land on a listening port; those are someone else's doing.
            if (c.Protocol == "TCP" && listeningTcpPorts.Contains(c.LocalPort)) continue;

            var path = ResolvePath(c.ProcessId);
            var exeName = string.IsNullOrEmpty(path) ? c.ProcessName : Path.GetFileName(path);

            if (ShellNames.Contains(exeName))
            {
                Emit(now, $"shell|{exeName}|{c.RemoteAddress}", new ThreatEvent
                {
                    Timestamp = now,
                    Type = ThreatType.SuspiciousProcess,
                    Level = ThreatLevel.High,
                    SourceIp = c.RemoteAddress,
                    Title = "Shell process with outbound connection",
                    Detail = $"{exeName} (PID {c.ProcessId}) holds an established connection to {c.RemoteAddress}:{c.RemotePort}. " +
                             "A shell or script interpreter talking to a public address is the classic reverse-shell signature. " +
                             "Legitimate uses exist (ssh wrappers, package scripts) — verify what launched it.",
                    Origin = "Origin resolving…",
                    Method = $"Process reputation · {exeName} → {c.RemoteAddress}:{c.RemotePort}"
                });
            }

            if (string.IsNullOrEmpty(path)) continue;

            // Fileless / unlinked executables: /proc/PID/exe points at a memfd or
            // a binary that has been removed from disk. Package upgrades leave
            // running daemons in the deleted state too, so only unlinked binaries
            // from throwaway locations count.
            if (IsFileless(path, out var filelessWhat))
            {
                Emit(now, $"fileless|{path}|{c.ProcessId}", new ThreatEvent
                {
                    Timestamp = now,
                    Type = ThreatType.SuspiciousProcess,
                    Level = ThreatLevel.High,
                    SourceIp = c.RemoteAddress,
                    Title = "Fileless process with outbound connection",
                    Detail = $"{exeName} (PID {c.ProcessId}) {filelessWhat} and is talking to {c.RemoteAddress}:{c.RemotePort}. " +
                             "Running a payload that never stays on disk is a deliberate anti-forensics technique — " +
                             "almost nothing legitimate does it.",
                    Origin = "Origin resolving…",
                    Method = "Process reputation · deleted / in-memory executable"
                });
                continue; // nothing on disk left to path- or package-check
            }

            if (IsSuspiciousPath(path))
            {
                Emit(now, $"path|{path}", new ThreatEvent
                {
                    Timestamp = now,
                    Type = ThreatType.SuspiciousProcess,
                    Level = ThreatLevel.Medium,
                    SourceIp = c.RemoteAddress,
                    Title = "Network activity from a throwaway location",
                    Detail = $"{exeName} is running from {path} and talking to {c.RemoteAddress}:{c.RemotePort}. " +
                             "Malware often stages itself in temp or download folders before persisting.",
                    Origin = "Origin resolving…",
                    Method = "Process reputation · suspicious executable path"
                });
            }

            if (IsPackageCheckWorthwhile(path))
            {
                if (QueueOrGetPackage(path) == PackageVerdict.Unowned)
                {
                    Emit(now, $"pkg|{path}", new ThreatEvent
                    {
                        Timestamp = now,
                        Type = ThreatType.SuspiciousProcess,
                        Level = ThreatLevel.Medium,
                        SourceIp = c.RemoteAddress,
                        Title = "Unpackaged system binary with network activity",
                        Detail = $"{exeName} ({path}) sits in a system directory that no installed package owns, and is " +
                                 $"talking to {c.RemoteAddress}:{c.RemotePort}. Locally compiled software lives here too — " +
                                 "the point is that nothing on this machine can say where this file came from.",
                        Origin = "Origin resolving…",
                        Method = "Process reputation · package ownership"
                    });
                }
            }
        }
    }

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

    private void Emit(DateTime now, string key, ThreatEvent threat)
    {
        lock (_gate)
        {
            if (_lastEmit.TryGetValue(key, out var last) && now - last < EmitCooldown)
                return;
            _lastEmit[key] = now;
            _pending.Add(threat);

            if (_lastEmit.Count > 2000)
            {
                foreach (var stale in _lastEmit.Where(kv => now - kv.Value > EmitCooldown)
                             .Select(kv => kv.Key).ToList())
                {
                    _lastEmit.Remove(stale);
                }
            }
        }
    }

    /// <summary>
    /// Executable path from /proc/PID/exe. The kernel appends " (deleted)" when
    /// the binary has been unlinked and reports "/memfd:name (deleted)" for
    /// anonymous in-memory executables; both are kept verbatim so
    /// <see cref="IsFileless"/> can see them.
    /// </summary>
    private string ResolvePath(int pid)
    {
        if (_pidPaths.TryGetValue(pid, out var cached))
            return cached;

        string path = "";
        try
        {
            var buffer = new byte[4096];
            int len = readlink($"/proc/{pid}/exe", buffer, buffer.Length - 1);
            if (len > 0)
                path = Encoding.UTF8.GetString(buffer, 0, len);
        }
        catch
        {
            // /proc entry gone, or EACCES on another user's process
        }

        // PIDs recycle; a short-lived cache is fine and avoids a syscall per poll.
        if (_pidPaths.Count > 4000) _pidPaths.Clear();
        _pidPaths[pid] = path;
        return path;
    }

    private static bool IsFileless(string path, out string what)
    {
        if (path.StartsWith("/memfd:", StringComparison.Ordinal) ||
            path.StartsWith("memfd:", StringComparison.Ordinal))
        {
            what = "is running from an anonymous memory file (memfd) with no binary on disk";
            return true;
        }

        if (path.EndsWith(" (deleted)", StringComparison.Ordinal))
        {
            var real = path[..^" (deleted)".Length];
            // A package upgrade unlinks the old binary under running daemons, so
            // only deleted binaries staged in throwaway directories are alarming.
            if (SuspiciousPathPrefixes.Any(p => real.StartsWith(p, StringComparison.Ordinal)))
            {
                what = $"is running from {real}, which has since been deleted from disk";
                return true;
            }
        }

        what = "";
        return false;
    }

    private bool IsSuspiciousPath(string path)
    {
        if (SuspiciousPathExceptions.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
            return false;
        return SuspiciousPathPrefixes.Any(p => path.StartsWith(p, StringComparison.Ordinal)) ||
               path.StartsWith(_downloadsPrefix, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsTrustedPath(string path)
        => TrustedPathPrefixes.Any(p => path.StartsWith(p, StringComparison.Ordinal));

    /// <summary>
    /// Package ownership only says something in the directories a package
    /// manager actually curates. Home directories are full of legitimately
    /// unpackaged software — language runtimes, editors, self-updating tools —
    /// so asking there produces a Medium alert for every one of them and
    /// teaches the user to ignore the whole category. What remains is the
    /// interesting case: an unaccounted-for binary sitting in a system
    /// directory, which is where a post-exploitation payload gets dropped.
    /// Payloads under $HOME are still covered by the throwaway-path, shell and
    /// fileless rules above.
    /// </summary>
    private static bool IsPackageCheckWorthwhile(string path)
    {
        if (IsTrustedPath(path)) return false;
        if (path.StartsWith("/home/", StringComparison.Ordinal)) return false;
        if (path.StartsWith("/root/", StringComparison.Ordinal)) return false;
        // Container/sandbox overlays and per-user runtime dirs are not curated either.
        if (path.StartsWith("/run/user/", StringComparison.Ordinal)) return false;
        return path.StartsWith('/');
    }

    private PackageVerdict QueueOrGetPackage(string path)
    {
        if (_packageQuery.Value == null)
            return PackageVerdict.Owned; // no package manager to ask — stay quiet

        if (_packages.TryGetValue(path, out var verdict))
            return verdict;

        if (_packageQueued.TryAdd(path, 0))
        {
            _ = Task.Run(() =>
            {
                try
                {
                    _packages[path] = CheckPackage(_packageQuery.Value!, path);
                }
                finally
                {
                    _packageQueued.TryRemove(path, out _);
                }
            });
        }

        return PackageVerdict.Pending;
    }

    private static PackageVerdict CheckPackage(PackageQuery query, string path)
    {
        try
        {
            var args = query.Args.Select(a => a == "{}" ? path : a).ToArray();
            return RunQuiet(query.Program, args) == 0
                ? PackageVerdict.Owned
                : PackageVerdict.Unowned;
        }
        catch
        {
            // If the query fails, stay quiet rather than false-positive.
            return PackageVerdict.Owned;
        }
    }

    /// <summary>
    /// First package manager present on this system. "{}" is replaced with the
    /// path being queried; exit code 0 means some package owns the file.
    /// </summary>
    private static PackageQuery? FindPackageQuery()
    {
        var candidates = new[]
        {
            new PackageQuery("/usr/bin/dpkg-query", new[] { "-S", "{}" }),
            new PackageQuery("/usr/bin/rpm", new[] { "-qf", "{}" }),
            new PackageQuery("/usr/bin/pacman", new[] { "-Qo", "{}" }),
            new PackageQuery("/sbin/apk", new[] { "info", "-W", "{}" }),
            new PackageQuery("/usr/bin/apk", new[] { "info", "-W", "{}" })
        };

        return candidates.FirstOrDefault(c => File.Exists(c.Program));
    }

    private static int RunQuiet(string file, params string[] args)
    {
        var psi = new ProcessStartInfo(file)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi);
        if (p == null) return 1;
        p.StandardOutput.ReadToEnd();
        p.StandardError.ReadToEnd();
        if (!p.WaitForExit(10_000))
        {
            try { p.Kill(entireProcessTree: true); } catch { /* ignore */ }
            return 1;
        }
        return p.ExitCode;
    }
}
