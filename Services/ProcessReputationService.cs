using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using NetworkSentinel.Models;

namespace NetworkSentinel.Services;

/// <summary>
/// Reputation checks on the local processes behind network connections:
///
///  * shells / script hosts / LOLBins holding an outbound connection to a
///    public address — the reverse-shell and living-off-the-land signature;
///  * binaries running from throwaway locations (%TEMP%, Downloads, Public)
///    with network activity;
///  * processes whose image file is no longer on disk — the payload deleted
///    itself after launching, so there is nothing left to inspect;
///  * unsigned binaries running from the system directories — the Windows
///    stand-in for "no package owns this": provenance unknown.
///
/// Paths come from QueryFullProcessImageName, which needs only
/// PROCESS_QUERY_LIMITED_INFORMATION and therefore works for most processes
/// without elevation (protected processes still refuse). The Authenticode
/// check runs once per unique executable path on a background task and is
/// cached, so the poll loop never blocks on WinVerifyTrust.
/// </summary>
public sealed class ProcessReputationService
{
    private const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder buffer, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    /// <summary>
    /// Interpreters and signed Microsoft binaries that attackers drive instead
    /// of dropping their own tooling. cmd/powershell talking to a public
    /// address is the classic reverse shell; certutil/bitsadmin/mshta are the
    /// standard download cradles and are signed, so no signature check would
    /// ever flag them.
    /// </summary>
    private static readonly HashSet<string> ShellNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe",
        "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
        "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe",
        "bash.exe", "sh.exe", "wsl.exe", "busybox.exe",
        "python.exe", "pythonw.exe", "perl.exe", "ruby.exe", "php.exe",
        "nc.exe", "ncat.exe", "netcat.exe", "socat.exe", "telnet.exe", "plink.exe"
    };

    /// <summary>
    /// Windows Installer, Inno Setup, NSIS and self-extracting archives all
    /// stage and run their payload from %TEMP% during a perfectly normal
    /// install or update, so an unfiltered temp-path rule fires on every
    /// software update the machine performs.
    /// </summary>
    private static readonly string[] SuspiciousPathExceptions =
    {
        @"\temp\{",     // MSI GUID-named staging directories
        @"\temp\msi",
        @"\temp\is-",   // Inno Setup
        @"\temp\7z",    // 7-Zip self-extractor
        @"\temp\nsis",
        @"\squirrel-temp\",
        @"\packages\windowsapps\"
    };

    private static readonly TimeSpan EmitCooldown = TimeSpan.FromMinutes(30);

    private readonly object _gate = new();
    private readonly List<ThreatEvent> _pending = new();
    private readonly Dictionary<string, DateTime> _lastEmit = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<int, string> _pidPaths = new();
    private readonly ConcurrentDictionary<string, SignatureVerdict> _signatures = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _signatureQueued = new(StringComparer.OrdinalIgnoreCase);
    private readonly int _ownPid = Environment.ProcessId;
    private readonly string[] _suspiciousPrefixes;
    private readonly string[] _systemPrefixes;
    private readonly string _userProfile;

    private enum SignatureVerdict { Pending, Signed, Unsigned }

    public ProcessReputationService()
    {
        _userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        _suspiciousPrefixes = new[]
        {
            Path.GetTempPath(),
            Path.Combine(windows, "Temp") + @"\",
            Path.Combine(_userProfile, "Downloads") + @"\",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments), "..", "Public") + @"\",
            @"C:\Users\Public\",
            @"C:\$Recycle.Bin\"
        };

        _systemPrefixes = new[]
        {
            windows + @"\",
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) + @"\",
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) + @"\"
        };
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
            if (c.ProcessId <= 4 || c.ProcessId == _ownPid) continue;
            if (c.State != TcpConnectionState.Established) continue;
            if (string.IsNullOrWhiteSpace(c.RemoteAddress)) continue;
            if (GeoIpService.IsNonPublic(c.RemoteAddress)) continue;
            if (GeoIpService.IsMulticastOrBroadcast(c.RemoteAddress)) continue;
            // Inbound sessions land on a listening port; those are someone else's doing.
            if (c.Protocol == "TCP" && listeningTcpPorts.Contains(c.LocalPort)) continue;

            var path = ResolvePath(c.ProcessId);
            var exeName = string.IsNullOrEmpty(path) ? c.ProcessName : Path.GetFileName(path);
            // The connection table reports "chrome", the image path "chrome.exe".
            var exeFile = exeName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? exeName : exeName + ".exe";

            if (ShellNames.Contains(exeFile))
            {
                Emit(now, $"shell|{exeFile}|{c.RemoteAddress}", new ThreatEvent
                {
                    Timestamp = now,
                    Type = ThreatType.SuspiciousProcess,
                    Level = ThreatLevel.High,
                    SourceIp = c.RemoteAddress,
                    Title = "Shell process with outbound connection",
                    Detail = $"{exeFile} (PID {c.ProcessId}) holds an established connection to {c.RemoteAddress}:{c.RemotePort}. " +
                             "A command shell, script host or download cradle talking to a public address is the classic " +
                             "reverse-shell signature. Legitimate uses exist (deployment scripts, package managers) — " +
                             "verify what launched it.",
                    Origin = "Origin resolving…",
                    Method = $"Process reputation · {exeFile} → {c.RemoteAddress}:{c.RemotePort}"
                });
            }

            if (string.IsNullOrEmpty(path)) continue;

            // Image file gone from disk. Windows holds a running executable's
            // file locked, so this is not the routine "upgraded while running"
            // case it would be on Linux — it means the payload deleted itself
            // after launch. Network and removable paths are excluded because a
            // disconnected drive looks identical.
            if (IsImageMissing(path))
            {
                Emit(now, $"missing|{path}|{c.ProcessId}", new ThreatEvent
                {
                    Timestamp = now,
                    Type = ThreatType.SuspiciousProcess,
                    Level = ThreatLevel.High,
                    SourceIp = c.RemoteAddress,
                    Title = "Running image deleted from disk",
                    Detail = $"{exeFile} (PID {c.ProcessId}) is running from {path}, which no longer exists on disk, and is " +
                             $"talking to {c.RemoteAddress}:{c.RemotePort}. Windows keeps a running program's file locked, so " +
                             "a payload that erased itself after starting is a deliberate anti-forensics technique.",
                    Origin = "Origin resolving…",
                    Method = "Process reputation · deleted executable image"
                });
                continue; // nothing on disk left to path- or signature-check
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
                    Detail = $"{exeFile} is running from {path} and talking to {c.RemoteAddress}:{c.RemotePort}. " +
                             "Malware often stages itself in temp or download folders before persisting.",
                    Origin = "Origin resolving…",
                    Method = "Process reputation · suspicious executable path"
                });
            }

            if (IsSignatureCheckWorthwhile(path))
            {
                if (QueueOrGetSignature(path) == SignatureVerdict.Unsigned)
                {
                    Emit(now, $"sig|{path}", new ThreatEvent
                    {
                        Timestamp = now,
                        Type = ThreatType.SuspiciousProcess,
                        Level = ThreatLevel.Medium,
                        SourceIp = c.RemoteAddress,
                        Title = "Unsigned system binary with network activity",
                        Detail = $"{exeFile} ({path}) sits in a system directory but carries no valid Authenticode signature, " +
                                 $"and is talking to {c.RemoteAddress}:{c.RemotePort}. Everything Windows and mainstream " +
                                 "installers put here is signed — an unsigned binary in this location cannot say where it came from.",
                        Origin = "Origin resolving…",
                        Method = "Process reputation · Authenticode signature"
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
    /// Full image path for a PID. PROCESS_QUERY_LIMITED_INFORMATION is the
    /// weakest right that answers this and is granted for processes of other
    /// users too; protected processes (antimalware, some system services)
    /// still refuse, and those simply come back empty.
    /// </summary>
    private string ResolvePath(int pid)
    {
        if (_pidPaths.TryGetValue(pid, out var cached))
            return cached;

        string path = "";
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle != IntPtr.Zero)
        {
            try
            {
                var buffer = new StringBuilder(1024);
                int size = buffer.Capacity;
                if (QueryFullProcessImageName(handle, 0, buffer, ref size))
                    path = buffer.ToString(0, size);
            }
            catch
            {
                // process exited between OpenProcess and the query
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        // PIDs recycle; a bounded cache is fine and avoids a handle open per poll.
        if (_pidPaths.Count > 4000) _pidPaths.Clear();
        _pidPaths[pid] = path;
        return path;
    }

    /// <summary>
    /// True when the image path points at a local fixed disk and the file is
    /// gone. UNC and removable paths are skipped: an unmapped share or an
    /// ejected USB stick is indistinguishable from a deleted payload.
    /// </summary>
    private static bool IsImageMissing(string path)
    {
        try
        {
            if (path.StartsWith(@"\\", StringComparison.Ordinal)) return false;
            var root = Path.GetPathRoot(path);
            if (string.IsNullOrEmpty(root)) return false;
            var drive = new DriveInfo(root);
            if (drive.DriveType != DriveType.Fixed) return false;
            return !File.Exists(path);
        }
        catch
        {
            return false;
        }
    }

    private bool IsSuspiciousPath(string path)
    {
        if (SuspiciousPathExceptions.Any(p => path.Contains(p, StringComparison.OrdinalIgnoreCase)))
            return false;
        return _suspiciousPrefixes.Any(p =>
            p.Length > 1 && path.StartsWith(p, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Signature checks only say something where signing is the norm. Under the
    /// user profile — %LOCALAPPDATA%, dev trees, self-updating tools — a large
    /// share of perfectly legitimate software is unsigned, so asking there
    /// produces a Medium alert for each one and teaches the user to ignore the
    /// whole category. What remains is the interesting case: an unsigned binary
    /// in Windows or Program Files, which is where a post-exploitation payload
    /// gets dropped to look native. Payloads under the profile are still
    /// covered by the throwaway-path, shell and deleted-image rules above.
    /// </summary>
    private bool IsSignatureCheckWorthwhile(string path)
    {
        if (path.StartsWith(_userProfile, StringComparison.OrdinalIgnoreCase)) return false;
        return _systemPrefixes.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase));
    }

    private SignatureVerdict QueueOrGetSignature(string path)
    {
        if (_signatures.TryGetValue(path, out var verdict))
            return verdict;

        if (_signatureQueued.TryAdd(path, 0))
        {
            _ = Task.Run(() =>
            {
                try
                {
                    _signatures[path] = Authenticode.IsTrusted(path)
                        ? SignatureVerdict.Signed
                        : SignatureVerdict.Unsigned;
                }
                catch
                {
                    // If the check itself fails, stay quiet rather than false-positive.
                    _signatures[path] = SignatureVerdict.Signed;
                }
                finally
                {
                    _signatureQueued.TryRemove(path, out _);
                }
            });
        }

        return SignatureVerdict.Pending;
    }
}
