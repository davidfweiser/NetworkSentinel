using System.IO;

namespace NetworkSentinel.Services;

/// <summary>
/// The only places a Windows tool this app runs is looked for. Everything resolved here
/// is started from an elevated process (or behind the UAC prompt the operator is about
/// to approve), so a bare name is never handed to the process launcher: for a bare name
/// <c>CreateProcess</c> tries the application directory and the *current* directory
/// before System32, and <c>ShellExecute</c> tries the current directory first of all —
/// so a <c>netsh.exe</c> or <c>powershell.exe</c> dropped into whatever folder the app
/// happened to be started from would be what ran as Administrator. PATH is not
/// consulted either: the machine PATH routinely collects directories ordinary accounts
/// can write to.
///
/// A tool that is not where Windows installs it reads as "not installed" — the Linux
/// build makes the same trade for <c>nft</c>, <c>sudo</c> and <c>pkexec</c>.
/// </summary>
internal static class SystemTools
{
    /// <summary>Absolute path of netsh.exe, or null when System32 does not hold one.</summary>
    public static string? Netsh => InSystemDirectory("netsh.exe");

    /// <summary>Absolute path of Windows PowerShell 5.1, or null when it is not present.</summary>
    public static string? PowerShell => InSystemDirectory("WindowsPowerShell", "v1.0", "powershell.exe");

    /// <summary>Absolute path of wg.exe where WireGuard for Windows installs it, or null.</summary>
    public static string? WireGuard
        => InDirectory(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WireGuard", "wg.exe")
           ?? InDirectory(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "WireGuard", "wg.exe");

    private static string? InSystemDirectory(params string[] relative)
        => InDirectory(Environment.SystemDirectory, relative);

    internal static string? InDirectory(string root, params string[] relative)
    {
        // An empty root would make the result a relative path — the very lookup this
        // class exists to avoid.
        if (string.IsNullOrEmpty(root) || !Path.IsPathFullyQualified(root))
            return null;

        try
        {
            var candidate = Path.Combine(new[] { root }.Concat(relative).ToArray());
            return File.Exists(candidate) ? candidate : null;
        }
        catch
        {
            return null;
        }
    }
}
