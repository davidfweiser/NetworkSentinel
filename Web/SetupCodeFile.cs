using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace NetworkSentinel.Web;

/// <summary>
/// Where the first-visit setup code can be read when nobody can see the console.
///
/// The code is printed where the web console runs, and on Linux that reaches the
/// journal. The Windows service is a scheduled task running as SYSTEM: its console is
/// on no desktop and is logged nowhere, so a code that every setup — the server's own
/// browser included — has to quote would otherwise be unobtainable. It is written here
/// instead, readable by Administrators and SYSTEM (and whoever started the console) and
/// by no one else.
///
/// The data directory itself lets ordinary accounts create and modify files, so the
/// file never relies on what it inherits: it is created new, with its access list in
/// place from the first instant, and anything already sitting under the name is removed
/// rather than written into.
/// </summary>
internal static class SetupCodeFile
{
    public const string FileName = "setup-code.txt";

    public static string PathIn(string dataDirectory) => Path.Combine(dataDirectory, FileName);

    /// <summary>Writes the code and returns the file's path, or null when it could not be written safely.</summary>
    public static string? TryWrite(string dataDirectory, string code)
    {
        try
        {
            Directory.CreateDirectory(dataDirectory);
            var path = PathIn(dataDirectory);

            // Not opened, not truncated: a file planted under this name keeps the access
            // list its author gave it, and a link would aim the write somewhere else.
            File.Delete(path);

            var security = new FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            Allow(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
            Allow(security, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
            if (WindowsIdentity.GetCurrent().User is { } self)
                Allow(security, self);

            using var stream = new FileInfo(path).Create(
                FileMode.CreateNew, FileSystemRights.Write, FileShare.None, 4096, FileOptions.None, security);
            using var writer = new StreamWriter(stream);
            writer.WriteLine(code);
            writer.WriteLine();
            writer.WriteLine("Network Sentinel web console - first-visit setup code.");
            writer.WriteLine("Type it into the setup page along with the new master password.");
            writer.WriteLine("It changes every time the console starts, and this file is removed once a password is set.");
            return path;
        }
        catch
        {
            // The console still prints the code, and --set-master-password needs none.
            return null;
        }
    }

    public static void TryDelete(string dataDirectory)
    {
        try { File.Delete(PathIn(dataDirectory)); }
        catch { /* a stale file holds a code no running console accepts */ }
    }

    private static void Allow(FileSecurity security, SecurityIdentifier who)
        => security.AddAccessRule(new FileSystemAccessRule(who, FileSystemRights.FullControl, AccessControlType.Allow));
}
