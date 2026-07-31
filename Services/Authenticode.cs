using System.Runtime.InteropServices;

namespace NetworkSentinel.Services;

/// <summary>
/// Authenticode verification via WinVerifyTrust — the same check Explorer's
/// "Digital Signatures" tab and SmartScreen use. This is stricter than reading
/// the certificate off the file: it validates the chain and confirms the
/// binary has not been altered since signing, so a tampered copy of a signed
/// system executable comes back untrusted.
///
/// Revocation checking is disabled and URL retrieval is cache-only, because
/// this runs unattended on a background task: a CRL fetch against a blocked or
/// slow network would otherwise stall for the full WinINet timeout on every
/// unique binary.
/// </summary>
internal static class Authenticode
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdSaferFlag = 0x100;
    private const uint WtdCacheOnlyUrlRetrieval = 0x1000;

    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid actionId, IntPtr data);

    /// <summary>
    /// True when <paramref name="path"/> carries a valid, trusted Authenticode
    /// signature (embedded or via a catalog). Anything else — unsigned, broken
    /// chain, tampered, or unreadable — is false.
    /// </summary>
    public static bool IsTrusted(string path)
    {
        var fileInfo = new WinTrustFileInfo
        {
            cbStruct = Marshal.SizeOf<WinTrustFileInfo>(),
            pcwszFilePath = Marshal.StringToCoTaskMemUni(path),
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        var filePtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<WinTrustFileInfo>());
        Marshal.StructureToPtr(fileInfo, filePtr, false);

        var data = new WinTrustData
        {
            cbStruct = Marshal.SizeOf<WinTrustData>(),
            pPolicyCallbackData = IntPtr.Zero,
            pSIPClientData = IntPtr.Zero,
            dwUIChoice = WtdUiNone,
            fdwRevocationChecks = WtdRevokeNone,
            dwUnionChoice = WtdChoiceFile,
            pUnion = filePtr,
            dwStateAction = WtdStateActionVerify,
            hWVTStateData = IntPtr.Zero,
            pwszURLReference = IntPtr.Zero,
            dwProvFlags = WtdSaferFlag | WtdCacheOnlyUrlRetrieval,
            dwUIContext = 0,
            pSignatureSettings = IntPtr.Zero
        };

        var dataPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<WinTrustData>());
        Marshal.StructureToPtr(data, dataPtr, false);

        try
        {
            int result = WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, dataPtr);

            // The verify call allocates state that must be released with a
            // second call, or every checked binary leaks a context.
            var close = Marshal.PtrToStructure<WinTrustData>(dataPtr);
            close.dwStateAction = WtdStateActionClose;
            Marshal.StructureToPtr(close, dataPtr, false);
            WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, dataPtr);

            return result == 0;
        }
        finally
        {
            Marshal.FreeCoTaskMem(fileInfo.pcwszFilePath);
            Marshal.FreeCoTaskMem(filePtr);
            Marshal.FreeCoTaskMem(dataPtr);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public int cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public int cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }
}
