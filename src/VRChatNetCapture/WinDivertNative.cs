using System.ComponentModel;
using System.Runtime.InteropServices;

namespace VRChatNetCapture;

internal static partial class WinDivertNative
{
    public const int LayerNetwork = 0;
    public const ulong FlagSniff = 0x0001;
    public const ulong FlagRecvOnly = 0x0004;
    public static readonly IntPtr InvalidHandle = new(-1);

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("WinDivert.dll", SetLastError = true, StringMarshalling = StringMarshalling.Custom, StringMarshallingCustomType = typeof(System.Runtime.InteropServices.Marshalling.AnsiStringMarshaller))]
    public static partial IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("WinDivert.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool WinDivertRecv(
        IntPtr handle,
        [Out] byte[] packet,
        uint packetLen,
        out uint recvLen,
        [Out] byte[] address);

    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    [LibraryImport("WinDivert.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool WinDivertClose(IntPtr handle);

    public static Win32Exception LastError(string operation) => new(Marshal.GetLastWin32Error(), operation);
}
