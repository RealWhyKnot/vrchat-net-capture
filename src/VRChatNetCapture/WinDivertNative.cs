using System.ComponentModel;
using System.Runtime.InteropServices;

namespace VRChatNetCapture;

public static class WinDivertNative
{
    public const int LayerNetwork = 0;
    public const ulong FlagSniff = 0x0001;
    public const ulong FlagRecvOnly = 0x0004;
    public static readonly IntPtr InvalidHandle = new(-1);

    [DllImport("WinDivert.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);

    [DllImport("WinDivert.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertRecv(
        IntPtr handle,
        byte[] packet,
        uint packetLen,
        out uint recvLen,
        byte[] address);

    [DllImport("WinDivert.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WinDivertClose(IntPtr handle);

    public static Win32Exception LastError(string operation) => new(Marshal.GetLastWin32Error(), operation);
}
