using System.Runtime.InteropServices;

namespace VRChatNetCapture;

[StructLayout(LayoutKind.Auto)]
internal readonly record struct WinDivertAddressInfo
{
    public bool Outbound { get; init; }
    public bool Loopback { get; init; }
    public uint InterfaceIndex { get; init; }

    public static WinDivertAddressInfo FromBuffer(byte[] buffer)
    {
        ulong flags = BitConverter.ToUInt64(buffer, 8);
        return new WinDivertAddressInfo
        {
            Outbound = ((flags >> 17) & 1) != 0,
            Loopback = ((flags >> 18) & 1) != 0,
            InterfaceIndex = BitConverter.ToUInt32(buffer, 16),
        };
    }
}
