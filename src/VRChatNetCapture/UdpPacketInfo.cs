using System.Runtime.InteropServices;

namespace VRChatNetCapture;

[StructLayout(LayoutKind.Auto)]
internal readonly record struct UdpPacketInfo(
    int IpVersion,
    int SourceAddressOffset,
    int DestinationAddressOffset,
    int SourcePort,
    int DestinationPort,
    int PayloadOffset,
    int PayloadLength);
