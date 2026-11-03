namespace VRChatNetCapture.Tests;

internal sealed record ReferenceUdpPacketInfo(
    int IpVersion,
    string SourceAddress,
    string DestinationAddress,
    int SourcePort,
    int DestinationPort,
    int PayloadOffset,
    int PayloadLength,
    string PayloadSha256);
