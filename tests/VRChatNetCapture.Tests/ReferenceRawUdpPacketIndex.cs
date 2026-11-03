namespace VRChatNetCapture.Tests;

internal sealed class ReferenceRawUdpPacketIndex
{
    public int SchemaVersion { get; set; } = 1;
    public long PacketNumber { get; set; }
    public string TsUtc { get; set; } = "";
    public string CaptureSemantics { get; set; } = "wire_copy";
    public string Backend { get; set; } = "WinDivert";
    public int IpVersion { get; set; }
    public string SourceAddress { get; set; } = "";
    public string DestinationAddress { get; set; } = "";
    public int SourcePort { get; set; }
    public int DestinationPort { get; set; }
    public int CapturedLength { get; set; }
    public int PayloadLength { get; set; }
    public string PayloadSha256 { get; set; } = "";
    public string PayloadPath { get; set; } = "";
    public string Direction { get; set; } = "unknown";
    public bool Loopback { get; set; }
    public uint InterfaceIndex { get; set; }
    public int? ProcessId { get; set; }
    public string PidConfidence { get; set; } = "none";
    public static ReferenceRawUdpPacketIndex FromPacket(long packetNumber, DateTimeOffset timestamp, ReferenceUdpPacketInfo udp, ReferenceWinDivertAddressInfo address, int capturedLength)
    {
        return new ReferenceRawUdpPacketIndex
        {
            PacketNumber = packetNumber,
            TsUtc = timestamp.ToString("O"),
            CaptureSemantics = "wire_copy",
            Backend = "WinDivert",
            IpVersion = udp.IpVersion,
            SourceAddress = udp.SourceAddress,
            DestinationAddress = udp.DestinationAddress,
            SourcePort = udp.SourcePort,
            DestinationPort = udp.DestinationPort,
            CapturedLength = capturedLength,
            PayloadLength = udp.PayloadLength,
            PayloadSha256 = udp.PayloadSha256,
            PayloadPath = $"network/payloads/{udp.PayloadSha256}.udp.bin",
            Direction = address.Outbound ? "outbound" : "inbound",
            Loopback = address.Loopback,
            InterfaceIndex = address.InterfaceIndex,
            ProcessId = null,
            PidConfidence = "none",
        };
    }
}
