using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;

namespace VRChatNetCapture;

public sealed record UdpPacketInfo(
    int IpVersion,
    string SourceAddress,
    string DestinationAddress,
    int SourcePort,
    int DestinationPort,
    int PayloadOffset,
    int PayloadLength,
    string PayloadSha256);

public static class UdpPacketParser
{
    public static UdpPacketInfo? TryParse(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 1)
        {
            return null;
        }
        var version = packet[0] >> 4;
        return version switch
        {
            4 => TryParseIPv4(packet),
            6 => TryParseIPv6(packet),
            _ => null,
        };
    }

    private static UdpPacketInfo? TryParseIPv4(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 28)
        {
            return null;
        }
        var ihl = (packet[0] & 0x0F) * 4;
        if (ihl < 20 || packet.Length < ihl + 8 || packet[9] != 17)
        {
            return null;
        }
        var totalLength = BinaryPrimitives.ReadUInt16BigEndian(packet[2..4]);
        if (totalLength == 0 || totalLength > packet.Length)
        {
            totalLength = (ushort)packet.Length;
        }
        var udpLength = BinaryPrimitives.ReadUInt16BigEndian(packet[(ihl + 4)..(ihl + 6)]);
        if (udpLength < 8 || ihl + udpLength > totalLength)
        {
            return null;
        }
        var payloadOffset = ihl + 8;
        var payloadLength = udpLength - 8;
        return new UdpPacketInfo(
            4,
            new IPAddress(packet[12..16]).ToString(),
            new IPAddress(packet[16..20]).ToString(),
            BinaryPrimitives.ReadUInt16BigEndian(packet[ihl..(ihl + 2)]),
            BinaryPrimitives.ReadUInt16BigEndian(packet[(ihl + 2)..(ihl + 4)]),
            payloadOffset,
            payloadLength,
            Sha256Hex(packet.Slice(payloadOffset, payloadLength)));
    }

    private static UdpPacketInfo? TryParseIPv6(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 48 || packet[6] != 17)
        {
            return null;
        }
        var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(packet[4..6]);
        if (payloadLength < 8 || 40 + payloadLength > packet.Length)
        {
            return null;
        }
        const int udpOffset = 40;
        var dataOffset = udpOffset + 8;
        var dataLength = BinaryPrimitives.ReadUInt16BigEndian(packet[(udpOffset + 4)..(udpOffset + 6)]) - 8;
        if (dataLength < 0 || dataOffset + dataLength > packet.Length)
        {
            return null;
        }
        return new UdpPacketInfo(
            6,
            new IPAddress(packet[8..24]).ToString(),
            new IPAddress(packet[24..40]).ToString(),
            BinaryPrimitives.ReadUInt16BigEndian(packet[udpOffset..(udpOffset + 2)]),
            BinaryPrimitives.ReadUInt16BigEndian(packet[(udpOffset + 2)..(udpOffset + 4)]),
            dataOffset,
            dataLength,
            Sha256Hex(packet.Slice(dataOffset, dataLength)));
    }

    public static string Sha256Hex(ReadOnlySpan<byte> data)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(data, hash);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
