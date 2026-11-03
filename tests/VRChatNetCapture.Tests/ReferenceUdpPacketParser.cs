using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;

namespace VRChatNetCapture.Tests;

internal static class ReferenceUdpPacketParser
{
    public static ReferenceUdpPacketInfo? TryParse(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 1)
        {
            return null;
        }
        int version = packet[0] >> 4;
        return version switch
        {
            4 => TryParseIPv4(packet),
            6 => TryParseIPv6(packet),
            _ => null,
        };
    }

    private static ReferenceUdpPacketInfo? TryParseIPv4(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 28)
        {
            return null;
        }
        int ihl = (packet[0] & 0x0F) * 4;
        if (ihl < 20 || packet.Length < ihl + 8 || packet[9] != 17)
        {
            return null;
        }
        ushort totalLength = BinaryPrimitives.ReadUInt16BigEndian(packet[2..4]);
        if (totalLength == 0 || totalLength > packet.Length)
        {
            totalLength = (ushort)packet.Length;
        }
        ushort udpLength = BinaryPrimitives.ReadUInt16BigEndian(packet[(ihl + 4)..(ihl + 6)]);
        if (udpLength < 8 || ihl + udpLength > totalLength)
        {
            return null;
        }
        int payloadOffset = ihl + 8;
        int payloadLength = udpLength - 8;
        return new ReferenceUdpPacketInfo(
            4,
            new IPAddress(packet[12..16]).ToString(),
            new IPAddress(packet[16..20]).ToString(),
            BinaryPrimitives.ReadUInt16BigEndian(packet[ihl..(ihl + 2)]),
            BinaryPrimitives.ReadUInt16BigEndian(packet[(ihl + 2)..(ihl + 4)]),
            payloadOffset,
            payloadLength,
            Sha256Hex(packet.Slice(payloadOffset, payloadLength)));
    }

    private static ReferenceUdpPacketInfo? TryParseIPv6(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 48 || packet[6] != 17)
        {
            return null;
        }
        ushort payloadLength = BinaryPrimitives.ReadUInt16BigEndian(packet[4..6]);
        if (payloadLength < 8 || 40 + payloadLength > packet.Length)
        {
            return null;
        }
        const int UdpOffset = 40;
        int dataOffset = UdpOffset + 8;
        int dataLength = BinaryPrimitives.ReadUInt16BigEndian(packet[(UdpOffset + 4)..(UdpOffset + 6)]) - 8;
        return dataLength < 0 || dataOffset + dataLength > packet.Length
            ? null
            : new ReferenceUdpPacketInfo(
            6,
            new IPAddress(packet[8..24]).ToString(),
            new IPAddress(packet[24..40]).ToString(),
            BinaryPrimitives.ReadUInt16BigEndian(packet[UdpOffset..(UdpOffset + 2)]),
            BinaryPrimitives.ReadUInt16BigEndian(packet[(UdpOffset + 2)..(UdpOffset + 4)]),
            dataOffset,
            dataLength,
            Sha256Hex(packet.Slice(dataOffset, dataLength)));
    }

    public static string Sha256Hex(ReadOnlySpan<byte> data)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(data, hash);
        return Convert.ToHexStringLower(hash);
    }
}
