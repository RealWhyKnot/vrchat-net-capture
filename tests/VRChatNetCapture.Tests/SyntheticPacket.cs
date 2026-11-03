using System.Buffers.Binary;

namespace VRChatNetCapture.Tests;

internal static class SyntheticPacket
{
    public static byte[] Create(int version, int payloadLength)
    {
        int headerLength = version == 4 ? 20 : 40;
        byte[] packet = new byte[headerLength + 8 + payloadLength];
        if (version == 4)
        {
            packet[0] = 0x45;
            packet[9] = 17;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)packet.Length);
            new byte[] { 192, 0, 2, 1, 198, 51, 100, 2 }.CopyTo(packet, 12);
        }
        else
        {
            packet[0] = 0x60;
            packet[6] = 17;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), (ushort)(payloadLength + 8));
            packet[8] = 0x20;
            packet[9] = 1;
            packet[23] = 1;
            packet[24] = 0x20;
            packet[25] = 1;
            packet[39] = 2;
        }
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(headerLength), 12345);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(headerLength + 2), 5055);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(headerLength + 4), (ushort)(payloadLength + 8));
        for (int index = headerLength + 8; index < packet.Length; index++)
        {
            packet[index] = (byte)index;
        }
        return packet;
    }
}
