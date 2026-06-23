using System.Buffers.Binary;

namespace VRChatNetCapture;

public sealed class PcapNgWriter : IDisposable
{
    private const uint SectionHeaderBlock = 0x0A0D0D0A;
    private const uint InterfaceDescriptionBlock = 0x00000001;
    private const uint EnhancedPacketBlock = 0x00000006;
    private const ushort LinkTypeRaw = 101;
    private readonly FileStream _stream;

    public PcapNgWriter(string path)
    {
        _stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read);
        WriteSectionHeader();
        WriteInterfaceDescription();
    }

    public void WritePacket(ReadOnlySpan<byte> packet, DateTimeOffset timestamp)
    {
        var paddedLength = Align4(packet.Length);
        var blockLength = 32 + paddedLength;
        Span<byte> header = stackalloc byte[28];
        WriteUInt32(header[0..4], EnhancedPacketBlock);
        WriteUInt32(header[4..8], (uint)blockLength);
        WriteUInt32(header[8..12], 0);
        var micros = timestamp.ToUnixTimeMilliseconds() * 1000L + (timestamp.Ticks % TimeSpan.TicksPerMillisecond) / 10L;
        WriteUInt32(header[12..16], (uint)(micros >> 32));
        WriteUInt32(header[16..20], (uint)(micros & 0xFFFFFFFF));
        WriteUInt32(header[20..24], (uint)packet.Length);
        WriteUInt32(header[24..28], (uint)packet.Length);
        _stream.Write(header);
        _stream.Write(packet);
        WritePadding(packet.Length);
        Span<byte> footer = stackalloc byte[4];
        WriteUInt32(footer, (uint)blockLength);
        _stream.Write(footer);
        _stream.Flush();
    }

    public void Dispose() => _stream.Dispose();

    private void WriteSectionHeader()
    {
        Span<byte> data = stackalloc byte[28];
        WriteUInt32(data[0..4], SectionHeaderBlock);
        WriteUInt32(data[4..8], 28);
        WriteUInt32(data[8..12], 0x1A2B3C4D);
        WriteUInt16(data[12..14], 1);
        WriteUInt16(data[14..16], 0);
        BinaryPrimitives.WriteInt64LittleEndian(data[16..24], -1);
        WriteUInt32(data[24..28], 28);
        _stream.Write(data);
    }

    private void WriteInterfaceDescription()
    {
        Span<byte> data = stackalloc byte[20];
        WriteUInt32(data[0..4], InterfaceDescriptionBlock);
        WriteUInt32(data[4..8], 20);
        WriteUInt16(data[8..10], LinkTypeRaw);
        WriteUInt16(data[10..12], 0);
        WriteUInt32(data[12..16], 65535);
        WriteUInt32(data[16..20], 20);
        _stream.Write(data);
    }

    private void WritePadding(int length)
    {
        var pad = Align4(length) - length;
        if (pad == 0)
        {
            return;
        }
        Span<byte> zeros = stackalloc byte[4];
        _stream.Write(zeros[..pad]);
    }

    private static int Align4(int value) => (value + 3) & ~3;

    private static void WriteUInt16(Span<byte> destination, ushort value) =>
        BinaryPrimitives.WriteUInt16LittleEndian(destination, value);

    private static void WriteUInt32(Span<byte> destination, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(destination, value);
}
