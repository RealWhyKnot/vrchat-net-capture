using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace VRChatNetCapture;

internal sealed class PacketRecordBuffer : IDisposable
{
    private readonly ArrayBufferWriter<byte> _buffer = new(2048);
    private readonly Utf8JsonWriter _writer;
    private readonly char[] _hash = new char[64];

    public PacketRecordBuffer()
    {
        _writer = new Utf8JsonWriter(_buffer);
    }

    public ReadOnlyMemory<byte> WrittenMemory => _buffer.WrittenMemory;
    public ReadOnlySpan<char> Hash => _hash;

    public void Prepare(ReadOnlySpan<byte> packet, UdpPacketInfo udp, WinDivertAddressInfo address, long packetNumber, DateTimeOffset timestamp)
    {
        Span<byte> hashBytes = stackalloc byte[32];
        SHA256.HashData(packet.Slice(udp.PayloadOffset, udp.PayloadLength), hashBytes);
        if (!Convert.TryToHexStringLower(hashBytes, _hash, out _))
        {
            throw new InvalidOperationException();
        }
        _buffer.ResetWrittenCount();
        _writer.Reset(_buffer);
        WriteRecord(packet, udp, address, packetNumber, timestamp);
        _writer.Flush();
    }

    private void WriteRecord(ReadOnlySpan<byte> packet, UdpPacketInfo udp, WinDivertAddressInfo address, long packetNumber, DateTimeOffset timestamp)
    {
        Span<char> text = stackalloc char[128];
        if (!timestamp.TryFormat(text, out int timestampLength, "O", CultureInfo.InvariantCulture))
        {
            throw new InvalidOperationException();
        }
        _writer.WriteStartObject();
        _writer.WriteNumber("schema_version"u8, 1);
        _writer.WriteNumber("packet_number"u8, packetNumber);
        _writer.WriteString("ts_utc"u8, text[..timestampLength]);
        _writer.WriteString("capture_semantics"u8, "wire_copy"u8);
        _writer.WriteString("backend"u8, "WinDivert"u8);
        _writer.WriteNumber("ip_version"u8, udp.IpVersion);
        int addressLength = udp.IpVersion == 4 ? 4 : 16;
        int sourceLength = PacketAddressFormatter.Format(packet.Slice(udp.SourceAddressOffset, addressLength), text);
        _writer.WriteString("source_address"u8, text[..sourceLength]);
        int destinationLength = PacketAddressFormatter.Format(packet.Slice(udp.DestinationAddressOffset, addressLength), text);
        _writer.WriteString("destination_address"u8, text[..destinationLength]);
        _writer.WriteNumber("source_port"u8, udp.SourcePort);
        _writer.WriteNumber("destination_port"u8, udp.DestinationPort);
        _writer.WriteNumber("captured_length"u8, packet.Length);
        _writer.WriteNumber("payload_length"u8, udp.PayloadLength);
        _writer.WriteString("payload_sha256"u8, _hash);
        const string Prefix = "network/payloads/";
        const string Suffix = ".udp.bin";
        Prefix.CopyTo(text);
        _hash.CopyTo(text[Prefix.Length..]);
        Suffix.CopyTo(text[(Prefix.Length + _hash.Length)..]);
        _writer.WriteString("payload_path"u8, text[..(Prefix.Length + _hash.Length + Suffix.Length)]);
        _writer.WriteString("direction"u8, address.Outbound ? "outbound"u8 : "inbound"u8);
        _writer.WriteBoolean("loopback"u8, address.Loopback);
        _writer.WriteNumber("interface_index"u8, address.InterfaceIndex);
        _writer.WriteNull("process_id"u8);
        _writer.WriteString("pid_confidence"u8, "none"u8);
        _writer.WriteEndObject();
    }

    public void AppendNewLine()
    {
        int written = Encoding.UTF8.GetBytes(Environment.NewLine, _buffer.GetSpan(2));
        _buffer.Advance(written);
    }

    public void Dispose() => _writer.Dispose();
}
