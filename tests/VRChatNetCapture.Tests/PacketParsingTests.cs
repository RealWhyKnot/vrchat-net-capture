using System.Buffers.Binary;
using System.Net;
using System.Text;
using System.Text.Json;
using Xunit;

namespace VRChatNetCapture.Tests;

public sealed class PacketParsingTests
{
    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void PacketRecordsMatchOriginalParsing(int version)
    {
        using var record = new PacketRecordBuffer();
        int[] lengths = [0, 1, 64, 1200, 65487];
        foreach (int length in lengths)
        {
            byte[] packet = SyntheticPacket.Create(version, length);
            AssertMatches(packet, record);
            for (int end = 0; end < Math.Min(packet.Length, 70); end++)
            {
                AssertMatches(packet.AsSpan(0, end), record);
            }
            packet[version == 4 ? 9 : 6] = 6;
            AssertMatches(packet, record);
        }
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public void InvalidLengthsKeepOriginalAcceptance(int version)
    {
        using var record = new PacketRecordBuffer();
        byte[] packet = SyntheticPacket.Create(version, 64);
        int ipLengthOffset = version == 4 ? 2 : 4;
        int udpLengthOffset = version == 4 ? 24 : 44;
        ushort[] lengths = [0, 1, 7, 8, 27, 28, 47, 48, 63, 64, 71, 72, 92, 112, ushort.MaxValue];
        foreach (ushort ipLength in lengths)
        {
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ipLengthOffset), ipLength);
            foreach (ushort udpLength in lengths)
            {
                BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(udpLengthOffset), udpLength);
                AssertMatches(packet, record);
            }
        }
        for (int header = 0; header < 256; header++)
        {
            packet[0] = (byte)header;
            AssertMatches(packet, record);
        }
    }

    [Fact]
    public void GeneratedPacketsMatchOriginalParsing()
    {
        using var record = new PacketRecordBuffer();
        byte[] packet = new byte[ushort.MaxValue + 1];
        for (int index = 0; index < packet.Length; index++)
        {
            packet[index] = (byte)((index * 73) + 19);
        }
        for (int count = 0; count < 2048; count++)
        {
            int length = count * 7919 % (packet.Length + 1);
            packet[0] = (byte)count;
            AssertMatches(packet.AsSpan(0, length), record);
        }
        SyntheticPacket.Create(4, 64).CopyTo(packet, 0);
        packet[2] = 0;
        packet[3] = 0;
        AssertMatches(packet, record);
    }

    [Fact]
    public void Ipv6CompressionAndEmbeddedAddressesMatchIPAddress()
    {
        Span<byte> address = stackalloc byte[16];
        Span<char> text = stackalloc char[45];
        for (int mask = 0; mask < 256; mask++)
        {
            for (int group = 0; group < 8; group++)
            {
                ushort value = (mask & (1 << group)) != 0 ? (ushort)0 : (ushort)((group * 7919) + mask + 1);
                BinaryPrimitives.WriteUInt16BigEndian(address.Slice(group * 2, 2), value);
            }
            int length = PacketAddressFormatter.Format(address, text);
            Assert.Equal(new IPAddress(address).ToString(), text[..length].ToString());
        }
    }

    [Theory]
    [InlineData("::")]
    [InlineData("::1")]
    [InlineData("::ffff:0:1")]
    [InlineData("::ffff:192.0.2.1")]
    [InlineData("::192.0.2.1")]
    [InlineData("::ffff:0:192.0.2.1")]
    [InlineData("2001:db8:0:1:0:5efe:192.0.2.1")]
    [InlineData("2001:db8:0:1:0:5efe:0:1")]
    [InlineData("2001:db8:1:0:0:2:0:0")]
    [InlineData("255.255.255.255")]
    [InlineData("0.0.0.0")]
    public void AddressTextMatchesOriginalRecords(string addressText)
    {
        var address = IPAddress.Parse(addressText);
        byte[] bytes = address.GetAddressBytes();
        byte[] packet = SyntheticPacket.Create(bytes.Length == 4 ? 4 : 6, 1);
        int offset = bytes.Length == 4 ? 12 : 8;
        bytes.CopyTo(packet, offset);
        bytes.CopyTo(packet, offset + bytes.Length);
        using var record = new PacketRecordBuffer();
        AssertMatches(packet, record);
    }

    private static void AssertMatches(ReadOnlySpan<byte> packet, PacketRecordBuffer record)
    {
        ReferenceUdpPacketInfo? expected = ReferenceUdpPacketParser.TryParse(packet);
        UdpPacketInfo? actual = UdpPacketParser.TryParse(packet);
        if (expected is null)
        {
            Assert.Null(actual);
            return;
        }
        UdpPacketInfo parsed = Assert.IsType<UdpPacketInfo>(actual);
        Assert.Equal(expected.IpVersion, parsed.IpVersion);
        Assert.Equal(expected.PayloadOffset, parsed.PayloadOffset);
        Assert.Equal(expected.PayloadLength, parsed.PayloadLength);
        byte[] metadata = new byte[80];
        BinaryPrimitives.WriteUInt64LittleEndian(metadata.AsSpan(8), 3UL << 17);
        BinaryPrimitives.WriteUInt32LittleEndian(metadata.AsSpan(16), uint.MaxValue);
        DateTimeOffset timestamp = new DateTimeOffset(2020, 2, 29, 23, 59, 59, TimeSpan.FromHours(-5)).AddTicks(1234567);
        var oldAddress = ReferenceWinDivertAddressInfo.FromBuffer(metadata);
        var oldRecord = ReferenceRawUdpPacketIndex.FromPacket(long.MaxValue, timestamp, expected, oldAddress, packet.Length);
        string json = JsonSerializer.Serialize(oldRecord, JsonFiles.JsonLineOptions);
        record.Prepare(packet, parsed, WinDivertAddressInfo.FromBuffer(metadata), long.MaxValue, timestamp);
        Assert.Equal(json, Encoding.UTF8.GetString(record.WrittenMemory.Span));
        Assert.Equal(expected.PayloadSha256, record.Hash.ToString());
    }
}
