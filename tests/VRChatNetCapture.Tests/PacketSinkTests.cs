using System.Text;
using System.Text.Json;
using Xunit;

namespace VRChatNetCapture.Tests;

public sealed class PacketSinkTests
{
    [Fact]
    public async Task PayloadsAndIndexesKeepOriginalBytesWhenBufferIsReused()
    {
        string directory = Path.Combine(Path.GetTempPath(), $"vcnc-packets-{Guid.NewGuid():N}");
        string payloadDirectory = Path.Combine(directory, "payloads");
        Directory.CreateDirectory(payloadDirectory);
        byte[] packet = SyntheticPacket.Create(6, 1200);
        ReferenceUdpPacketInfo parsed = Assert.IsType<ReferenceUdpPacketInfo>(ReferenceUdpPacketParser.TryParse(packet));
        byte[] payload = packet.AsSpan(parsed.PayloadOffset, parsed.PayloadLength).ToArray();
        byte[] address = new byte[80];
        string payloadPath = Path.Combine(payloadDirectory, parsed.PayloadSha256 + ".udp.bin");
        DateTimeOffset timestamp = DateTimeOffset.UnixEpoch;
        var expected = ReferenceRawUdpPacketIndex.FromPacket(1, timestamp, parsed, ReferenceWinDivertAddressInfo.FromBuffer(address), packet.Length);
        string firstLine = JsonSerializer.Serialize(expected, JsonFiles.JsonLineOptions) + Environment.NewLine;
        try
        {
            await using (var sink = new RawUdpPacketSink(directory, payloadDirectory))
            {
                UdpPacketInfo udp = Assert.IsType<UdpPacketInfo>(UdpPacketParser.TryParse(packet));
                await sink.WriteAsync(packet, udp, WinDivertAddressInfo.FromBuffer(address), 1, timestamp, CancellationToken.None);
                Assert.Equal(payload, await File.ReadAllBytesAsync(payloadPath, CancellationToken.None));
                Assert.Equal(firstLine, await ReadOpenFileAsync(Path.Combine(directory, "packet-index.jsonl"), CancellationToken.None));
                byte[] existing = [7, 8, 9];
                await File.WriteAllBytesAsync(payloadPath, existing, CancellationToken.None);
                await sink.WriteAsync(packet, udp, WinDivertAddressInfo.FromBuffer(address), 2, timestamp, CancellationToken.None);
                Assert.Equal(existing, await File.ReadAllBytesAsync(payloadPath, CancellationToken.None));
                packet.AsSpan().Clear();
            }
            expected.PacketNumber = 2;
            string lines = firstLine + JsonSerializer.Serialize(expected, JsonFiles.JsonLineOptions) + Environment.NewLine;
            byte[] index = await File.ReadAllBytesAsync(Path.Combine(directory, "packet-index.jsonl"), CancellationToken.None);
            byte[] datagrams = await File.ReadAllBytesAsync(Path.Combine(directory, "udp-datagrams.jsonl"), CancellationToken.None);
            Assert.Equal(Encoding.UTF8.GetBytes(lines), index);
            Assert.Equal(index, datagrams);
            Assert.Single(Directory.GetFiles(payloadDirectory));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task CanceledPayloadWriteDoesNotAppendIndex()
    {
        string directory = Path.Combine(Path.GetTempPath(), $"vcnc-cancel-{Guid.NewGuid():N}");
        string payloadDirectory = Path.Combine(directory, "payloads");
        Directory.CreateDirectory(payloadDirectory);
        try
        {
            byte[] packet = SyntheticPacket.Create(4, 64);
            UdpPacketInfo parsed = Assert.IsType<UdpPacketInfo>(UdpPacketParser.TryParse(packet));
            using var cancellation = new CancellationTokenSource();
            await cancellation.CancelAsync();
            await using var sink = new RawUdpPacketSink(directory, payloadDirectory);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sink.WriteAsync(packet, parsed, default, 1, DateTimeOffset.UnixEpoch, cancellation.Token));
            Assert.Empty(await ReadOpenFileAsync(Path.Combine(directory, "packet-index.jsonl"), CancellationToken.None));
            Assert.Empty(await ReadOpenFileAsync(Path.Combine(directory, "udp-datagrams.jsonl"), CancellationToken.None));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task CancellationAfterPayloadExistsKeepsThePacketRecord()
    {
        string directory = Path.Combine(Path.GetTempPath(), $"vcnc-commit-{Guid.NewGuid():N}");
        string payloadDirectory = Path.Combine(directory, "payloads");
        Directory.CreateDirectory(payloadDirectory);
        try
        {
            byte[] packet = SyntheticPacket.Create(4, 64);
            UdpPacketInfo parsed = Assert.IsType<UdpPacketInfo>(UdpPacketParser.TryParse(packet));
            byte[] payload = packet.AsSpan(parsed.PayloadOffset, parsed.PayloadLength).ToArray();
            string hash = ReferenceUdpPacketParser.Sha256Hex(payload);
            await File.WriteAllBytesAsync(Path.Combine(payloadDirectory, hash + ".udp.bin"), payload, CancellationToken.None);
            using var cancellation = new CancellationTokenSource();
            await cancellation.CancelAsync();
            await using var sink = new RawUdpPacketSink(directory, payloadDirectory);
            await sink.WriteAsync(packet, parsed, default, 1, DateTimeOffset.UnixEpoch, cancellation.Token);
            string index = await ReadOpenFileAsync(Path.Combine(directory, "packet-index.jsonl"), CancellationToken.None);
            string datagrams = await ReadOpenFileAsync(Path.Combine(directory, "udp-datagrams.jsonl"), CancellationToken.None);
            Assert.NotEmpty(index);
            Assert.Equal(index, datagrams);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task<string> ReadOpenFileAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync(cancellationToken);
    }
}
