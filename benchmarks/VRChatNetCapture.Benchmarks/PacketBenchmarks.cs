using System.Text.Json;
using BenchmarkDotNet.Attributes;
using VRChatNetCapture.Tests;

namespace VRChatNetCapture.Benchmarks;

[MemoryDiagnoser]
public class PacketBenchmarks : IDisposable
{
    private byte[] _packet = [];
    private readonly PacketRecordBuffer _record = new();
    private readonly byte[] _address = new byte[80];

    [Params(4, 6)]
    public int Version { get; set; }

    [Params(64, 1200)]
    public int PayloadLength { get; set; }

    [GlobalSetup]
    public void Setup() => _packet = SyntheticPacket.Create(Version, PayloadLength);

    [Benchmark(Baseline = true)]
    public int PrepareBefore()
    {
        ReferenceUdpPacketInfo parsed = ReferenceUdpPacketParser.TryParse(_packet) ?? throw new InvalidOperationException();
        byte[] payload = _packet.AsSpan(parsed.PayloadOffset, parsed.PayloadLength).ToArray();
        Stream.Null.Write(payload);
        var address = ReferenceWinDivertAddressInfo.FromBuffer(_address);
        var index = ReferenceRawUdpPacketIndex.FromPacket(1, DateTimeOffset.UnixEpoch, parsed, address, _packet.Length);
        return JsonSerializer.Serialize(index, JsonFiles.JsonLineOptions).Length;
    }

    [Benchmark]
    public int PrepareAfter()
    {
        UdpPacketInfo parsed = UdpPacketParser.TryParse(_packet) ?? throw new InvalidOperationException();
        Stream.Null.Write(_packet.AsSpan(parsed.PayloadOffset, parsed.PayloadLength));
        var address = WinDivertAddressInfo.FromBuffer(_address);
        _record.Prepare(_packet, parsed, address, 1, DateTimeOffset.UnixEpoch);
        return _record.WrittenMemory.Length;
    }

    [GlobalCleanup]
    public void Dispose()
    {
        Dispose(isDisposing: true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool isDisposing)
    {
        if (isDisposing)
        {
            _record.Dispose();
        }
    }
}
