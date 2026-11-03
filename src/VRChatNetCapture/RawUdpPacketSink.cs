namespace VRChatNetCapture;

internal sealed class RawUdpPacketSink : IAsyncDisposable
{
    private readonly string _payloadDir;
    private readonly FileStream _index;
    private readonly FileStream _datagrams;
    private readonly PacketRecordBuffer _record = new();

    public RawUdpPacketSink(string networkDir, string payloadDir)
    {
        _payloadDir = payloadDir;
        _index = new FileStream(Path.Combine(networkDir, "packet-index.jsonl"), FileMode.Create, FileAccess.Write, FileShare.Read);
        try
        {
            _datagrams = new FileStream(Path.Combine(networkDir, "udp-datagrams.jsonl"), FileMode.Create, FileAccess.Write, FileShare.Read);
        }
        catch (IOException)
        {
            _index.Dispose();
            _record.Dispose();
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            _index.Dispose();
            _record.Dispose();
            throw;
        }
    }

    public async Task WriteAsync(ReadOnlyMemory<byte> packet, UdpPacketInfo udp, WinDivertAddressInfo address, long packetNumber, DateTimeOffset timestamp, CancellationToken cancellationToken)
    {
        _record.Prepare(packet.Span, udp, address, packetNumber, timestamp);
        string payloadPath = string.Create(_payloadDir.Length + 1 + 64 + 8, this, static (path, sink) =>
        {
            sink._payloadDir.CopyTo(path);
            path[sink._payloadDir.Length] = Path.DirectorySeparatorChar;
            sink._record.Hash.CopyTo(path[(sink._payloadDir.Length + 1)..]);
            ".udp.bin".CopyTo(path[^8..]);
        });
        if (!File.Exists(payloadPath))
        {
            await File.WriteAllBytesAsync(payloadPath, packet.Slice(udp.PayloadOffset, udp.PayloadLength), cancellationToken).ConfigureAwait(false);
        }
        await CommitIndexesAsync(CancellationToken.None).ConfigureAwait(false);
    }

    private async Task CommitIndexesAsync(CancellationToken cancellationToken)
    {
        _record.AppendNewLine();
        await _index.WriteAsync(_record.WrittenMemory, cancellationToken).ConfigureAwait(false);
        await _index.FlushAsync(cancellationToken).ConfigureAwait(false);
        await _datagrams.WriteAsync(_record.WrittenMemory, cancellationToken).ConfigureAwait(false);
        await _datagrams.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await _datagrams.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            _record.Dispose();
            await _index.DisposeAsync().ConfigureAwait(false);
        }
    }
}
