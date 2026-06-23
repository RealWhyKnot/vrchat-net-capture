using System.Text.Json;

namespace VRChatNetCapture;

public static class RawUdpCaptureWorker
{
    private const int MaxPacketSize = 0xFFFF;
    private const int AddressSize = 80;

    public static async Task<int> RunAsync(RawUdpCaptureOptions options, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(options.CaptureDir);
        var networkDir = Path.Combine(options.CaptureDir, "network");
        var payloadDir = Path.Combine(networkDir, "payloads");
        Directory.CreateDirectory(networkDir);
        Directory.CreateDirectory(payloadDir);

        await using var log = new StreamWriter(
            new FileStream(Path.Combine(networkDir, "raw-udp-worker.log"), FileMode.Create, FileAccess.Write, FileShare.Read))
        {
            AutoFlush = true,
        };
        try
        {
            var ports = RawUdpCaptureOptions.ParsePorts(options.Ports);
            var filter = RawUdpCaptureOptions.BuildWinDivertFilter(ports);
            await log.WriteLineAsync($"filter={filter}").ConfigureAwait(false);

            var handle = WinDivertNative.WinDivertOpen(
                filter,
                WinDivertNative.LayerNetwork,
                0,
                WinDivertNative.FlagSniff | WinDivertNative.FlagRecvOnly);
            if (handle == WinDivertNative.InvalidHandle)
            {
                throw WinDivertNative.LastError("WinDivertOpen failed");
            }

            try
            {
                await CaptureLoopAsync(handle, networkDir, payloadDir, ports, options.StopFile, cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                _ = WinDivertNative.WinDivertClose(handle);
            }
            return 0;
        }
        catch (Exception ex)
        {
            await log.WriteLineAsync(ex.ToString()).ConfigureAwait(false);
            JsonFiles.Write(
                Path.Combine(networkDir, "raw-udp-error.json"),
                new
                {
                    schema_version = 1,
                    error = ex.Message,
                    detail = ex.GetType().FullName,
                });
            return 1;
        }
    }

    private static async Task CaptureLoopAsync(
        IntPtr handle,
        string networkDir,
        string payloadDir,
        IReadOnlyList<int> ports,
        string stopFile,
        CancellationToken cancellationToken)
    {
        var packetPath = Path.Combine(networkDir, "realtime-udp.pcapng");
        var indexPath = Path.Combine(networkDir, "packet-index.jsonl");
        var datagramPath = Path.Combine(networkDir, "udp-datagrams.jsonl");
        JsonFiles.Write(
            Path.Combine(networkDir, "raw-udp-manifest.json"),
            new
            {
                schema_version = 1,
                capture_semantics = "wire_copy",
                backend = "WinDivert",
                filter_ports = ports,
                started_at = DateTimeOffset.UtcNow.ToString("O"),
            });

        var packetBuffer = new byte[MaxPacketSize];
        var addressBuffer = new byte[AddressSize];
        using var pcap = new PcapNgWriter(packetPath);
        await using var indexWriter = new StreamWriter(new FileStream(indexPath, FileMode.Create, FileAccess.Write, FileShare.Read))
        {
            AutoFlush = true,
        };
        await using var datagramWriter = new StreamWriter(new FileStream(datagramPath, FileMode.Create, FileAccess.Write, FileShare.Read))
        {
            AutoFlush = true,
        };

        long packetNumber = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            if (File.Exists(stopFile))
            {
                break;
            }
            if (!WinDivertNative.WinDivertRecv(handle, packetBuffer, (uint)packetBuffer.Length, out var recvLen, addressBuffer))
            {
                throw WinDivertNative.LastError("WinDivertRecv failed");
            }
            if (File.Exists(stopFile))
            {
                break;
            }
            var timestamp = DateTimeOffset.UtcNow;
            var packet = packetBuffer.AsSpan(0, (int)recvLen);
            var udp = UdpPacketParser.TryParse(packet);
            if (udp is null)
            {
                continue;
            }
            packetNumber++;
            pcap.WritePacket(packet, timestamp);
            var payload = packet.Slice(udp.PayloadOffset, udp.PayloadLength);
            var payloadPath = Path.Combine(payloadDir, udp.PayloadSha256 + ".udp.bin");
            if (!File.Exists(payloadPath))
            {
                await File.WriteAllBytesAsync(payloadPath, payload.ToArray(), cancellationToken).ConfigureAwait(false);
            }

            var address = WinDivertAddressInfo.FromBuffer(addressBuffer);
            var index = new RawUdpPacketIndex
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
                CapturedLength = (int)recvLen,
                PayloadLength = udp.PayloadLength,
                PayloadSha256 = udp.PayloadSha256,
                PayloadPath = $"network/payloads/{udp.PayloadSha256}.udp.bin",
                Direction = address.Outbound ? "outbound" : "inbound",
                Loopback = address.Loopback,
                InterfaceIndex = address.InterfaceIndex,
                ProcessId = null,
                PidConfidence = "none",
            };
            var json = JsonSerializer.Serialize(index, JsonFiles.Options);
            await indexWriter.WriteLineAsync(json).ConfigureAwait(false);
            await datagramWriter.WriteLineAsync(json).ConfigureAwait(false);
        }
    }
}

public sealed class RawUdpPacketIndex
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
}

public sealed class WinDivertAddressInfo
{
    public bool Outbound { get; init; }
    public bool Loopback { get; init; }
    public uint InterfaceIndex { get; init; }

    public static WinDivertAddressInfo FromBuffer(byte[] buffer)
    {
        var flags = BitConverter.ToUInt64(buffer, 8);
        return new WinDivertAddressInfo
        {
            Outbound = ((flags >> 17) & 1) != 0,
            Loopback = ((flags >> 18) & 1) != 0,
            InterfaceIndex = BitConverter.ToUInt32(buffer, 16),
        };
    }
}
