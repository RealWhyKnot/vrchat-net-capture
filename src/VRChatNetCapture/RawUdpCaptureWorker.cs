namespace VRChatNetCapture;

internal static class RawUdpCaptureWorker
{
    private const int MaxPacketSize = 0xFFFF;

    public static async Task<int> RunAsync(RawUdpCaptureOptions options, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(options.CaptureDir);
        string networkDir = Path.Combine(options.CaptureDir, "network");
        string payloadDir = Path.Combine(networkDir, "payloads");
        Directory.CreateDirectory(networkDir);
        Directory.CreateDirectory(payloadDir);

        await using var log = new StreamWriter(
            new FileStream(Path.Combine(networkDir, "raw-udp-worker.log"), FileMode.Create, FileAccess.Write, FileShare.Read))
        {
            AutoFlush = true,
        };
        try
        {
            await RunCaptureAsync(options, networkDir, payloadDir, log, cancellationToken).ConfigureAwait(false);
            return 0;
        }
        catch (DllNotFoundException ex)
        {
            await WriteErrorAsync(log, networkDir, ex, cancellationToken).ConfigureAwait(false);
            return 1;
        }
        catch (EntryPointNotFoundException ex)
        {
            await WriteErrorAsync(log, networkDir, ex, cancellationToken).ConfigureAwait(false);
            return 1;
        }
        catch (BadImageFormatException ex)
        {
            await WriteErrorAsync(log, networkDir, ex, cancellationToken).ConfigureAwait(false);
            return 1;
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            await WriteErrorAsync(log, networkDir, ex, cancellationToken).ConfigureAwait(false);
            return 1;
        }
        catch (IOException ex)
        {
            await WriteErrorAsync(log, networkDir, ex, cancellationToken).ConfigureAwait(false);
            return 1;
        }
        catch (UnauthorizedAccessException ex)
        {
            await WriteErrorAsync(log, networkDir, ex, cancellationToken).ConfigureAwait(false);
            return 1;
        }
    }

    private static async Task RunCaptureAsync(RawUdpCaptureOptions options, string networkDir, string payloadDir, StreamWriter log, CancellationToken cancellationToken)
    {
        IReadOnlyList<int> ports = RawUdpCaptureOptions.ParsePorts(options.Ports);
        string filter = RawUdpCaptureOptions.BuildWinDivertFilter(ports);
        await log.WriteLineAsync($"filter={filter}").ConfigureAwait(false);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        nint handle = WinDivertNative.WinDivertOpen(
            filter,
            WinDivertNative.LayerNetwork,
            0,
            WinDivertNative.FlagSniff | WinDivertNative.FlagRecvOnly);
        if (handle == WinDivertNative.InvalidHandle)
        {
            throw WinDivertNative.LastError("WinDivertOpen failed");
        }

        Task parentWatch = WatchParentAsync(options.ParentPid, options.StopFile, ports, log, linkedCts.Token);
        try
        {
            await CaptureLoopAsync(handle, networkDir, payloadDir, ports, options.StopFile, linkedCts.Token)
                .ConfigureAwait(false);
        }
        finally
        {
            await linkedCts.CancelAsync().ConfigureAwait(false);
            await parentWatch.ConfigureAwait(false);
            _ = WinDivertNative.WinDivertClose(handle);
        }
    }

    private static async Task WriteErrorAsync(StreamWriter log, string networkDir, Exception ex, CancellationToken cancellationToken)
    {
        await log.WriteLineAsync(ex.ToString().AsMemory(), cancellationToken).ConfigureAwait(false);
        JsonFiles.Write(
            Path.Combine(networkDir, "raw-udp-error.json"),
            new
            {
                schema_version = 1,
                error = ex.Message,
                detail = ex.GetType().FullName,
            });
    }

    private static async Task CaptureLoopAsync(
        IntPtr handle,
        string networkDir,
        string payloadDir,
        IReadOnlyList<int> ports,
        string stopFile,
        CancellationToken cancellationToken)
    {
        string packetPath = Path.Combine(networkDir, "realtime-udp.pcapng");
        WriteManifest(networkDir, ports);

        using var buffers = new CapturePacketBuffers();
        using var pcap = new PcapNgWriter(packetPath);
        await using var sink = new RawUdpPacketSink(networkDir, payloadDir);

        long packetNumber = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            if (File.Exists(stopFile))
            {
                break;
            }
            if (!WinDivertNative.WinDivertRecv(handle, buffers.Packet, MaxPacketSize, out uint receivedLength, buffers.Address))
            {
                throw WinDivertNative.LastError("WinDivertRecv failed");
            }
            if (File.Exists(stopFile))
            {
                break;
            }
            DateTimeOffset timestamp = DateTimeOffset.UtcNow;
            Memory<byte> packet = buffers.Packet.AsMemory(0, (int)receivedLength);
            if (UdpPacketParser.TryParse(packet.Span) is not { } udp)
            {
                continue;
            }
            packetNumber++;
            pcap.WritePacket(packet.Span, timestamp);
            var address = WinDivertAddressInfo.FromBuffer(buffers.Address);
            await sink.WriteAsync(packet, udp, address, packetNumber, timestamp, cancellationToken).ConfigureAwait(false);
        }
    }

    private static void WriteManifest(string networkDir, IReadOnlyList<int> ports)
    {
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
    }

    private static Task WatchParentAsync(
        int? parentPid,
        string stopFile,
        IReadOnlyList<int> ports,
        StreamWriter log,
        CancellationToken cancellationToken)
    {
        return parentPid is null
            ? Task.CompletedTask
            : Task.Run(
            async () =>
            {
                try
                {
                    using var parent = System.Diagnostics.Process.GetProcessById(parentPid.Value);
                    await parent.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (ArgumentException ex)
                {
                    CaptureLog.Debug(ex);
                }
                catch (InvalidOperationException ex)
                {
                    CaptureLog.Debug(ex);
                }

                if (cancellationToken.IsCancellationRequested)
                {
                    return;
                }

                await log.WriteLineAsync("parent process exited; stopping raw UDP worker").ConfigureAwait(false);
                SignalStop(stopFile, ports);
            },
            CancellationToken.None);
    }

    private static void SignalStop(string stopFile, IReadOnlyList<int> ports)
    {
        try
        {
            File.WriteAllText(stopFile, DateTimeOffset.UtcNow.ToString("O"));
        }
        catch (IOException ex)
        {
            CaptureLog.Debug(ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            CaptureLog.Debug(ex);
        }
        catch (System.Net.Sockets.SocketException ex)
        {
            CaptureLog.Debug(ex);
        }

        try
        {
            int port = ports.Contains(9001) ? 9001 : ports[0];
            using var udp = new System.Net.Sockets.UdpClient();
            udp.Send([0], 1, "127.0.0.1", port);
        }
        catch (IOException ex)
        {
            CaptureLog.Debug(ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            CaptureLog.Debug(ex);
        }
        catch (System.Net.Sockets.SocketException ex)
        {
            CaptureLog.Debug(ex);
        }
    }
}
