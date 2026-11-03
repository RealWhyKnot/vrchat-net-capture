using System.Diagnostics;
using System.Net;
using Xunit;
using static Xunit.Assert;

namespace VRChatNetCapture.Tests;

public sealed class CaptureTests
{
    [Fact]
    public void DefaultsUseRegularProxyMode()
    {
        var options = CaptureOptions.Parse([]);
        Equal("start", options.Command);
        Equal("regular", options.Mode);
        Equal(8080, options.ListenPort);
        Null(options.DecodeOsc);
        Null(options.PhotonMetadata);
        Null(options.UnityMetadata);
        Null(options.RawUdpCapture);
        False(options.PacketOnly);
        Equal("", options.MitmAllowHosts);
        Equal("", options.MitmIgnoreHosts);
    }

    [Fact]
    public void DefaultIgnoreHostsPassThroughInfrastructure()
    {
        var host = new System.Text.RegularExpressions.Regex(CaptureOptions.Parse([]).EffectiveMitmIgnoreHosts, System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(1));
        foreach (string? passthrough in new[]
        {
        "api.vrchat.cloud:443",
        "pipeline.vrchat.cloud:443",
        "files.vrchat.cloud:443",
        "file-variants.vrchat.cloud:443",
        "assets.vrchat.com:443",
        "vrchat.com:443",
        "localhost.youtube.com:54332",
    })
        {
            Matches(host, passthrough);
        }
        foreach (string? captured in new[]
        {
        "data.illumination.media:443",
        "bh3.imvrcdn.com:443",
        "www.youtube.com:443",
        "notvrchat.cloud.example.com:443",
    })
        {
            DoesNotMatch(host, captured);
        }

        var combined = CaptureOptions.Parse(["--mitm-ignore-hosts", @"(?i)^([a-z0-9-]+\.)*example\.test:\d+$"]);
        var merged = new System.Text.RegularExpressions.Regex(combined.EffectiveMitmIgnoreHosts, System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(1));
        Matches(merged, "file-variants.vrchat.cloud:443");
        Matches(merged, "sub.example.test:443");
        DoesNotMatch(merged, "bh3.imvrcdn.com:443");

        var opted = CaptureOptions.Parse(["--no-default-ignore-hosts"]);
        True(opted.NoDefaultIgnoreHosts);
        Equal("", opted.EffectiveMitmIgnoreHosts);

        string root = Path.Combine(Path.GetTempPath(), "vnc-ignore-hosts");
        var paths = new CapturePaths(root, Path.Combine(root, "captures"));
        var session = new CaptureSession { CaptureDir = Path.Combine(root, "captures", "one") };
        Contains(MitmdumpProcess.BuildArguments(CaptureOptions.Parse([]), paths, session), "--ignore-hosts");
        DoesNotContain("--ignore-hosts", MitmdumpProcess.BuildArguments(opted, paths, session), StringComparer.Ordinal);
    }

    [Fact]
    public void CapturingAllProcessesRequiresExplicitFlag()
    {
        string root = Path.Combine(Path.GetTempPath(), "vnc-process-scope");
        var paths = new CapturePaths(root, Path.Combine(root, "captures"));
        var session = new CaptureSession { CaptureDir = Path.Combine(root, "captures", "one") };

        var defaults = CaptureOptions.Parse([]);
        False(defaults.CaptureAllProcesses);
        IReadOnlyList<string> defaultArgs = MitmdumpProcess.BuildArguments(defaults, paths, session);
        Contains(defaultArgs, "capture_all_processes=false");
        DoesNotContain("capture_all_processes=true", defaultArgs, StringComparer.Ordinal);
        True(ConsoleReport.ProcessScopeLine(captureAllProcesses: false).Contains("without being decrypted", StringComparison.Ordinal));

        var all = CaptureOptions.Parse(["--capture-all-processes"]);
        True(all.CaptureAllProcesses);
        Contains(MitmdumpProcess.BuildArguments(all, paths, session), "capture_all_processes=true");
        True(ConsoleReport.ProcessScopeLine(captureAllProcesses: true).Contains("WARNING", StringComparison.Ordinal));
        True(CaptureOptions.Usage("app").Contains("--capture-all-processes", StringComparison.Ordinal));
    }

    [Fact]
    public void StopCommandParses()
    {
        var options = CaptureOptions.Parse(["stop"]);
        Equal("stop", options.Command);
    }

    [Fact]
    public void AnalysisOptionsDefaultOffAndParseFlags()
    {
        var enabled = CaptureOptions.Parse([
            "--decode-osc",
        "--store-osc-values",
        "--photon-metadata",
        "--unity-metadata",
        "--raw-udp-capture",
        "--raw-udp-ports",
        "27002,9000-9001",
        "--no-analysis-prompts",
    ]);
        Equal(true, enabled.DecodeOsc);
        True(enabled.StoreOscValues);
        Equal(true, enabled.PhotonMetadata);
        Equal(true, enabled.UnityMetadata);
        Equal(true, enabled.RawUdpCapture);
        Equal("27002,9000-9001", enabled.RawUdpPorts);
        True(enabled.NoAnalysisPrompts);

        var packetOnly = CaptureOptions.Parse(["--packet-only"]);
        True(packetOnly.PacketOnly);
        Equal(true, packetOnly.RawUdpCapture);

        var disabled = CaptureOptions.Parse([
            "--mode",
        "regular",
        "--no-decode-osc",
        "--no-photon-metadata",
        "--no-unity-metadata",
        "--no-raw-udp-capture",
        "--mitm-allow-hosts",
        "",
        "--mitm-ignore-hosts",
        "",
    ]);
        Equal(false, disabled.DecodeOsc);
        Equal(false, disabled.PhotonMetadata);
        Equal(false, disabled.UnityMetadata);
        Equal(false, disabled.RawUdpCapture);
        Equal("", disabled.MitmAllowHosts);
        Equal("", disabled.MitmIgnoreHosts);
    }

    [Fact]
    public void LocalModeIsRejected()
    {
        Throws(() => CaptureOptions.Parse(["--mode", "local"]));
        Throws(() => CaptureOptions.Parse(["--local-target", "VRChat.exe"]));
    }

    [Fact]
    public void RunningVrchatWarnsWithoutBlocking()
    {
        True(CaptureApp.ShouldWarnAboutRunningVrChat(CaptureOptions.Parse([]), vrchatRunning: true));
        False(CaptureApp.ShouldWarnAboutRunningVrChat(CaptureOptions.Parse([]), vrchatRunning: false));
        False(CaptureApp.ShouldWarnAboutRunningVrChat(CaptureOptions.Parse(["--packet-only"]), vrchatRunning: true));
        True(ConsoleReport.ReadyActionLine(vrchatAlreadyRunning: true).Contains("already running", StringComparison.Ordinal));
        True(ConsoleReport.ReadyActionLine(vrchatAlreadyRunning: false).Contains("Launch VRChat", StringComparison.Ordinal));
    }

    [Fact]
    public void PacketOnlyImpliesRawUdp()
    {
        var options = CaptureOptions.Parse(["--packet-only", "--decode-osc", "--photon-metadata"]);
        True(options.PacketOnly);
        Equal(true, options.RawUdpCapture);
        Equal(true, options.DecodeOsc);
        Equal(true, options.PhotonMetadata);
    }

    [Fact]
    public void RawUdpOptionsParsePorts()
    {
        var options = RawUdpCaptureOptions.Parse([
            "--capture-dir",
        "C:\\capture",
        "--ports",
        "27002,9000-9001",
        "--parent-pid",
        "1234",
    ]);
        Equal("27002,9000-9001", options.Ports);
        Equal(1234, options.ParentPid);
        IReadOnlyList<int> ports = RawUdpCaptureOptions.ParsePorts(options.Ports);
        Equal(3, ports.Count);
        Contains(ports, 27002);
        Contains(ports, 9000);
        Contains(ports, 9001);

        string filter = RawUdpCaptureOptions.BuildWinDivertFilter(ports);
        True(filter.Contains("udp.SrcPort == 27002", StringComparison.Ordinal));
        True(filter.Contains("udp.DstPort == 9001", StringComparison.Ordinal));

        byte[] packet = SyntheticPacket.Create(4, 0);
        UdpPacketInfo parsed = IsType<UdpPacketInfo>(UdpPacketParser.TryParse(packet));
        using var record = new PacketRecordBuffer();
        record.Prepare(packet, parsed, default, 1, DateTimeOffset.UnixEpoch);
        False(record.WrittenMemory.Span.Contains((byte)'\n'));
    }

    [Fact]
    public void RawUdpArgumentsIncludeParentPid()
    {
        var session = new CaptureSession
        {
            CaptureDir = "C:\\capture",
        };
        var analysis = new AnalysisOptions
        {
            RawUdpPorts = "27002,9000-9001",
        };
        IReadOnlyList<string> args = RawUdpWorkerHost.BuildArguments(session, analysis, 1234);
        Contains(args, "raw-udp-worker");
        Contains(args, "--parent-pid");
        Contains(args, "1234");
        Contains(args, "--stop-file");
        Contains(args, Path.Combine("C:\\capture", ".raw-udp.stop"));
    }

    [Fact]
    public void ParsesMatchingProcessUdpEndpoints()
    {
        const string Output = """
      Proto  Local Address          Foreign Address        State           PID
      UDP    0.0.0.0:9000           *:*                                    40224
      UDP    0.0.0.0:61465          *:*                                    40224
      UDP    [::]:5353              *:*                                    40224
      UDP    0.0.0.0:9999           *:*                                    1234
    """;

        IReadOnlyList<int> ports = UdpEndpointDiscovery.ParseNetstatUdpPorts(Output, new HashSet<int> { 40224 });

        Equal(2, ports.Count);
        Contains(ports, 9000);
        Contains(ports, 61465);
    }

    [Fact]
    public void ParsesIpv4DatagramsAndWritesPcap()
    {
        byte[] packet = BuildUdpPacket([1, 2, 3, 4]);
        UdpPacketInfo info = IsType<UdpPacketInfo>(UdpPacketParser.TryParse(packet));
        Equal("127.0.0.1", new IPAddress(packet.AsSpan(info.SourceAddressOffset, 4)).ToString());
        Equal("127.0.0.1", new IPAddress(packet.AsSpan(info.DestinationAddressOffset, 4)).ToString());
        Equal(50000, info.SourcePort);
        Equal(9000, info.DestinationPort);
        Equal(4, info.PayloadLength);

        string path = Path.Combine(Path.GetTempPath(), $"vcnc-pcap-{Guid.NewGuid():N}.pcapng");
        try
        {
            using (var writer = new PcapNgWriter(path))
            {
                writer.WritePacket(packet, DateTimeOffset.UnixEpoch);
            }
            True(new FileInfo(path).Length > 48);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void CertificateRemovalRequiresSessionOwnership()
    {
        True(CertificateManager.ShouldRemove(new CertificateMetadata
        {
            Thumbprint = "ABC",
            InstalledBySession = true,
            RemoveOnStop = true,
        }));
        False(CertificateManager.ShouldRemove(new CertificateMetadata
        {
            Thumbprint = "ABC",
            InstalledBySession = false,
            RemoveOnStop = true,
        }));
        False(CertificateManager.ShouldRemove(metadata: null));
    }

    [Fact]
    public void MitmdumpArgumentsReflectOptions()
    {
        string root = Path.Combine(Path.GetTempPath(), "vcnc-tests");
        var paths = new CapturePaths(root, Path.Combine(root, "captures"));
        Equal(Path.Combine(root, "python"), paths.PythonDir);
        Equal(Path.Combine(root, "python", "capture_addon.py"), paths.AddonPath);
        var session = new CaptureSession
        {
            CaptureDir = Path.Combine(root, "captures", "one"),
        };
        IReadOnlyList<string> defaultArgs = MitmdumpProcess.BuildArguments(CaptureOptions.Parse([]), paths, session);
        Contains(defaultArgs, "regular");
        Contains(defaultArgs, "--listen-port");
        Contains(defaultArgs, "8080");
        DoesNotContain("--allow-hosts", defaultArgs, StringComparer.Ordinal);
        Contains(defaultArgs, "--ignore-hosts");

        var regularOptions = CaptureOptions.Parse(["--mode", "regular", "--listen-port", "8081", "--ignore-hosts", "example.test"]);
        IReadOnlyList<string> regular = MitmdumpProcess.BuildArguments(regularOptions, paths, session);
        Contains(regular, "regular");
        Contains(regular, "8081");
        Contains(regular, "ignore_hosts_list=example.test");
        DoesNotContain(regular, static arg => arg.StartsWith("local", StringComparison.OrdinalIgnoreCase));

        var analysis = new AnalysisOptions
        {
            DecodeOsc = true,
            StoreOscValues = false,
            PhotonMetadata = true,
            UnityMetadata = true,
        };
        IReadOnlyList<string> analysisArgs = MitmdumpProcess.BuildArguments(CaptureOptions.Parse([]), paths, session, analysis);
        Contains(analysisArgs, "decode_osc=true");
        Contains(analysisArgs, "store_osc_values=false");
        Contains(analysisArgs, "photon_metadata=true");
        Contains(analysisArgs, "unity_metadata=true");

    }

    [Fact]
    public void StopLeavesReusedMitmdumpPid()
    {
        string sessionDir = NewTempDir("vnc-stale-pid");
        using Process unrelated = StartIdleProcess();
        try
        {
            string pidFile = Path.Combine(sessionDir, MitmdumpProcess.PidFileName);
            File.WriteAllText(pidFile, unrelated.Id.ToString(System.Globalization.CultureInfo.InvariantCulture));
            File.SetLastWriteTimeUtc(pidFile, unrelated.StartTime.ToUniversalTime().AddMinutes(-5));

            MitmdumpProcess.StopForSession(sessionDir);

            False(unrelated.WaitForExit(500));
        }
        finally
        {
            ProcessTools.TryKill(unrelated);
            Directory.Delete(sessionDir, recursive: true);
        }
    }

    [Fact]
    public void StopLeavesReusedRawUdpPid()
    {
        string sessionDir = NewTempDir("vnc-stale-raw");
        using Process unrelated = StartIdleProcess();
        try
        {
            long startTicks = unrelated.StartTime.ToUniversalTime().Ticks;
            File.WriteAllText(Path.Combine(sessionDir, RawUdpWorkerHost.PidFileName), $"{unrelated.Id} {startTicks - 1}");

            RawUdpWorkerHost.StopForSession(sessionDir, analysis: null);

            False(unrelated.WaitForExit(500));
            False(File.Exists(Path.Combine(sessionDir, RawUdpWorkerHost.StopFileName)));
        }
        finally
        {
            ProcessTools.TryKill(unrelated);
            Directory.Delete(sessionDir, recursive: true);
        }
    }

    [Fact]
    public void StopKillsRecordedMitmdump()
    {
        string sessionDir = NewTempDir("vnc-live-pid");
        using Process recorded = StartIdleProcess();
        try
        {
            ProcessTools.WritePidFile(Path.Combine(sessionDir, MitmdumpProcess.PidFileName), recorded);

            MitmdumpProcess.StopForSession(sessionDir);

            True(recorded.WaitForExit(5000));
        }
        finally
        {
            ProcessTools.TryKill(recorded);
            Directory.Delete(sessionDir, recursive: true);
        }
    }

    [Fact]
    public void PidFilesIdentifyTheRecordedProcess()
    {
        string dir = NewTempDir("vnc-pid-match");
        try
        {
            using var current = Process.GetCurrentProcess();
            DateTime started = current.StartTime.ToUniversalTime();
            string pidFile = Path.Combine(dir, "test.pid");

            ProcessTools.WritePidFile(pidFile, current);
            Equal($"{current.Id} {started.Ticks}", File.ReadAllText(pidFile));
            using (Process? match = ProcessTools.OpenRecordedProcess(pidFile))
            {
                Equal(current.Id, match?.Id);
            }

            File.WriteAllText(pidFile, $"{current.Id} {started.Ticks + 1}");
            AssertProcessMissing(pidFile);

            File.WriteAllText(pidFile, current.Id.ToString(System.Globalization.CultureInfo.InvariantCulture));
            File.SetLastWriteTimeUtc(pidFile, started.AddSeconds(-1));
            AssertProcessMissing(pidFile);
            File.SetLastWriteTimeUtc(pidFile, started.AddSeconds(1));
            using (Process? legacy = ProcessTools.OpenRecordedProcess(pidFile))
            {
                Equal(current.Id, legacy?.Id);
            }

            foreach (string? bad in new[] { "", "abc", $"{current.Id} abc", "-1", $"{current.Id} -5" })
            {
                File.WriteAllText(pidFile, bad);
                AssertProcessMissing(pidFile);
            }
            AssertProcessMissing(Path.Combine(dir, "missing.pid"));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static void AssertProcessMissing(string pidFile)
    {
        using Process? process = ProcessTools.OpenRecordedProcess(pidFile);
        Null(process);
    }

    private static string NewTempDir(string prefix)
    {
        string dir = Path.Combine(Path.GetTempPath(), $"{prefix}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static Process StartIdleProcess()
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "PING.EXE"),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
        };
        foreach (string? arg in new[] { "-n", "30", "127.0.0.1" })
        {
            startInfo.ArgumentList.Add(arg);
        }
        return Process.Start(startInfo) ?? throw new InvalidOperationException("Failed to start idle process.");
    }

    private static void Throws(Action action) => ThrowsAny<ArgumentException>(action);

    private static void Contains<T>(IReadOnlyList<T> values, T expected) => Assert.Contains(expected, values);

    private static byte[] BuildUdpPacket(byte[] payload)
    {
        int totalLength = 20 + 8 + payload.Length;
        byte[] packet = new byte[totalLength];
        packet[0] = 0x45;
        packet[2] = (byte)(totalLength >> 8);
        packet[3] = (byte)totalLength;
        packet[8] = 64;
        packet[9] = 17;
        packet[12] = 127;
        packet[15] = 1;
        packet[16] = 127;
        packet[19] = 1;
        packet[20] = 0xC3;
        packet[21] = 0x50;
        packet[22] = 0x23;
        packet[23] = 0x28;
        int udpLength = 8 + payload.Length;
        packet[24] = (byte)(udpLength >> 8);
        packet[25] = (byte)udpLength;
        payload.CopyTo(packet.AsSpan(28));
        return packet;
    }

}
