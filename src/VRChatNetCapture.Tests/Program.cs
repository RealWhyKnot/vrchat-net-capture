using VRChatNetCapture;
using System.Text.Json;

var tests = new (string Name, Action Body)[]
{
    ("default options use regular proxy mode", TestDefaultOptions),
    ("stop command parses", TestStopCommand),
    ("analysis options parse and default off", TestAnalysisOptions),
    ("local mode is rejected", TestLocalModeRejected),
    ("running VRChat warns without blocking", TestRunningVrchatWarning),
    ("packet-only option implies raw UDP", TestPacketOnlyOptions),
    ("UDP endpoint discovery parses netstat output", TestUdpEndpointDiscovery),
    ("raw UDP worker options parse", TestRawUdpOptions),
    ("raw UDP worker args link parent process", TestRawUdpWorkerArgs),
    ("UDP parser and PCAP writer handle IPv4 datagrams", TestUdpParserAndPcapWriter),
    ("certificate removal is exact-session only", TestCertificateRemovalDecision),
    ("mitmdump args follow mode", TestMitmdumpArgs),
};

var failures = 0;
foreach (var test in tests)
{
    try
    {
        test.Body();
        Console.WriteLine($"PASS {test.Name}");
    }
    catch (Exception ex)
    {
        failures++;
        Console.Error.WriteLine($"FAIL {test.Name}: {ex.Message}");
    }
}

if (failures > 0)
{
    throw new InvalidOperationException($"{failures} test(s) failed.");
}

static void TestDefaultOptions()
{
    var options = CaptureOptions.Parse([]);
    Equal("start", options.Command);
    Equal("regular", options.Mode);
    Equal(8080, options.ListenPort);
    Equal(null, options.DecodeOsc);
    Equal(null, options.PhotonMetadata);
    Equal(null, options.UnityMetadata);
    Equal(null, options.RawUdpCapture);
    False(options.PacketOnly);
    Equal("", options.MitmAllowHosts);
    Equal("", options.MitmIgnoreHosts);
}

static void TestStopCommand()
{
    var options = CaptureOptions.Parse(["stop"]);
    Equal("stop", options.Command);
}

static void TestAnalysisOptions()
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

static void TestLocalModeRejected()
{
    Throws(() => CaptureOptions.Parse(["--mode", "local"]));
    Throws(() => CaptureOptions.Parse(["--local-target", "VRChat.exe"]));
}

static void TestRunningVrchatWarning()
{
    True(CaptureApp.ShouldWarnAboutRunningVrChat(CaptureOptions.Parse([]), vrchatRunning: true));
    False(CaptureApp.ShouldWarnAboutRunningVrChat(CaptureOptions.Parse([]), vrchatRunning: false));
    False(CaptureApp.ShouldWarnAboutRunningVrChat(CaptureOptions.Parse(["--packet-only"]), vrchatRunning: true));
    True(CaptureApp.ReadyActionLine(vrchatAlreadyRunning: true).Contains("already running", StringComparison.Ordinal));
    True(CaptureApp.ReadyActionLine(vrchatAlreadyRunning: false).Contains("Launch VRChat", StringComparison.Ordinal));
}

static void TestPacketOnlyOptions()
{
    var options = CaptureOptions.Parse(["--packet-only", "--decode-osc", "--photon-metadata"]);
    True(options.PacketOnly);
    Equal(true, options.RawUdpCapture);
    Equal(true, options.DecodeOsc);
    Equal(true, options.PhotonMetadata);
}

static void TestRawUdpOptions()
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
    var ports = RawUdpCaptureOptions.ParsePorts(options.Ports);
    Equal(3, ports.Count);
    Contains(ports, 27002);
    Contains(ports, 9000);
    Contains(ports, 9001);

    var filter = RawUdpCaptureOptions.BuildWinDivertFilter(ports);
    True(filter.Contains("udp.SrcPort == 27002", StringComparison.Ordinal));
    True(filter.Contains("udp.DstPort == 9001", StringComparison.Ordinal));

    var line = JsonSerializer.Serialize(new RawUdpPacketIndex { PacketNumber = 1 }, JsonFiles.JsonLineOptions);
    False(line.Contains('\n'));
}

static void TestRawUdpWorkerArgs()
{
    var session = new CaptureSession
    {
        CaptureDir = "C:\\capture",
    };
    var analysis = new AnalysisOptions
    {
        RawUdpPorts = "27002,9000-9001",
    };
    var args = CaptureApp.BuildRawUdpWorkerArguments(session, analysis, 1234);
    Contains(args, "raw-udp-worker");
    Contains(args, "--parent-pid");
    Contains(args, "1234");
    Contains(args, "--stop-file");
    Contains(args, Path.Combine("C:\\capture", ".raw-udp.stop"));
}

static void TestUdpEndpointDiscovery()
{
    const string output = """
      Proto  Local Address          Foreign Address        State           PID
      UDP    0.0.0.0:9000           *:*                                    40224
      UDP    0.0.0.0:61465          *:*                                    40224
      UDP    [::]:5353              *:*                                    40224
      UDP    0.0.0.0:9999           *:*                                    1234
    """;

    var ports = UdpEndpointDiscovery.ParseNetstatUdpPorts(output, new HashSet<int> { 40224 });

    Equal(2, ports.Count);
    Contains(ports, 9000);
    Contains(ports, 61465);
}

static void TestUdpParserAndPcapWriter()
{
    var packet = BuildUdpPacket([1, 2, 3, 4]);
    var info = UdpPacketParser.TryParse(packet);
    True(info is not null);
    Equal("127.0.0.1", info!.SourceAddress);
    Equal("127.0.0.1", info.DestinationAddress);
    Equal(50000, info.SourcePort);
    Equal(9000, info.DestinationPort);
    Equal(4, info.PayloadLength);

    var path = Path.Combine(Path.GetTempPath(), $"vcnc-pcap-{Guid.NewGuid():N}.pcapng");
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

static void TestCertificateRemovalDecision()
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
    False(CertificateManager.ShouldRemove(null));
}

static void TestMitmdumpArgs()
{
    var root = Path.Combine(Path.GetTempPath(), "vcnc-tests");
    var paths = new CapturePaths(root, Path.Combine(root, "captures"));
    Equal(Path.Combine(root, "python"), paths.PythonDir);
    Equal(Path.Combine(root, "python", "capture_addon.py"), paths.AddonPath);
    var session = new CaptureSession
    {
        CaptureDir = Path.Combine(root, "captures", "one"),
    };
    var defaultArgs = CaptureApp.BuildMitmdumpArguments(CaptureOptions.Parse([]), paths, session);
    Contains(defaultArgs, "regular");
    Contains(defaultArgs, "--listen-port");
    Contains(defaultArgs, "8080");
    False(defaultArgs.Contains("--allow-hosts"));
    False(defaultArgs.Contains("--ignore-hosts"));

    var regularOptions = CaptureOptions.Parse(["--mode", "regular", "--listen-port", "8081", "--ignore-hosts", "example.test"]);
    var regular = CaptureApp.BuildMitmdumpArguments(regularOptions, paths, session);
    Contains(regular, "regular");
    Contains(regular, "8081");
    Contains(regular, "ignore_hosts_list=example.test");
    False(regular.Any(static arg => arg.StartsWith("local", StringComparison.OrdinalIgnoreCase)));

    var analysis = new AnalysisOptions
    {
        DecodeOsc = true,
        StoreOscValues = false,
        PhotonMetadata = true,
        UnityMetadata = true,
    };
    var analysisArgs = CaptureApp.BuildMitmdumpArguments(CaptureOptions.Parse([]), paths, session, analysis);
    Contains(analysisArgs, "decode_osc=true");
    Contains(analysisArgs, "store_osc_values=false");
    Contains(analysisArgs, "photon_metadata=true");
    Contains(analysisArgs, "unity_metadata=true");

}

static void True(bool condition)
{
    if (!condition)
    {
        throw new InvalidOperationException("Expected true.");
    }
}

static void False(bool condition)
{
    if (condition)
    {
        throw new InvalidOperationException("Expected false.");
    }
}

static void Throws(Action action)
{
    try
    {
        action();
    }
    catch
    {
        return;
    }

    throw new InvalidOperationException("Expected exception.");
}

static void Equal<T>(T expected, T actual)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
    {
        throw new InvalidOperationException($"Expected '{expected}', got '{actual}'.");
    }
}

static void Contains<T>(IReadOnlyList<T> values, T expected)
{
    if (!values.Contains(expected))
    {
        throw new InvalidOperationException($"Expected argument '{expected}'.");
    }
}

static byte[] BuildUdpPacket(byte[] payload)
{
    var totalLength = 20 + 8 + payload.Length;
    var packet = new byte[totalLength];
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
    var udpLength = 8 + payload.Length;
    packet[24] = (byte)(udpLength >> 8);
    packet[25] = (byte)udpLength;
    payload.CopyTo(packet.AsSpan(28));
    return packet;
}
