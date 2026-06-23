using VRChatNetCapture;

var tests = new (string Name, Action Body)[]
{
    ("default options use local VRChat target", TestDefaultOptions),
    ("stop command parses", TestStopCommand),
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
    Equal("local", options.Mode);
    Equal("VRChat.exe", options.LocalTarget);
    Equal(8080, options.ListenPort);
}

static void TestStopCommand()
{
    var options = CaptureOptions.Parse(["stop"]);
    Equal("stop", options.Command);
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
    var session = new CaptureSession
    {
        CaptureDir = Path.Combine(root, "captures", "one"),
    };
    var local = CaptureApp.BuildMitmdumpArguments(CaptureOptions.Parse([]), paths, session);
    Contains(local, "local:VRChat.exe");
    False(local.Contains("--listen-port"));

    var regularOptions = CaptureOptions.Parse(["--mode", "regular", "--listen-port", "8081", "--ignore-hosts", "example.test"]);
    var regular = CaptureApp.BuildMitmdumpArguments(regularOptions, paths, session);
    Contains(regular, "regular");
    Contains(regular, "8081");
    Contains(regular, "ignore_hosts_list=example.test");
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

static void Equal<T>(T expected, T actual)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
    {
        throw new InvalidOperationException($"Expected '{expected}', got '{actual}'.");
    }
}

static void Contains(IReadOnlyList<string> values, string expected)
{
    if (!values.Contains(expected))
    {
        throw new InvalidOperationException($"Expected argument '{expected}'.");
    }
}
