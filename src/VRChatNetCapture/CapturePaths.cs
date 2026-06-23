namespace VRChatNetCapture;

public sealed class CapturePaths
{
    public CapturePaths(string appDir, string? captureRootOverride)
    {
        AppDir = appDir;
        CaptureRoot = string.IsNullOrWhiteSpace(captureRootOverride)
            ? Path.Combine(appDir, "captures")
            : Path.GetFullPath(captureRootOverride);
        RequirementsPath = Path.Combine(appDir, "requirements.txt");
        AddonPath = Path.Combine(appDir, "capture_addon.py");
    }

    public string AppDir { get; }
    public string CaptureRoot { get; }
    public string RequirementsPath { get; }
    public string AddonPath { get; }
    public string LatestPointer => Path.Combine(CaptureRoot, ".latest-session.json");

    public CaptureSession CreateSession()
    {
        Directory.CreateDirectory(CaptureRoot);
        var stamp = DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss");
        var captureDir = Path.Combine(CaptureRoot, stamp);
        Directory.CreateDirectory(captureDir);
        foreach (var name in new[] { "bodies", "decoded", "by-host", "websockets", "streams" })
        {
            Directory.CreateDirectory(Path.Combine(captureDir, name));
        }

        return new CaptureSession
        {
            CaptureRoot = CaptureRoot,
            CaptureDir = captureDir,
            PreviousProxyFile = Path.Combine(captureDir, ".previous-proxy.json"),
            LatestPointer = LatestPointer,
            PidFile = Path.Combine(captureDir, ".mitmdump.pid"),
            SessionFile = Path.Combine(captureDir, ".session.json"),
            CertificateFile = Path.Combine(captureDir, ".mitmproxy-cert.json"),
        };
    }
}
