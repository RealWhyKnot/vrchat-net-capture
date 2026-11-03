namespace VRChatNetCapture;

internal sealed class CapturePaths
{
    public CapturePaths(string appDir, string? captureRootOverride)
    {
        AppDir = appDir;
        CaptureRoot = string.IsNullOrWhiteSpace(captureRootOverride)
            ? Path.Combine(appDir, "captures")
            : Path.GetFullPath(captureRootOverride);
        RequirementsPath = Path.Combine(appDir, "requirements.txt");
        PythonDir = Path.Combine(appDir, "python");
        AddonPath = Path.Combine(PythonDir, "capture_addon.py");
    }

    public string AppDir { get; }
    public string PythonDir { get; }
    public string CaptureRoot { get; }
    public string RequirementsPath { get; }
    public string AddonPath { get; }
    public string LatestPointer => Path.Combine(CaptureRoot, ".latest-session.json");

    public CaptureSession CreateSession()
    {
        Directory.CreateDirectory(CaptureRoot);
        string stamp = DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss", System.Globalization.CultureInfo.InvariantCulture);
        string captureDir = Path.Combine(CaptureRoot, stamp);
        Directory.CreateDirectory(captureDir);
        foreach (string? name in new[] { "bodies", "decoded", "by-host", "websockets", "streams" })
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
