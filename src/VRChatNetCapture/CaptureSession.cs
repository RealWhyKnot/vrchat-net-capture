namespace VRChatNetCapture;

internal sealed class CaptureSession
{
    public string CaptureRoot { get; init; } = "";
    public string CaptureDir { get; init; } = "";
    public string PreviousProxyFile { get; init; } = "";
    public string LatestPointer { get; init; } = "";
    public string PidFile { get; init; } = "";
    public string SessionFile { get; init; } = "";
    public string CertificateFile { get; init; } = "";
}
