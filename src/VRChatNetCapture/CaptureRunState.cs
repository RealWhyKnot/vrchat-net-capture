using System.Diagnostics;

namespace VRChatNetCapture;

internal sealed class CaptureRunState
{
    public Process? Mitmdump { get; set; }
    public Process? RawUdpWorker { get; set; }
    public PythonCommand? Python { get; set; }
    public AnalysisOptions? Analysis { get; set; }
    public bool ProxyChanged { get; set; }
}
