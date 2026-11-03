namespace VRChatNetCapture;

internal static class CaptureSessionFiles
{
    public static void WriteProxySession(CaptureSession session, AnalysisOptions analysis, CaptureOptions options, bool proxyChanged, string? version)
    {
        var metadata = new SessionMetadata
        {
            SessionDir = session.CaptureDir,
            PidFile = session.PidFile,
            SessionFile = session.SessionFile,
            CertFile = session.CertificateFile,
            ProxyChanged = proxyChanged,
            Mode = options.Mode,
            PacketOnly = false,
            LocalTarget = null,
            ListenPort = options.ListenPort,
            StartedAt = DateTimeOffset.Now.ToString("O"),
            Mitmproxy = version,
            DecodeOsc = analysis.DecodeOsc,
            StoreOscValues = analysis.StoreOscValues,
            PhotonMetadata = analysis.PhotonMetadata,
            UnityMetadata = analysis.UnityMetadata,
            RawUdpCapture = analysis.RawUdpCapture,
            RawUdpPorts = analysis.RawUdpPorts,
            CaptureAllProcesses = options.CaptureAllProcesses,
        };
        JsonFiles.Write(session.SessionFile, metadata);
        JsonFiles.Write(session.LatestPointer, metadata);
    }

    public static void WritePacketSession(CaptureSession session, AnalysisOptions analysis)
    {
        var metadata = new SessionMetadata
        {
            SessionDir = session.CaptureDir,
            PidFile = session.PidFile,
            SessionFile = session.SessionFile,
            CertFile = session.CertificateFile,
            ProxyChanged = false,
            Mode = "packet-only",
            PacketOnly = true,
            LocalTarget = null,
            ListenPort = null,
            StartedAt = DateTimeOffset.Now.ToString("O"),
            Mitmproxy = null,
            DecodeOsc = analysis.DecodeOsc,
            StoreOscValues = analysis.StoreOscValues,
            PhotonMetadata = analysis.PhotonMetadata,
            UnityMetadata = analysis.UnityMetadata,
            RawUdpCapture = analysis.RawUdpCapture,
            RawUdpPorts = analysis.RawUdpPorts,
        };
        JsonFiles.Write(session.SessionFile, metadata);
        JsonFiles.Write(session.LatestPointer, metadata);
    }
}
