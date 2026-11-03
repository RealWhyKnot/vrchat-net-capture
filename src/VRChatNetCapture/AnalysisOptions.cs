namespace VRChatNetCapture;

internal sealed class AnalysisOptions
{
    public bool DecodeOsc { get; init; }
    public bool StoreOscValues { get; init; }
    public bool PhotonMetadata { get; init; }
    public bool UnityMetadata { get; init; }
    public bool RawUdpCapture { get; init; }
    public string RawUdpPorts { get; init; } = "";
}
