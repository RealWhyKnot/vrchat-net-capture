using System.Text.Json.Serialization;

namespace VRChatNetCapture;

internal sealed class SessionMetadata
{
    [JsonPropertyName("session_dir")]
    public string SessionDir { get; set; } = "";

    [JsonPropertyName("pid_file")]
    public string PidFile { get; set; } = "";

    [JsonPropertyName("session_file")]
    public string SessionFile { get; set; } = "";

    [JsonPropertyName("cert_file")]
    public string CertFile { get; set; } = "";

    [JsonPropertyName("proxy_changed")]
    public bool ProxyChanged { get; set; }

    [JsonPropertyName("mode")]
    public string Mode { get; set; } = "regular";

    [JsonPropertyName("packet_only")]
    public bool PacketOnly { get; set; }

    [JsonPropertyName("local_target")]
    public string? LocalTarget { get; set; }

    [JsonPropertyName("listen_port")]
    public int? ListenPort { get; set; }

    [JsonPropertyName("started_at")]
    public string StartedAt { get; set; } = "";

    [JsonPropertyName("mitmproxy")]
    public string? Mitmproxy { get; set; }

    [JsonPropertyName("decode_osc")]
    public bool DecodeOsc { get; set; }

    [JsonPropertyName("store_osc_values")]
    public bool StoreOscValues { get; set; }

    [JsonPropertyName("photon_metadata")]
    public bool PhotonMetadata { get; set; }

    [JsonPropertyName("unity_metadata")]
    public bool UnityMetadata { get; set; }

    [JsonPropertyName("raw_udp_capture")]
    public bool RawUdpCapture { get; set; }

    [JsonPropertyName("raw_udp_ports")]
    public string RawUdpPorts { get; set; } = "";

    [JsonPropertyName("capture_all_processes")]
    public bool CaptureAllProcesses { get; set; }
}
