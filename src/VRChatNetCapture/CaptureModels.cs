using System.Text.Json.Serialization;

namespace VRChatNetCapture;

public sealed class ProxySettings
{
    [JsonPropertyName("ProxyEnable")]
    public int ProxyEnable { get; set; }

    [JsonPropertyName("ProxyServer")]
    public string? ProxyServer { get; set; }

    [JsonPropertyName("ProxyOverride")]
    public string? ProxyOverride { get; set; }

    [JsonPropertyName("AutoConfigURL")]
    public string? AutoConfigUrl { get; set; }
}

public sealed class SessionMetadata
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
    public string Mode { get; set; } = "local";

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
}

public sealed class AnalysisOptions
{
    public bool DecodeOsc { get; init; }
    public bool StoreOscValues { get; init; }
    public bool PhotonMetadata { get; init; }
    public bool UnityMetadata { get; init; }
    public bool RawUdpCapture { get; init; }
    public string RawUdpPorts { get; init; } = "";
}

public sealed class CertificateMetadata
{
    [JsonPropertyName("store")]
    public string Store { get; set; } = "CurrentUser\\Root";

    [JsonPropertyName("source_path")]
    public string SourcePath { get; set; } = "";

    [JsonPropertyName("thumbprint")]
    public string? Thumbprint { get; set; }

    [JsonPropertyName("existed_before")]
    public bool ExistedBefore { get; set; }

    [JsonPropertyName("installed_by_session")]
    public bool InstalledBySession { get; set; }

    [JsonPropertyName("remove_on_stop")]
    public bool RemoveOnStop { get; set; }

    [JsonPropertyName("skipped")]
    public bool Skipped { get; set; }

    [JsonPropertyName("error")]
    public string? Error { get; set; }
}

public sealed class CaptureSession
{
    public string CaptureRoot { get; init; } = "";
    public string CaptureDir { get; init; } = "";
    public string PreviousProxyFile { get; init; } = "";
    public string LatestPointer { get; init; } = "";
    public string PidFile { get; init; } = "";
    public string SessionFile { get; init; } = "";
    public string CertificateFile { get; init; } = "";
}

public sealed class PythonCommand
{
    public string FileName { get; init; } = "";
    public List<string> PrefixArgs { get; init; } = [];
}

public sealed class ProcessResult
{
    public int ExitCode { get; init; }
    public string Stdout { get; init; } = "";
    public string Stderr { get; init; } = "";
}
