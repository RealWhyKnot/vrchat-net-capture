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

    [JsonPropertyName("local_target")]
    public string? LocalTarget { get; set; }

    [JsonPropertyName("listen_port")]
    public int? ListenPort { get; set; }

    [JsonPropertyName("started_at")]
    public string StartedAt { get; set; } = "";

    [JsonPropertyName("mitmproxy")]
    public string? Mitmproxy { get; set; }
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
