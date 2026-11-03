using System.Text.Json.Serialization;

namespace VRChatNetCapture;

internal sealed class CertificateMetadata
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
