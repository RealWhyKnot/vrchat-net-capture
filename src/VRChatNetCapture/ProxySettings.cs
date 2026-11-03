using System.Text.Json.Serialization;

namespace VRChatNetCapture;

internal sealed class ProxySettings
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
