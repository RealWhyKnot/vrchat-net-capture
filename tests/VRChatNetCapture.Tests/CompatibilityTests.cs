using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using Xunit;

namespace VRChatNetCapture.Tests;

public sealed class CompatibilityTests
{
    [Theory]
    [InlineData("START", "REGULAR", "start")]
    [InlineData("Stop", "Regular", "stop")]
    public void CommandCasePreservesCanonicalValues(string command, string mode, string expected)
    {
        var options = CaptureOptions.Parse([command, "--MODE", mode]);
        Assert.Equal(expected, options.Command);
        Assert.Equal("regular", options.Mode);
    }

    [Fact]
    public void InvalidCommandKeepsItsMessageAndParameter()
    {
        CaptureArgumentException error = Assert.Throws<CaptureArgumentException>(() => CaptureOptions.Parse(["unknown"]));
        Assert.Equal("Command must be 'start' or 'stop'.", error.Message);
        Assert.Equal("args", error.ParamName);
    }

    [Fact]
    public void ProxySettingsKeepLegacyPropertyNames()
    {
        const string Json = "{\"ProxyEnable\":1,\"ProxyServer\":\"127.0.0.1:8080\",\"ProxyOverride\":\"<local>\",\"AutoConfigURL\":\"relative/pac\"}";
        ProxySettings? settings = JsonSerializer.Deserialize<ProxySettings>(Json);
        Assert.NotNull(settings);
        Assert.Equal("relative/pac", settings.AutoConfigUrl);
        using var serialized = JsonDocument.Parse(JsonSerializer.Serialize(settings, JsonFiles.Options));
        Assert.Equal("relative/pac", serialized.RootElement.GetProperty("AutoConfigURL").GetString());
        Assert.Equal(1, serialized.RootElement.GetProperty("ProxyEnable").GetInt32());
    }

    [Fact]
    public void PacketHashesStayLowercase() => Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", UdpPacketParser.Sha256Hex("abc"u8));

    [Fact]
    public void WinDivertReceiveCopiesBothNativeOutputBuffers()
    {
        MethodInfo? method = typeof(WinDivertNative).GetMethod(nameof(WinDivertNative.WinDivertRecv));
        Assert.NotNull(method);
        ParameterInfo[] parameters = method.GetParameters();
        Assert.NotNull(parameters[1].GetCustomAttribute<OutAttribute>());
        Assert.NotNull(parameters[4].GetCustomAttribute<OutAttribute>());
    }
}
