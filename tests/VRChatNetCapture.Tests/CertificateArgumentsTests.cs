using Xunit;

namespace VRChatNetCapture.Tests;

public sealed class CertificateArgumentsTests
{
    [Theory]
    [InlineData("capture files/capture CA.cer")]
    [InlineData("capture's/capture-ca.cer")]
    public void InstallArgumentsKeepCertificatePathAsOneLiteralArgument(string certificatePath)
    {
        IReadOnlyList<string> arguments = CertificateManager.BuildInstallArguments(certificatePath);
        Assert.Equal(["-user", "-addstore", "Root", certificatePath], arguments);
    }
}
