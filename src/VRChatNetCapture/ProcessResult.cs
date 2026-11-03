namespace VRChatNetCapture;

internal sealed class ProcessResult
{
    public int ExitCode { get; init; }
    public string Stdout { get; init; } = "";
    public string Stderr { get; init; } = "";
}
