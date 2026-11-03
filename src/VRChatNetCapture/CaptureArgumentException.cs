namespace VRChatNetCapture;

internal sealed class CaptureArgumentException : ArgumentException
{
    private readonly string _message;

    public CaptureArgumentException() : base()
    {
        _message = base.Message;
    }

    public CaptureArgumentException(string message) : base(message)
    {
        _message = message;
    }

    public CaptureArgumentException(string message, Exception innerException) : base(message, innerException)
    {
        _message = message;
    }

    public CaptureArgumentException(string message, string parameterName)
        : base(message, parameterName)
    {
        _message = message;
    }

    public override string Message => _message;
}
