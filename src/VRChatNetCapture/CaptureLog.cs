using System.Diagnostics;

namespace VRChatNetCapture;

internal static class CaptureLog
{
    public static void Info(string message) => Console.WriteLine(message);

    public static void Error(string message) => Console.Error.WriteLine(message);

    public static async Task ErrorAsync(string message, CancellationToken cancellationToken) => await Console.Error.WriteLineAsync(message.AsMemory(), cancellationToken).ConfigureAwait(false);

    public static void Debug(Exception error) => System.Diagnostics.Debug.WriteLine(error);

    public static void Unhandled(Exception error) => Trace.TraceError("{0}", error);
}
