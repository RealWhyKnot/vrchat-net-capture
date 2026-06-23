namespace VRChatNetCapture;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.Length > 0 && args[0].Equals("raw-udp-worker", StringComparison.OrdinalIgnoreCase))
            {
                return await RawUdpCaptureWorker.RunAsync(
                    RawUdpCaptureOptions.Parse(args.Skip(1).ToArray()),
                    CancellationToken.None).ConfigureAwait(false);
            }

            var options = CaptureOptions.Parse(args);
            var paths = new CapturePaths(AppContext.BaseDirectory, options.CaptureRoot);
            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                cts.Cancel();
            };
            return await new CaptureApp(options, paths, cts.Token).RunAsync().ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return 130;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[capture] ERROR: {ex.Message}");
            return 1;
        }
    }
}
