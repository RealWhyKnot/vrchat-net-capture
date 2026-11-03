namespace VRChatNetCapture;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
        ChildProcessTracker? childProcesses = null;
        try
        {
            if (args.Length > 0 && args[0].Equals("raw-udp-worker", StringComparison.OrdinalIgnoreCase))
            {
                return await RawUdpCaptureWorker.RunAsync(
                    RawUdpCaptureOptions.Parse([.. args.Skip(1)]),
                    CancellationToken.None).ConfigureAwait(false);
            }

            var options = CaptureOptions.Parse(args);
            if (!string.Equals(options.Command, "stop", StringComparison.Ordinal))
            {
                childProcesses = ChildProcessTracker.Create();
            }
            var paths = new CapturePaths(AppContext.BaseDirectory, options.CaptureRoot);
            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                cts.Cancel();
            };
            return await new CaptureApp(options, paths).RunAsync(cts.Token).ConfigureAwait(false);
        }
        catch (CaptureArgumentException ex)
        {
            await CaptureLog.ErrorAsync($"[capture] ERROR: {ex.Message}", CancellationToken.None).ConfigureAwait(false);
            return 1;
        }
        catch (OperationCanceledException)
        {
            return 130;
        }
        finally
        {
            childProcesses?.Dispose();
        }
    }

    private static void OnUnhandledException(object sender, UnhandledExceptionEventArgs args)
    {
        if (args.ExceptionObject is Exception error)
        {
            CaptureLog.Unhandled(error);
            CaptureLog.Error($"[capture] ERROR: {error.Message}");
        }
        Environment.Exit(1);
    }

    private static void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs args) => CaptureLog.Unhandled(args.Exception);
}
