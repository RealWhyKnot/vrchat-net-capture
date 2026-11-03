using System.Diagnostics;
using System.Net.Sockets;

namespace VRChatNetCapture;

internal static class MitmdumpProcess
{
    public const string PidFileName = ".mitmdump.pid";

    public static IReadOnlyList<string> BuildArguments(
        CaptureOptions options,
        CapturePaths paths,
        CaptureSession session,
        AnalysisOptions? analysis = null)
    {
        analysis ??= new AnalysisOptions
        {
            DecodeOsc = options.DecodeOsc ?? false,
            StoreOscValues = options.StoreOscValues,
            PhotonMetadata = options.PhotonMetadata ?? false,
            UnityMetadata = options.UnityMetadata ?? false,
        };

        var args = new List<string>
        {
            "--mode", "regular",
            "--listen-host", "127.0.0.1",
            "--listen-port", options.ListenPort.ToString(System.Globalization.CultureInfo.InvariantCulture),
        };

        if (!string.IsNullOrWhiteSpace(options.MitmAllowHosts))
        {
            args.AddRange(["--allow-hosts", options.MitmAllowHosts]);
        }
        else if (!string.IsNullOrWhiteSpace(options.EffectiveMitmIgnoreHosts))
        {
            args.AddRange(["--ignore-hosts", options.EffectiveMitmIgnoreHosts]);
        }

        args.AddRange(
        [
            "-s", paths.AddonPath,
            "--set", $"capture_dir={session.CaptureDir}",
            "--set", $"ignore_hosts_list={options.IgnoreHosts}",
            "--set", $"decode_osc={Flag(analysis.DecodeOsc)}",
            "--set", $"store_osc_values={Flag(analysis.StoreOscValues)}",
            "--set", $"photon_metadata={Flag(analysis.PhotonMetadata)}",
            "--set", $"unity_metadata={Flag(analysis.UnityMetadata)}",
            "--set", $"capture_all_processes={Flag(options.CaptureAllProcesses)}",
            "--set", "flow_detail=0",
        ]);
        return args;
    }

    public static async Task<bool> WaitForListenerAsync(int port, Process process, TimeSpan timeout, CancellationToken cancellationToken)
    {
        long started = Stopwatch.GetTimestamp();
        while (Stopwatch.GetElapsedTime(started) < timeout && !process.HasExited)
        {
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", port, cancellationToken).ConfigureAwait(false);
                return true;
            }
            catch (SocketException ex)
            {
                Trace.TraceError("{0}", ex);
                await Task.Delay(250, cancellationToken).ConfigureAwait(false);
            }
        }
        return false;
    }

    public static void StopForSession(string sessionDir)
    {
        using Process? process = ProcessTools.OpenRecordedProcess(Path.Combine(sessionDir, PidFileName));
        if (process is null)
        {
            return;
        }
        try
        {
            CaptureLog.Info($"[capture] killing mitmdump pid={process.Id}");
            process.Kill(entireProcessTree: true);
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            Trace.TraceError("{0}", ex);
        }
        catch (InvalidOperationException ex)
        {
            Trace.TraceError("{0}", ex);
        }
    }

    public static void StopStrayProcesses()
    {
        foreach (Process process in Process.GetProcessesByName("mitmdump"))
        {
            try
            {
                CaptureLog.Info($"[capture] killing stray mitmdump pid={process.Id}");
                process.Kill(entireProcessTree: true);
            }
            catch (System.ComponentModel.Win32Exception ex)
            {
                Trace.TraceError("{0}", ex);
            }
            catch (InvalidOperationException ex)
            {
                Trace.TraceError("{0}", ex);
            }
        }
    }

    private static string Flag(bool value) => value ? "true" : "false";
}
