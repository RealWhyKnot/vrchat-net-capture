using System.Diagnostics;
using System.Net.Sockets;

namespace VRChatNetCapture;

public static class MitmdumpProcess
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
            "--listen-port", options.ListenPort.ToString(),
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
            "--set", "flow_detail=0",
        ]);
        return args;
    }

    public static async Task<bool> WaitForListenerAsync(int port, Process process, TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline && !process.HasExited)
        {
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", port).ConfigureAwait(false);
                return true;
            }
            catch
            {
                await Task.Delay(250).ConfigureAwait(false);
            }
        }
        return false;
    }

    public static void StopForSession(string sessionDir)
    {
        var pidFile = Path.Combine(sessionDir, PidFileName);
        if (!File.Exists(pidFile) || !int.TryParse(File.ReadAllText(pidFile).Trim(), out var pid))
        {
            return;
        }
        try
        {
            var process = Process.GetProcessById(pid);
            Console.WriteLine($"[capture] killing mitmdump pid={pid}");
            process.Kill(entireProcessTree: true);
        }
        catch
        {
        }
    }

    public static void StopStrayProcesses()
    {
        foreach (var process in Process.GetProcessesByName("mitmdump"))
        {
            try
            {
                Console.WriteLine($"[capture] killing stray mitmdump pid={process.Id}");
                process.Kill(entireProcessTree: true);
            }
            catch
            {
            }
        }
    }

    private static string Flag(bool value) => value ? "true" : "false";
}
