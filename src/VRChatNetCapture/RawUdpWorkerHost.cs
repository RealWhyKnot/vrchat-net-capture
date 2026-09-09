using System.Diagnostics;
using System.Net.Sockets;

namespace VRChatNetCapture;

public static class RawUdpWorkerHost
{
    public const string PidFileName = ".raw-udp.pid";
    public const string StopFileName = ".raw-udp.stop";

    private const int WakePortFallback = 9001;

    public static Process? Start(CaptureSession session, AnalysisOptions analysis, string appDir, string appName)
    {
        if (!ProcessTools.IsAdministrator())
        {
            Console.Error.WriteLine("[capture] ERROR: passive raw UDP capture requires running VRChat Net Capture as Administrator.");
            return null;
        }

        var stopFile = Path.Combine(session.CaptureDir, StopFileName);
        if (File.Exists(stopFile))
        {
            File.Delete(stopFile);
        }

        var exe = Environment.ProcessPath ?? appName;
        var args = BuildArguments(session, analysis, Environment.ProcessId);
        try
        {
            Console.WriteLine($"[capture] starting passive raw UDP capture for ports: {analysis.RawUdpPorts}");
            var process = ProcessTools.StartBackground(exe, args, appDir);
            File.WriteAllText(Path.Combine(session.CaptureDir, PidFileName), process.Id.ToString());
            Thread.Sleep(1500);
            if (process.HasExited)
            {
                Console.Error.WriteLine($"[capture] ERROR: raw UDP capture worker exited early with code {process.ExitCode}.");
                return null;
            }
            Console.WriteLine($"[capture] raw UDP worker pid={process.Id}");
            return process;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[capture] WARN: raw UDP capture did not start: {ex.Message}");
            return null;
        }
    }

    public static IReadOnlyList<string> BuildArguments(
        CaptureSession session,
        AnalysisOptions analysis,
        int parentPid) =>
        [
            "raw-udp-worker",
            "--capture-dir", session.CaptureDir,
            "--ports", analysis.RawUdpPorts,
            "--stop-file", Path.Combine(session.CaptureDir, StopFileName),
            "--parent-pid", parentPid.ToString(),
        ];

    public static void Stop(Process process, string sessionDir, AnalysisOptions? analysis)
    {
        if (process.HasExited)
        {
            return;
        }
        Console.WriteLine($"[capture] stopping raw UDP worker (pid {process.Id})...");
        File.WriteAllText(Path.Combine(sessionDir, StopFileName), DateTimeOffset.UtcNow.ToString("O"));
        Wake(analysis);
        try
        {
            if (!process.WaitForExit(5000))
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(3000);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[capture] WARN: raw UDP worker stop failed: {ex.Message}");
        }
    }

    public static void StopForSession(string sessionDir, AnalysisOptions? analysis)
    {
        var pidPath = Path.Combine(sessionDir, PidFileName);
        if (!File.Exists(pidPath) || !int.TryParse(File.ReadAllText(pidPath).Trim(), out var pid))
        {
            return;
        }
        try
        {
            Stop(Process.GetProcessById(pid), sessionDir, analysis);
        }
        catch
        {
        }
    }

    public static void StopForAllSessions(string captureRoot)
    {
        if (!Directory.Exists(captureRoot))
        {
            return;
        }

        foreach (var sessionDir in Directory.EnumerateDirectories(captureRoot))
        {
            var metadata = JsonFiles.Read<SessionMetadata>(Path.Combine(sessionDir, ".session.json"));
            StopForSession(
                sessionDir,
                metadata is null
                    ? null
                    : new AnalysisOptions
                    {
                        RawUdpCapture = metadata.RawUdpCapture,
                        RawUdpPorts = metadata.RawUdpPorts,
                    });
        }
    }

    public static void RunPostprocess(PythonCommand python, string captureDir, AnalysisOptions analysis)
    {
        var script = Path.Combine(AppContext.BaseDirectory, "python", "postprocess_raw_udp.py");
        if (!File.Exists(script))
        {
            return;
        }

        var args = new List<string> { script, "--capture-dir", captureDir };
        if (analysis.DecodeOsc)
        {
            args.Add("--decode-osc");
        }
        if (analysis.StoreOscValues)
        {
            args.Add("--store-osc-values");
        }
        if (analysis.PhotonMetadata)
        {
            args.Add("--photon-metadata");
        }

        try
        {
            Console.WriteLine("[capture] running raw UDP postprocess...");
            var result = PythonResolver.RunPythonAsync(python, args, CancellationToken.None).GetAwaiter().GetResult();
            if (result != 0)
            {
                Console.Error.WriteLine("[capture] WARN: raw UDP postprocess failed.");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[capture] WARN: raw UDP postprocess failed: {ex.Message}");
        }
    }

    private static void Wake(AnalysisOptions? analysis)
    {
        var port = WakePortFallback;
        try
        {
            var ports = RawUdpCaptureOptions.ParsePorts(analysis?.RawUdpPorts ?? "");
            port = ports.Contains(WakePortFallback) ? WakePortFallback : ports[0];
        }
        catch
        {
        }
        try
        {
            using var udp = new UdpClient();
            udp.Send([0], 1, "127.0.0.1", port);
        }
        catch
        {
        }
    }
}
