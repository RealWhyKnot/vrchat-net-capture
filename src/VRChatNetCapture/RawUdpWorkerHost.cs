using System.Diagnostics;
using System.Net.Sockets;

namespace VRChatNetCapture;

internal static class RawUdpWorkerHost
{
    public const string PidFileName = ".raw-udp.pid";
    public const string StopFileName = ".raw-udp.stop";

    private const int WakePortFallback = 9001;

    public static Process? Start(CaptureSession session, AnalysisOptions analysis, string appDir, string appName)
    {
        if (!ProcessTools.IsAdministrator())
        {
            CaptureLog.Error("[capture] ERROR: passive raw UDP capture requires running VRChat Net Capture as Administrator.");
            return null;
        }

        string stopFile = Path.Combine(session.CaptureDir, StopFileName);
        if (File.Exists(stopFile))
        {
            File.Delete(stopFile);
        }

        string exe = Environment.ProcessPath ?? appName;
        IReadOnlyList<string> args = BuildArguments(session, analysis, Environment.ProcessId);
        try
        {
            CaptureLog.Info($"[capture] starting passive raw UDP capture for ports: {analysis.RawUdpPorts}");
            Process process = ProcessTools.StartBackground(exe, args, appDir);
            ProcessTools.WritePidFile(Path.Combine(session.CaptureDir, PidFileName), process);
            Thread.Sleep(1500);
            if (process.HasExited)
            {
                CaptureLog.Error($"[capture] ERROR: raw UDP capture worker exited early with code {process.ExitCode}.");
                return null;
            }
            CaptureLog.Info($"[capture] raw UDP worker pid={process.Id}");
            return process;
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            CaptureLog.Error($"[capture] WARN: raw UDP capture did not start: {ex.Message}");
            return null;
        }
        catch (InvalidOperationException ex)
        {
            CaptureLog.Error($"[capture] WARN: raw UDP capture did not start: {ex.Message}");
            return null;
        }
        catch (IOException ex)
        {
            CaptureLog.Error($"[capture] WARN: raw UDP capture did not start: {ex.Message}");
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
            "--parent-pid", parentPid.ToString(System.Globalization.CultureInfo.InvariantCulture),
        ];

    public static void Stop(Process process, string sessionDir, AnalysisOptions? analysis)
    {
        if (process.HasExited)
        {
            return;
        }
        CaptureLog.Info($"[capture] stopping raw UDP worker (pid {process.Id})...");
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
        catch (System.ComponentModel.Win32Exception ex)
        {
            CaptureLog.Error($"[capture] WARN: raw UDP worker stop failed: {ex.Message}");
        }
        catch (InvalidOperationException ex)
        {
            CaptureLog.Error($"[capture] WARN: raw UDP worker stop failed: {ex.Message}");
        }
        catch (IOException ex)
        {
            CaptureLog.Error($"[capture] WARN: raw UDP worker stop failed: {ex.Message}");
        }
    }

    public static void StopForSession(string sessionDir, AnalysisOptions? analysis)
    {
        using Process? process = ProcessTools.OpenRecordedProcess(Path.Combine(sessionDir, PidFileName));
        if (process is null)
        {
            return;
        }
        try
        {
            Stop(process, sessionDir, analysis);
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            Trace.TraceError("{0}", ex);
        }
        catch (InvalidOperationException ex)
        {
            Trace.TraceError("{0}", ex);
        }
        catch (IOException ex)
        {
            Trace.TraceError("{0}", ex);
        }
    }

    public static void StopForAllSessions(string captureRoot)
    {
        if (!Directory.Exists(captureRoot))
        {
            return;
        }

        foreach (string sessionDir in Directory.EnumerateDirectories(captureRoot))
        {
            SessionMetadata? metadata = JsonFiles.Read<SessionMetadata>(Path.Combine(sessionDir, ".session.json"));
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

    public static async Task RunPostprocessAsync(PythonCommand python, string captureDir, AnalysisOptions analysis, CancellationToken cancellationToken)
    {
        string script = Path.Combine(AppContext.BaseDirectory, "python", "postprocess_raw_udp.py");
        if (!File.Exists(script))
        {
            return;
        }

        var args = new List<string> { "-I", script, "--capture-dir", captureDir };
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
            CaptureLog.Info("[capture] running raw UDP postprocess...");
            int result = await PythonResolver.RunPythonAsync(python, args, cancellationToken);
            if (result != 0)
            {
                await CaptureLog.ErrorAsync("[capture] WARN: raw UDP postprocess failed.", CancellationToken.None).ConfigureAwait(false);
            }
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            await CaptureLog.ErrorAsync($"[capture] WARN: raw UDP postprocess failed: {ex.Message}", CancellationToken.None).ConfigureAwait(false);
        }
        catch (InvalidOperationException ex)
        {
            await CaptureLog.ErrorAsync($"[capture] WARN: raw UDP postprocess failed: {ex.Message}", CancellationToken.None).ConfigureAwait(false);
        }
        catch (IOException ex)
        {
            await CaptureLog.ErrorAsync($"[capture] WARN: raw UDP postprocess failed: {ex.Message}", CancellationToken.None).ConfigureAwait(false);
        }
    }

    private static void Wake(AnalysisOptions? analysis)
    {
        int port = WakePortFallback;
        try
        {
            IReadOnlyList<int> ports = RawUdpCaptureOptions.ParsePorts(analysis?.RawUdpPorts ?? "");
            port = ports.Contains(WakePortFallback) ? WakePortFallback : ports[0];
        }
        catch (ArgumentException ex)
        {
            Trace.TraceError("{0}", ex);
        }
        catch (SocketException ex)
        {
            Trace.TraceError("{0}", ex);
        }
        try
        {
            using var udp = new UdpClient();
            udp.Send([0], 1, "127.0.0.1", port);
        }
        catch (ArgumentException ex)
        {
            Trace.TraceError("{0}", ex);
        }
        catch (SocketException ex)
        {
            Trace.TraceError("{0}", ex);
        }
    }
}
