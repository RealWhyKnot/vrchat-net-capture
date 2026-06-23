using System.Diagnostics;
using System.Reflection;
using System.Text.Json;

namespace VRChatNetCapture;

public sealed class CaptureApp
{
    private readonly CaptureOptions _options;
    private readonly CapturePaths _paths;
    private readonly CancellationToken _cancellationToken;

    public CaptureApp(CaptureOptions options, CapturePaths paths, CancellationToken cancellationToken)
    {
        _options = options;
        _paths = paths;
        _cancellationToken = cancellationToken;
    }

    public async Task<int> RunAsync()
    {
        if (_options.ShowHelp)
        {
            Console.WriteLine(CaptureOptions.Usage(AppName()));
            return 0;
        }
        if (_options.ShowVersion)
        {
            Console.WriteLine(GetVersion());
            return 0;
        }
        return _options.Command == "stop" ? Stop() : await StartAsync().ConfigureAwait(false);
    }

    public async Task<int> StartAsync()
    {
        var session = _paths.CreateSession();
        Process? mitmdump = null;
        Process? rawUdpWorker = null;
        PythonCommand? pythonForPostprocess = null;
        AnalysisOptions? analysis = null;
        var proxyChanged = false;
        Console.WriteLine($"[capture] session dir: {session.CaptureDir}");

        try
        {
            var python = await PythonResolver.FindPythonAsync(_cancellationToken).ConfigureAwait(false);
            if (python is null)
            {
                Console.Error.WriteLine("[capture] ERROR: No real Python 3 found on PATH.");
                return 1;
            }
            Console.WriteLine($"[capture] using python: {python.FileName} {string.Join(" ", python.PrefixArgs)}");
            pythonForPostprocess = python;

            if (!await PythonResolver.IsMitmproxyImportableAsync(python, _cancellationToken).ConfigureAwait(false))
            {
                Console.WriteLine("[capture] mitmproxy not installed in this Python -- installing...");
                var install = await PythonResolver.RunPythonAsync(
                    python,
                    ["-m", "pip", "install", "--user", "-r", _paths.RequirementsPath],
                    _cancellationToken).ConfigureAwait(false);
                if (install != 0)
                {
                    Console.Error.WriteLine("[capture] ERROR: pip install failed.");
                    return 1;
                }
            }

            var update = await PromptAndUpdateMitmproxyAsync(python).ConfigureAwait(false);
            if (update != 0)
            {
                Console.Error.WriteLine("[capture] ERROR: mitmproxy update failed. Re-run with --no-update-prompt to skip it.");
                return 1;
            }

            var mitmdumpPath = await PythonResolver.ResolveMitmdumpAsync(python, _cancellationToken).ConfigureAwait(false);
            if (mitmdumpPath is null)
            {
                Console.Error.WriteLine("[capture] ERROR: Cannot locate mitmdump.");
                return 1;
            }
            var version = await PythonResolver.GetMitmproxyVersionAsync(mitmdumpPath, _cancellationToken).ConfigureAwait(false);
            Console.WriteLine($"[capture] using mitmdump: {mitmdumpPath}");
            if (!string.IsNullOrWhiteSpace(version))
            {
                Console.WriteLine($"[capture] mitmproxy version: {version}");
            }
            if (_options.Mode == "local" && !PythonResolver.SupportsLocalMode(version))
            {
                Console.Error.WriteLine("[capture] ERROR: local mode requires mitmproxy 10.2 or newer.");
                return 1;
            }
            analysis = ResolveAnalysisOptions();
            PrintAnalysisState(analysis);
            if (analysis.RawUdpCapture)
            {
                rawUdpWorker = StartRawUdpWorker(session, analysis);
            }

            var cert = await CertificateManager.InitializeAsync(
                mitmdumpPath,
                session.CertificateFile,
                _options.NoCertInstall,
                _options.KeepCert,
                _cancellationToken).ConfigureAwait(false);
            PrintCertificateState(cert);

            if (_options.Mode == "regular")
            {
                Console.WriteLine("[capture] stashing current proxy settings...");
                ProxyManager.Save(session.PreviousProxyFile);
                Console.WriteLine($"[capture] setting system proxy to 127.0.0.1:{_options.ListenPort}");
                ProxyManager.SetLocalProxy(_options.ListenPort);
                proxyChanged = true;
            }
            else
            {
                Console.WriteLine($"[capture] using local capture mode for target: {_options.LocalTarget}");
            }

            var metadata = new SessionMetadata
            {
                SessionDir = session.CaptureDir,
                PidFile = session.PidFile,
                SessionFile = session.SessionFile,
                CertFile = session.CertificateFile,
                ProxyChanged = proxyChanged,
                Mode = _options.Mode,
                LocalTarget = _options.Mode == "local" ? _options.LocalTarget : null,
                ListenPort = _options.Mode == "regular" ? _options.ListenPort : null,
                StartedAt = DateTimeOffset.Now.ToString("O"),
                Mitmproxy = version,
                DecodeOsc = analysis.DecodeOsc,
                StoreOscValues = analysis.StoreOscValues,
                PhotonMetadata = analysis.PhotonMetadata,
                UnityMetadata = analysis.UnityMetadata,
                RawUdpCapture = analysis.RawUdpCapture,
                RawUdpPorts = analysis.RawUdpPorts,
            };
            JsonFiles.Write(session.SessionFile, metadata);
            JsonFiles.Write(session.LatestPointer, metadata);

            var args = BuildMitmdumpArguments(_options, _paths, session, analysis);
            Console.WriteLine("[capture] launching mitmdump...");
            mitmdump = ProcessTools.StartInteractive(mitmdumpPath, args, _paths.AppDir);
            File.WriteAllText(session.PidFile, mitmdump.Id.ToString());

            if (_options.Mode == "regular")
            {
                if (!await WaitForTcpPortAsync(_options.ListenPort, mitmdump, TimeSpan.FromSeconds(10)).ConfigureAwait(false))
                {
                    Console.Error.WriteLine($"[capture] ERROR: mitmdump did not bind 127.0.0.1:{_options.ListenPort} within 10s.");
                    TryKill(mitmdump);
                    return 1;
                }
            }
            else
            {
                await Task.Delay(TimeSpan.FromSeconds(2), _cancellationToken).ConfigureAwait(false);
                if (mitmdump.HasExited)
                {
                    Console.Error.WriteLine($"[capture] ERROR: mitmdump exited early with code {mitmdump.ExitCode}. Local mode may require an elevated shell.");
                    return 1;
                }
            }

            PrintReady(session.CaptureDir);
            await mitmdump.WaitForExitAsync(_cancellationToken).ConfigureAwait(false);
            Console.WriteLine($"[capture] mitmdump exited (code {mitmdump.ExitCode}).");
            return mitmdump.ExitCode;
        }
        finally
        {
            if (mitmdump is not null && !mitmdump.HasExited)
            {
                Console.WriteLine($"[capture] stopping mitmdump (pid {mitmdump.Id})...");
                TryKill(mitmdump);
            }
            if (rawUdpWorker is not null)
            {
                StopRawUdpWorker(rawUdpWorker, session, analysis);
            }
            if (analysis?.RawUdpCapture == true && pythonForPostprocess is not null)
            {
                RunRawUdpPostprocess(pythonForPostprocess, session.CaptureDir, analysis);
            }
            CleanupSession(session.CaptureDir, session.CaptureRoot, proxyChanged);
            Console.WriteLine($"[capture] session dir: {session.CaptureDir}");
            Console.WriteLine("[capture] done.");
        }
    }

    public int Stop()
    {
        if (!Directory.Exists(_paths.CaptureRoot))
        {
            Console.WriteLine("[capture] no captures dir -- nothing to clean up.");
            return 0;
        }
        var sessionDir = FindLatestSession(_paths.CaptureRoot, _paths.LatestPointer);
        if (sessionDir is null)
        {
            Console.WriteLine("[capture] no capture session found -- nothing to clean up.");
        }
        else
        {
            Console.WriteLine($"[capture] cleaning up {sessionDir}");
            StopMitmdumpForSession(sessionDir);
            var metadata = JsonFiles.Read<SessionMetadata>(Path.Combine(sessionDir, ".session.json"));
            CleanupSession(sessionDir, _paths.CaptureRoot, metadata?.ProxyChanged ?? File.Exists(Path.Combine(sessionDir, ".previous-proxy.json")));
        }
        StopStrayMitmdumpProcesses();
        Console.WriteLine("[capture] done.");
        return 0;
    }

    public static IReadOnlyList<string> BuildMitmdumpArguments(
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
        var args = new List<string>();
        if (options.Mode == "local")
        {
            args.AddRange(["--mode", string.IsNullOrWhiteSpace(options.LocalTarget) ? "local" : $"local:{options.LocalTarget}"]);
        }
        else
        {
            args.AddRange(["--mode", "regular", "--listen-host", "127.0.0.1", "--listen-port", options.ListenPort.ToString()]);
        }
        args.AddRange(
        [
            "-s",
            paths.AddonPath,
            "--set",
            $"capture_dir={session.CaptureDir}",
            "--set",
            $"ignore_hosts_list={options.IgnoreHosts}",
            "--set",
            $"decode_osc={BoolString(analysis.DecodeOsc)}",
            "--set",
            $"store_osc_values={BoolString(analysis.StoreOscValues)}",
            "--set",
            $"photon_metadata={BoolString(analysis.PhotonMetadata)}",
            "--set",
            $"unity_metadata={BoolString(analysis.UnityMetadata)}",
            "--set",
            "flow_detail=0",
            "-w",
            Path.Combine(session.CaptureDir, "flows.mitm"),
        ]);
        return args;
    }

    private AnalysisOptions ResolveAnalysisOptions()
    {
        var decodeOsc = ResolveOptIn(
            _options.DecodeOsc,
            "Decode observed VRChat OSC UDP datagrams? This does not bind OSC ports. [y/N] ");
        var storeOscValues = false;
        if (decodeOsc)
        {
            storeOscValues = _options.StoreOscValues ||
                ResolveOptIn(null, "Store full OSC argument values? No redacts values. [y/N] ");
        }

        var photonMetadata = ResolveOptIn(
            _options.PhotonMetadata,
            "Build proxy-observed Photon-like UDP metadata? Payload semantics are not decoded. [y/N] ");
        var unityMetadata = ResolveOptIn(
            _options.UnityMetadata,
            "Run Unity bundle metadata peeks after detected bundle downloads? No asset export. [y/N] ");
        var rawUdpCapture = ResolveOptIn(
            _options.RawUdpCapture,
            "Capture raw VRChat realtime UDP / likely Photon and OSC packets with passive WinDivert? Requires Administrator. [y/N] ");

        return new AnalysisOptions
        {
            DecodeOsc = decodeOsc,
            StoreOscValues = storeOscValues,
            PhotonMetadata = photonMetadata,
            UnityMetadata = unityMetadata,
            RawUdpCapture = rawUdpCapture,
            RawUdpPorts = _options.RawUdpPorts,
        };
    }

    private bool ResolveOptIn(bool? explicitValue, string question)
    {
        if (explicitValue.HasValue)
        {
            return explicitValue.Value;
        }
        if (_options.NoAnalysisPrompts || Console.IsInputRedirected)
        {
            return false;
        }
        Console.Write("[capture] " + question);
        var answer = Console.ReadLine();
        return !string.IsNullOrWhiteSpace(answer) && answer.StartsWith("y", StringComparison.OrdinalIgnoreCase);
    }

    private async Task<int> PromptAndUpdateMitmproxyAsync(PythonCommand python)
    {
        if (_options.NoUpdatePrompt)
        {
            return 0;
        }
        if (!File.Exists(_paths.RequirementsPath))
        {
            return 0;
        }
        if (Console.IsInputRedirected)
        {
            return 0;
        }
        Console.Write("[capture] Check for and install the latest mitmproxy now? [Y/n] ");
        var answer = Console.ReadLine();
        if (!string.IsNullOrWhiteSpace(answer) && !answer.StartsWith("y", StringComparison.OrdinalIgnoreCase))
        {
            return 0;
        }
        return await PythonResolver.RunPythonAsync(
            python,
            ["-m", "pip", "install", "--upgrade", "-r", _paths.RequirementsPath],
            _cancellationToken).ConfigureAwait(false);
    }

    private void CleanupSession(string sessionDir, string captureRoot, bool proxyChanged)
    {
        if (proxyChanged)
        {
            var previousProxy = Path.Combine(sessionDir, ".previous-proxy.json");
            var settings = JsonFiles.Read<ProxySettings>(previousProxy);
            if (settings is not null)
            {
                try
                {
                    Console.WriteLine("[capture] restoring previous proxy settings...");
                    ProxyManager.Restore(settings);
                    Console.WriteLine("[capture] proxy restored.");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[capture] WARN: proxy restore failed: {ex.Message}");
                }
            }
        }

        try
        {
            var result = CertificateManager.RemoveForSession(sessionDir, captureRoot);
            if (result.Removed)
            {
                Console.WriteLine($"[capture] removed session CA: {result.Thumbprint}");
            }
            else if (result.Reason == "other-active-session")
            {
                Console.WriteLine($"[capture] WARN: kept CA because another capture is active: {result.Thumbprint}");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[capture] WARN: certificate cleanup failed: {ex.Message}");
        }
    }

    private Process? StartRawUdpWorker(CaptureSession session, AnalysisOptions analysis)
    {
        var exe = Environment.ProcessPath ?? AppName();
        var stopFile = Path.Combine(session.CaptureDir, ".raw-udp.stop");
        if (File.Exists(stopFile))
        {
            File.Delete(stopFile);
        }
        var args = new[]
        {
            "raw-udp-worker",
            "--capture-dir",
            session.CaptureDir,
            "--ports",
            analysis.RawUdpPorts,
            "--stop-file",
            stopFile,
        };
        try
        {
            Console.WriteLine($"[capture] starting passive raw UDP capture for ports: {analysis.RawUdpPorts}");
            var process = ProcessTools.StartBackground(exe, args, _paths.AppDir, elevate: true);
            File.WriteAllText(Path.Combine(session.CaptureDir, ".raw-udp.pid"), process.Id.ToString());
            Thread.Sleep(1500);
            if (process.HasExited)
            {
                Console.Error.WriteLine("[capture] WARN: raw UDP capture worker exited early; continuing without passive packet capture.");
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

    private static void StopRawUdpWorker(Process process, CaptureSession session, AnalysisOptions? analysis)
    {
        if (process.HasExited)
        {
            return;
        }
        Console.WriteLine($"[capture] stopping raw UDP worker (pid {process.Id})...");
        var stopFile = Path.Combine(session.CaptureDir, ".raw-udp.stop");
        File.WriteAllText(stopFile, DateTimeOffset.UtcNow.ToString("O"));
        WakeRawUdpWorker(analysis);
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

    private static void WakeRawUdpWorker(AnalysisOptions? analysis)
    {
        var port = 9001;
        try
        {
            var ports = RawUdpCaptureOptions.ParsePorts(analysis?.RawUdpPorts ?? "");
            port = ports.Contains(9001) ? 9001 : ports[0];
        }
        catch
        {
        }
        try
        {
            using var udp = new System.Net.Sockets.UdpClient();
            udp.Send([0], 1, "127.0.0.1", port);
        }
        catch
        {
        }
    }

    private static void RunRawUdpPostprocess(PythonCommand python, string captureDir, AnalysisOptions analysis)
    {
        var script = Path.Combine(AppContext.BaseDirectory, "postprocess_raw_udp.py");
        if (!File.Exists(script))
        {
            return;
        }
        var args = new List<string>
        {
            script,
            "--capture-dir",
            captureDir,
        };
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

    private static async Task<bool> WaitForTcpPortAsync(int port, Process process, TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline && !process.HasExited)
        {
            try
            {
                using var client = new System.Net.Sockets.TcpClient();
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

    private static string? FindLatestSession(string captureRoot, string latestPointer)
    {
        var latest = JsonFiles.Read<SessionMetadata>(latestPointer);
        if (latest is not null && Directory.Exists(latest.SessionDir))
        {
            return latest.SessionDir;
        }
        return Directory.EnumerateDirectories(captureRoot)
            .Where(static d => File.Exists(Path.Combine(d, ".session.json")) || File.Exists(Path.Combine(d, ".previous-proxy.json")))
            .OrderByDescending(Directory.GetLastWriteTimeUtc)
            .FirstOrDefault();
    }

    private static void StopMitmdumpForSession(string sessionDir)
    {
        var pidFile = Path.Combine(sessionDir, ".mitmdump.pid");
        if (!File.Exists(pidFile))
        {
            return;
        }
        if (!int.TryParse(File.ReadAllText(pidFile).Trim(), out var pid))
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

    private static void StopStrayMitmdumpProcesses()
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

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(3000);
            }
        }
        catch
        {
        }
    }

    private static void PrintCertificateState(CertificateMetadata cert)
    {
        if (!string.IsNullOrWhiteSpace(cert.Error))
        {
            Console.Error.WriteLine($"[capture] WARN: {cert.Error}");
        }
        else if (cert.InstalledBySession)
        {
            Console.WriteLine($"[capture] CA installed for current user: {cert.Thumbprint}");
        }
        else if (cert.ExistedBefore)
        {
            Console.WriteLine($"[capture] CA already trusted for current user: {cert.Thumbprint}");
        }
    }

    private static void PrintReady(string captureDir)
    {
        Console.WriteLine();
        Console.WriteLine("=================================================================");
        Console.WriteLine(" READY. Launch VRChat now and visit the worlds you want to study.");
        Console.WriteLine($" Capture dir: {captureDir}");
        Console.WriteLine(" Press Ctrl+C in this window to stop and tear everything down.");
        Console.WriteLine("=================================================================");
        Console.WriteLine();
    }

    private static string AppName() => Path.GetFileName(Environment.ProcessPath) ?? "VRChatNetCapture";

    private static string BoolString(bool value) => value ? "true" : "false";

    private static void PrintAnalysisState(AnalysisOptions analysis)
    {
        Console.WriteLine(
            "[capture] optional analysis: " +
            $"osc={(analysis.DecodeOsc ? "on" : "off")}, " +
            $"osc_values={(analysis.StoreOscValues ? "on" : "off")}, " +
            $"photon_metadata={(analysis.PhotonMetadata ? "on" : "off")}, " +
            $"unity_metadata={(analysis.UnityMetadata ? "on" : "off")}, " +
            $"raw_udp={(analysis.RawUdpCapture ? "on" : "off")}");
    }

    private static string GetVersion()
    {
        var versionPath = Path.Combine(AppContext.BaseDirectory, "version.txt");
        if (File.Exists(versionPath))
        {
            return File.ReadAllText(versionPath).Trim();
        }
        return Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0";
    }
}
