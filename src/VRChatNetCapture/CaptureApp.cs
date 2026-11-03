using System.Diagnostics;

namespace VRChatNetCapture;

internal sealed class CaptureApp
{
    private readonly CaptureOptions _options;
    private readonly CapturePaths _paths;

    public CaptureApp(CaptureOptions options, CapturePaths paths)
    {
        _options = options;
        _paths = paths;
    }

    public async Task<int> RunAsync(CancellationToken cancellationToken)
    {
        if (_options.ShowHelp)
        {
            Console.WriteLine(CaptureOptions.Usage(ConsoleReport.AppName()));
            return 0;
        }
        if (_options.ShowVersion)
        {
            Console.WriteLine(ConsoleReport.Version());
            return 0;
        }
        return string.Equals(_options.Command, "stop", StringComparison.Ordinal) ? Stop() : await StartAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<int> StartAsync(CancellationToken cancellationToken)
    {
        if (_options.PacketOnly && !ProcessTools.IsAdministrator())
        {
            await CaptureLog.ErrorAsync("[capture] ERROR: packet-only capture requires running VRChat Net Capture as Administrator.", CancellationToken.None);
            return 1;
        }
        bool vrchatAlreadyRunning = ShouldWarnAboutRunningVrChat(_options, ProcessTools.IsRunning("VRChat"));
        if (vrchatAlreadyRunning)
        {
            await CaptureLog.ErrorAsync("[capture] WARN: VRChat is already running. Existing traffic may keep using old proxy settings; for full startup traffic, start capture before launching VRChat.", CancellationToken.None);
        }

        CaptureSession session = _paths.CreateSession();
        return _options.PacketOnly
            ? await StartPacketOnlyAsync(session, cancellationToken).ConfigureAwait(false)
            : await StartProxyAsync(session, vrchatAlreadyRunning, cancellationToken).ConfigureAwait(false);
    }

    private async Task<int> StartProxyAsync(CaptureSession session, bool vrchatAlreadyRunning, CancellationToken cancellationToken)
    {
        var state = new CaptureRunState();
        CaptureLog.Info($"[capture] session dir: {session.CaptureDir}");

        try
        {
            RuntimeInfo? runtime = await CaptureRuntime.PrepareAsync(_options, _paths, cancellationToken).ConfigureAwait(false);
            if (runtime is null)
            {
                return 1;
            }
            state.Python = runtime.Python;
            state.Analysis = await AddObservedUdpPortsAsync(ResolveAnalysisOptions(), cancellationToken).ConfigureAwait(false);
            ConsoleReport.AnalysisState(state.Analysis);
            if (state.Analysis.RawUdpCapture)
            {
                state.RawUdpWorker = RawUdpWorkerHost.Start(session, state.Analysis, _paths.AppDir, ConsoleReport.AppName());
                if (state.RawUdpWorker is null)
                {
                    return 1;
                }
            }

            CertificateMetadata cert = await CertificateManager.InitializeAsync(
                runtime.MitmdumpPath,
                session.CertificateFile,
                _options.NoCertInstall,
                _options.KeepCert,
                cancellationToken).ConfigureAwait(false);
            ConsoleReport.CertificateState(cert);

            state.ProxyChanged = ConfigureProxy(session);

            CaptureSessionFiles.WriteProxySession(session, state.Analysis, _options, state.ProxyChanged, runtime.Version);

            IReadOnlyList<string> args = MitmdumpProcess.BuildArguments(_options, _paths, session, state.Analysis);
            CaptureLog.Info("[capture] launching mitmdump...");
            state.Mitmdump = ProcessTools.StartInteractive(runtime.MitmdumpPath, args, _paths.AppDir);
            ProcessTools.WritePidFile(session.PidFile, state.Mitmdump);

            if (string.Equals(_options.Mode, "regular", StringComparison.Ordinal))
            {
                if (!await MitmdumpProcess.WaitForListenerAsync(_options.ListenPort, state.Mitmdump, TimeSpan.FromSeconds(10), cancellationToken).ConfigureAwait(false))
                {
                    await CaptureLog.ErrorAsync($"[capture] ERROR: mitmdump did not bind 127.0.0.1:{_options.ListenPort} within 10s.", CancellationToken.None);
                    ProcessTools.TryKill(state.Mitmdump);
                    return 1;
                }
            }
            ConsoleReport.Ready(session.CaptureDir, vrchatAlreadyRunning);
            return await WaitForLinkedCaptureExitAsync(state.Mitmdump, state.RawUdpWorker, session, state.Analysis, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await FinishProxyAsync(session, state, CancellationToken.None).ConfigureAwait(false);
        }
    }

    private static async Task FinishProxyAsync(CaptureSession session, CaptureRunState state, CancellationToken cancellationToken)
    {
        if (state.Mitmdump is not null && !state.Mitmdump.HasExited)
        {
            CaptureLog.Info($"[capture] stopping mitmdump (pid {state.Mitmdump.Id})...");
            ProcessTools.TryKill(state.Mitmdump);
        }
        if (state.RawUdpWorker is not null)
        {
            RawUdpWorkerHost.Stop(state.RawUdpWorker, session.CaptureDir, state.Analysis);
        }
        if (state.Analysis?.RawUdpCapture == true && state.Python is not null)
        {
            await RawUdpWorkerHost.RunPostprocessAsync(state.Python, session.CaptureDir, state.Analysis, cancellationToken);
        }
        CleanupSession(session.CaptureDir, session.CaptureRoot, state.ProxyChanged);
        CaptureLog.Info($"[capture] session dir: {session.CaptureDir}");
        CaptureLog.Info("[capture] done.");
    }

    private async Task<int> StartPacketOnlyAsync(CaptureSession session, CancellationToken cancellationToken)
    {
        Process? rawUdpWorker = null;
        PythonCommand? pythonForPostprocess = null;
        AnalysisOptions? analysis = null;
        CaptureLog.Info($"[capture] session dir: {session.CaptureDir}");

        try
        {
            pythonForPostprocess = await PythonResolver.FindPythonAsync(cancellationToken).ConfigureAwait(false);
            if (pythonForPostprocess is null)
            {
                await CaptureLog.ErrorAsync("[capture] WARN: No real Python 3 found on PATH; raw postprocess will be skipped.", CancellationToken.None);
            }
            else
            {
                Console.WriteLine(
                    $"[capture] using python for postprocess: {pythonForPostprocess.FileName} {string.Join(" ", pythonForPostprocess.PrefixArgs)}");
            }

            analysis = await AddObservedUdpPortsAsync(ResolveAnalysisOptions(forceRawUdp: true), cancellationToken).ConfigureAwait(false);
            ConsoleReport.AnalysisState(analysis);
            rawUdpWorker = RawUdpWorkerHost.Start(session, analysis, _paths.AppDir, ConsoleReport.AppName());
            if (rawUdpWorker is null)
            {
                await CaptureLog.ErrorAsync("[capture] ERROR: passive raw UDP capture did not start.", CancellationToken.None);
                return 1;
            }

            CaptureSessionFiles.WritePacketSession(session, analysis);

            CaptureLog.Info($"[capture] READY. Passive packet capture is running: {session.CaptureDir}");
            CaptureLog.Info("[capture] Press Ctrl+C to stop and run offline analysis.");
            try
            {
                await rawUdpWorker.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                CaptureLog.Info($"[capture] raw UDP worker exited (code {rawUdpWorker.ExitCode}).");
                return rawUdpWorker.ExitCode;
            }
            catch (OperationCanceledException)
            {
                return 0;
            }
        }
        finally
        {
            if (rawUdpWorker is not null)
            {
                RawUdpWorkerHost.Stop(rawUdpWorker, session.CaptureDir, analysis);
            }
            if (analysis?.RawUdpCapture == true && pythonForPostprocess is not null)
            {
                await RawUdpWorkerHost.RunPostprocessAsync(pythonForPostprocess, session.CaptureDir, analysis, CancellationToken.None);
            }
            CleanupSession(session.CaptureDir, session.CaptureRoot, proxyChanged: false);
            CaptureLog.Info($"[capture] session dir: {session.CaptureDir}");
            CaptureLog.Info("[capture] done.");
        }
    }

    private bool ConfigureProxy(CaptureSession session)
    {
        bool proxyChanged = false;
        if (string.Equals(_options.Mode, "regular", StringComparison.Ordinal))
        {
            CaptureLog.Info("[capture] stashing current proxy settings...");
            ProxyManager.Save(session.PreviousProxyFile);
            CaptureLog.Info($"[capture] setting system proxy to 127.0.0.1:{_options.ListenPort}");
            ProxyManager.SetLocalProxy(_options.ListenPort);
            proxyChanged = true;
        }
        if (!string.IsNullOrWhiteSpace(_options.MitmAllowHosts))
        {
            CaptureLog.Info($"[capture] active mitmproxy allow-hosts regex: {_options.MitmAllowHosts}");
        }
        if (!string.IsNullOrWhiteSpace(_options.EffectiveMitmIgnoreHosts))
        {
            CaptureLog.Info($"[capture] active mitmproxy ignore-hosts regex: {_options.EffectiveMitmIgnoreHosts}");
        }
        if (_options.NoDefaultIgnoreHosts)
        {
            CaptureLog.Info("[capture] WARNING: --no-default-ignore-hosts is set; VRChat world downloads and video playback will fail.");
        }
        Console.WriteLine(ConsoleReport.ProcessScopeLine(_options.CaptureAllProcesses));

        return proxyChanged;
    }

    public int Stop()
    {
        if (!Directory.Exists(_paths.CaptureRoot))
        {
            CaptureLog.Info("[capture] no captures dir -- nothing to clean up.");
            return 0;
        }
        string? sessionDir = FindLatestSession(_paths.CaptureRoot, _paths.LatestPointer);
        if (sessionDir is null)
        {
            CaptureLog.Info("[capture] no capture session found -- nothing to clean up.");
        }
        else
        {
            CaptureLog.Info($"[capture] cleaning up {sessionDir}");
            MitmdumpProcess.StopForSession(sessionDir);
            SessionMetadata? metadata = JsonFiles.Read<SessionMetadata>(Path.Combine(sessionDir, ".session.json"));
            RawUdpWorkerHost.StopForSession(
                sessionDir,
                metadata is null
                    ? null
                    : new AnalysisOptions
                    {
                        RawUdpCapture = metadata.RawUdpCapture,
                        RawUdpPorts = metadata.RawUdpPorts,
                    });
            CleanupSession(sessionDir, _paths.CaptureRoot, metadata?.ProxyChanged ?? File.Exists(Path.Combine(sessionDir, ".previous-proxy.json")));
        }
        RawUdpWorkerHost.StopForAllSessions(_paths.CaptureRoot);
        MitmdumpProcess.StopStrayProcesses();
        CaptureLog.Info("[capture] done.");
        return 0;
    }

    private AnalysisOptions ResolveAnalysisOptions(bool forceRawUdp = false)
    {
        bool decodeOsc = ResolveOptIn(
            _options.DecodeOsc,
            "Decode observed VRChat OSC UDP datagrams? This does not bind OSC ports. [y/N] ");
        bool storeOscValues = false;
        if (decodeOsc)
        {
            storeOscValues = _options.StoreOscValues ||
                ResolveOptIn(explicitValue: null, "Store full OSC argument values? No redacts values. [y/N] ");
        }

        bool photonMetadata = ResolveOptIn(
            _options.PhotonMetadata,
            "Build proxy-observed Photon-like UDP metadata? Payload semantics are not decoded. [y/N] ");
        bool unityMetadata = ResolveOptIn(
            _options.UnityMetadata,
            "Run Unity bundle metadata peeks after detected bundle downloads? No asset export. [y/N] ");
        bool rawUdpCapture = ResolveOptIn(
            _options.RawUdpCapture,
            "Capture raw VRChat realtime UDP / likely Photon and OSC packets with passive WinDivert? Requires Administrator. [y/N] ");
        if (forceRawUdp)
        {
            rawUdpCapture = true;
        }

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

    private static async Task<AnalysisOptions> AddObservedUdpPortsAsync(AnalysisOptions analysis, CancellationToken cancellationToken)
    {
        if (!analysis.RawUdpCapture)
        {
            return analysis;
        }

        IReadOnlyList<int> observedPorts = await UdpEndpointDiscovery.FindUdpPortsForProcessAsync(
            "VRChat.exe",
            cancellationToken).ConfigureAwait(false);
        if (observedPorts.Count == 0)
        {
            return analysis;
        }

        var merged = new SortedSet<int>(RawUdpCaptureOptions.ParsePorts(analysis.RawUdpPorts));
        foreach (int port in observedPorts)
        {
            merged.Add(port);
        }

        string mergedText = string.Join(",", merged);
        if (!string.Equals(mergedText, analysis.RawUdpPorts, StringComparison.Ordinal))
        {
            CaptureLog.Info($"[capture] observed VRChat UDP ports: {string.Join(",", observedPorts)}");
        }

        return new AnalysisOptions
        {
            DecodeOsc = analysis.DecodeOsc,
            StoreOscValues = analysis.StoreOscValues,
            PhotonMetadata = analysis.PhotonMetadata,
            UnityMetadata = analysis.UnityMetadata,
            RawUdpCapture = analysis.RawUdpCapture,
            RawUdpPorts = mergedText,
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
        string? answer = Console.ReadLine();
        return !string.IsNullOrWhiteSpace(answer) && (answer[0] is 'y' or 'Y');
    }

    private static void CleanupSession(string sessionDir, string captureRoot, bool proxyChanged)
    {
        if (proxyChanged)
        {
            string previousProxy = Path.Combine(sessionDir, ".previous-proxy.json");
            ProxySettings? settings = JsonFiles.Read<ProxySettings>(previousProxy);
            if (settings is not null)
            {
                try
                {
                    CaptureLog.Info("[capture] restoring previous proxy settings...");
                    ProxyManager.Restore(settings);
                    CaptureLog.Info("[capture] proxy restored.");
                }
                catch (IOException ex)
                {
                    CaptureLog.Error($"[capture] WARN: proxy restore failed: {ex.Message}");
                }
                catch (UnauthorizedAccessException ex)
                {
                    CaptureLog.Error($"[capture] WARN: proxy restore failed: {ex.Message}");
                }
                catch (System.Security.Cryptography.CryptographicException ex)
                {
                    CaptureLog.Error($"[capture] WARN: proxy restore failed: {ex.Message}");
                }
            }
        }

        try
        {
            RemovalResult result = CertificateManager.RemoveForSession(sessionDir, captureRoot);
            if (result.Removed)
            {
                CaptureLog.Info($"[capture] removed session CA: {result.Thumbprint}");
            }
            else if (string.Equals(result.Reason, "other-active-session", StringComparison.Ordinal))
            {
                CaptureLog.Info($"[capture] WARN: kept CA because another capture is active: {result.Thumbprint}");
            }
        }
        catch (IOException ex)
        {
            CaptureLog.Error($"[capture] WARN: certificate cleanup failed: {ex.Message}");
        }
        catch (UnauthorizedAccessException ex)
        {
            CaptureLog.Error($"[capture] WARN: certificate cleanup failed: {ex.Message}");
        }
        catch (System.Security.Cryptography.CryptographicException ex)
        {
            CaptureLog.Error($"[capture] WARN: certificate cleanup failed: {ex.Message}");
        }
    }

    private static async Task<int> WaitForLinkedCaptureExitAsync(
        Process mitmdump,
        Process? rawUdpWorker,
        CaptureSession session,
        AnalysisOptions? analysis, CancellationToken cancellationToken)
    {
        Task mitmdumpExit = mitmdump.WaitForExitAsync(cancellationToken);
        if (rawUdpWorker is null)
        {
            await mitmdumpExit.ConfigureAwait(false);
            CaptureLog.Info($"[capture] mitmdump exited (code {mitmdump.ExitCode}).");
            return mitmdump.ExitCode;
        }

        Task rawExit = rawUdpWorker.WaitForExitAsync(cancellationToken);
        Task completed = await Task.WhenAny(mitmdumpExit, rawExit).ConfigureAwait(false);
        if (completed == rawExit)
        {
            await rawExit.ConfigureAwait(false);
            if (rawUdpWorker.ExitCode == 0)
            {
                CaptureLog.Info("[capture] raw UDP worker stopped; stopping capture.");
            }
            else
            {
                await CaptureLog.ErrorAsync($"[capture] ERROR: raw UDP worker exited (code {rawUdpWorker.ExitCode}); stopping capture.", CancellationToken.None);
            }
            if (!mitmdump.HasExited)
            {
                CaptureLog.Info($"[capture] stopping mitmdump (pid {mitmdump.Id}) after raw UDP worker exit...");
                ProcessTools.TryKill(mitmdump);
            }
            return rawUdpWorker.ExitCode == 0 ? 0 : rawUdpWorker.ExitCode;
        }

        await mitmdumpExit.ConfigureAwait(false);
        CaptureLog.Info($"[capture] mitmdump exited (code {mitmdump.ExitCode}).");
        if (!rawUdpWorker.HasExited)
        {
            RawUdpWorkerHost.Stop(rawUdpWorker, session.CaptureDir, analysis);
        }
        return mitmdump.ExitCode;
    }

    private static string? FindLatestSession(string captureRoot, string latestPointer)
    {
        SessionMetadata? latest = JsonFiles.Read<SessionMetadata>(latestPointer);
        return latest is not null && Directory.Exists(latest.SessionDir)
            ? latest.SessionDir
            : Directory.EnumerateDirectories(captureRoot)
            .Where(static d => File.Exists(Path.Combine(d, ".session.json")) || File.Exists(Path.Combine(d, ".previous-proxy.json")))
            .OrderByDescending(Directory.GetLastWriteTimeUtc)
            .FirstOrDefault();
    }

    internal static bool ShouldWarnAboutRunningVrChat(CaptureOptions options, bool vrchatRunning) =>
        !options.PacketOnly && string.Equals(options.Mode, "regular", StringComparison.Ordinal) && vrchatRunning;
}
