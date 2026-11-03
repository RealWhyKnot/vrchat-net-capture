using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace VRChatNetCapture;

internal static class CertificateManager
{
    public static async Task<CertificateMetadata> InitializeAsync(
        string mitmdumpPath,
        string metadataPath,
        bool noCertInstall,
        bool keepCert,
        CancellationToken cancellationToken)
    {
        string certPath = GetMitmproxyCertificatePath();
        var metadata = new CertificateMetadata
        {
            SourcePath = certPath,
            Skipped = noCertInstall,
        };
        if (noCertInstall)
        {
            JsonFiles.Write(metadataPath, metadata);
            return metadata;
        }

        if (!File.Exists(certPath))
        {
            using Process generator = ProcessTools.StartInteractive(
                mitmdumpPath,
                ["--listen-host", "127.0.0.1", "--listen-port", "0", "-q"],
                AppContext.BaseDirectory);
            await Task.Delay(TimeSpan.FromSeconds(3), cancellationToken).ConfigureAwait(false);
            TryKill(generator);
        }

        if (!File.Exists(certPath))
        {
            metadata.Error = $"mitmproxy CA was not found at {certPath}";
            JsonFiles.Write(metadataPath, metadata);
            return metadata;
        }

        using X509Certificate2 cert = X509CertificateLoader.LoadCertificateFromFile(certPath);
        metadata.Thumbprint = cert.Thumbprint;
        metadata.ExistedBefore = IsInCurrentUserRoot(cert.Thumbprint);
        if (!metadata.ExistedBefore)
        {
            await InstallAsync(certPath, cancellationToken).ConfigureAwait(false);
            metadata.InstalledBySession = IsInCurrentUserRoot(cert.Thumbprint);
        }
        metadata.RemoveOnStop = metadata.InstalledBySession && !keepCert;
        JsonFiles.Write(metadataPath, metadata);
        return metadata;
    }

    public static IReadOnlyList<string> BuildInstallArguments(string certificatePath) =>
        ["-user", "-addstore", "Root", certificatePath];

    private static async Task InstallAsync(string certificatePath, CancellationToken cancellationToken)
    {
        ProcessResult result = await ProcessTools.RunAsync(
            Path.Combine(Environment.SystemDirectory, "certutil.exe"),
            BuildInstallArguments(certificatePath),
            hidden: true,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        string message = $"[capture] certutil exit_code={result.ExitCode} stdout={JsonSerializer.Serialize(result.Stdout)} stderr={JsonSerializer.Serialize(result.Stderr)}";
        if (result.ExitCode == 0)
        {
            CaptureLog.Info(message);
        }
        else
        {
            CaptureLog.Error(message);
        }
    }

    public static RemovalResult RemoveForSession(string sessionDir, string captureRoot)
    {
        string metadataPath = Path.Combine(sessionDir, ".mitmproxy-cert.json");
        CertificateMetadata? metadata = JsonFiles.Read<CertificateMetadata>(metadataPath);
        if (!ShouldRemove(metadata))
        {
            return new RemovalResult(Removed: false, "not-installed-by-session", metadata?.Thumbprint);
        }
        if (OtherActiveSessionUsesCertificate(captureRoot, sessionDir, metadata!.Thumbprint!))
        {
            return new RemovalResult(Removed: false, "other-active-session", metadata.Thumbprint);
        }

        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        X509Certificate2? cert = FindByThumbprint(store, metadata.Thumbprint!);
        if (cert is null)
        {
            return new RemovalResult(Removed: false, "already-absent", metadata.Thumbprint);
        }
        store.Remove(cert);
        return new RemovalResult(Removed: true, "removed", metadata.Thumbprint);
    }

    public static bool ShouldRemove(CertificateMetadata? metadata) =>
        metadata is { Thumbprint.Length: > 0, InstalledBySession: true, RemoveOnStop: true };

    public static string GetMitmproxyCertificatePath() =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".mitmproxy",
            "mitmproxy-ca-cert.cer");

    private static bool IsInCurrentUserRoot(string thumbprint)
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        using X509Certificate2? cert = FindByThumbprint(store, thumbprint);
        return cert is not null;
    }

    private static X509Certificate2? FindByThumbprint(X509Store store, string thumbprint)
    {
        foreach (X509Certificate2 cert in store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false))
        {
            return cert;
        }
        return null;
    }

    private static bool OtherActiveSessionUsesCertificate(string captureRoot, string currentSession, string thumbprint)
    {
        if (!Directory.Exists(captureRoot))
        {
            return false;
        }
        string currentFull = Path.GetFullPath(currentSession);
        foreach (string session in Directory.EnumerateDirectories(captureRoot))
        {
            if (string.Equals(Path.GetFullPath(session), currentFull, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            string pidFile = Path.Combine(session, ".mitmdump.pid");
            string certFile = Path.Combine(session, ".mitmproxy-cert.json");
            if (!File.Exists(pidFile) || !File.Exists(certFile))
            {
                continue;
            }
            if (!int.TryParse(File.ReadAllText(pidFile).Trim(), System.Globalization.CultureInfo.InvariantCulture, out int pid))
            {
                continue;
            }
            if (!ProcessIsAlive(pid))
            {
                continue;
            }
            CertificateMetadata? metadata = JsonFiles.Read<CertificateMetadata>(certFile);
            if (string.Equals(metadata?.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static bool ProcessIsAlive(int pid)
    {
        try
        {
            _ = Process.GetProcessById(pid);
            return true;
        }
        catch (ArgumentException ex)
        {
            Trace.TraceError("{0}", ex);
            return false;
        }
        catch (InvalidOperationException ex)
        {
            Trace.TraceError("{0}", ex);
            return false;
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
