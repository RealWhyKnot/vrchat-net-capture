using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace VRChatNetCapture;

public static class CertificateManager
{
    public static async Task<CertificateMetadata> InitializeAsync(
        string mitmdumpPath,
        string metadataPath,
        bool noCertInstall,
        bool keepCert,
        CancellationToken cancellationToken)
    {
        var certPath = GetMitmproxyCertificatePath();
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
            using var generator = ProcessTools.StartInteractive(
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

        using var cert = X509CertificateLoader.LoadCertificateFromFile(certPath);
        metadata.Thumbprint = cert.Thumbprint;
        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        metadata.ExistedBefore = FindByThumbprint(store, cert.Thumbprint) is not null;
        if (!metadata.ExistedBefore)
        {
            store.Add(cert);
            metadata.InstalledBySession = FindByThumbprint(store, cert.Thumbprint) is not null;
        }
        metadata.RemoveOnStop = metadata.InstalledBySession && !keepCert;
        JsonFiles.Write(metadataPath, metadata);
        return metadata;
    }

    public static RemovalResult RemoveForSession(string sessionDir, string captureRoot)
    {
        var metadataPath = Path.Combine(sessionDir, ".mitmproxy-cert.json");
        var metadata = JsonFiles.Read<CertificateMetadata>(metadataPath);
        if (!ShouldRemove(metadata))
        {
            return new RemovalResult(false, "not-installed-by-session", metadata?.Thumbprint);
        }
        if (OtherActiveSessionUsesCertificate(captureRoot, sessionDir, metadata!.Thumbprint!))
        {
            return new RemovalResult(false, "other-active-session", metadata.Thumbprint);
        }

        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        var cert = FindByThumbprint(store, metadata.Thumbprint!);
        if (cert is null)
        {
            return new RemovalResult(false, "already-absent", metadata.Thumbprint);
        }
        store.Remove(cert);
        return new RemovalResult(true, "removed", metadata.Thumbprint);
    }

    public static bool ShouldRemove(CertificateMetadata? metadata) =>
        metadata is { Thumbprint.Length: > 0, InstalledBySession: true, RemoveOnStop: true };

    public static string GetMitmproxyCertificatePath() =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".mitmproxy",
            "mitmproxy-ca-cert.cer");

    private static X509Certificate2? FindByThumbprint(X509Store store, string thumbprint)
    {
        foreach (var cert in store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false))
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
        var currentFull = Path.GetFullPath(currentSession);
        foreach (var session in Directory.EnumerateDirectories(captureRoot))
        {
            if (string.Equals(Path.GetFullPath(session), currentFull, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            var pidFile = Path.Combine(session, ".mitmdump.pid");
            var certFile = Path.Combine(session, ".mitmproxy-cert.json");
            if (!File.Exists(pidFile) || !File.Exists(certFile))
            {
                continue;
            }
            if (!int.TryParse(File.ReadAllText(pidFile).Trim(), out var pid))
            {
                continue;
            }
            if (!ProcessIsAlive(pid))
            {
                continue;
            }
            var metadata = JsonFiles.Read<CertificateMetadata>(certFile);
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
        catch
        {
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
        catch
        {
        }
    }
}

public readonly record struct RemovalResult(bool Removed, string Reason, string? Thumbprint);
