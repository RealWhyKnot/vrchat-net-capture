using System.Reflection;

namespace VRChatNetCapture;

internal static class ConsoleReport
{
    public static string AppName() => Path.GetFileName(Environment.ProcessPath) ?? "VRChatNetCapture";

    public static string Version()
    {
        string versionPath = Path.Combine(AppContext.BaseDirectory, "version.txt");
        return File.Exists(versionPath)
            ? File.ReadAllText(versionPath).Trim()
            : Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0";
    }

    public static void CertificateState(CertificateMetadata cert)
    {
        if (!string.IsNullOrWhiteSpace(cert.Error))
        {
            CaptureLog.Error($"[capture] WARN: {cert.Error}");
        }
        else if (cert.InstalledBySession)
        {
            CaptureLog.Info($"[capture] CA installed for current user: {cert.Thumbprint}");
        }
        else if (cert.ExistedBefore)
        {
            CaptureLog.Info($"[capture] CA already trusted for current user: {cert.Thumbprint}");
        }
    }

    public static void AnalysisState(AnalysisOptions analysis)
    {
        Console.WriteLine(
            "[capture] optional analysis: " +
            $"osc={OnOff(analysis.DecodeOsc)}, " +
            $"osc_values={OnOff(analysis.StoreOscValues)}, " +
            $"photon_metadata={OnOff(analysis.PhotonMetadata)}, " +
            $"unity_metadata={OnOff(analysis.UnityMetadata)}, " +
            $"raw_udp={OnOff(analysis.RawUdpCapture)}");
    }

    public static string ProcessScopeLine(bool captureAllProcesses) =>
        captureAllProcesses
            ? "[capture] WARNING: --capture-all-processes is set; HTTPS from every program that uses the system proxy will be decrypted and saved."
            : "[capture] capturing VRChat and the programs it starts; other programs go through the proxy without being decrypted or saved.";

    public static string ReadyActionLine(bool vrchatAlreadyRunning) =>
        vrchatAlreadyRunning
            ? " READY. VRChat is already running; continue from the current session."
            : " READY. Launch VRChat now and visit the worlds you want to study.";

    public static void Ready(string captureDir, bool vrchatAlreadyRunning)
    {
        Console.WriteLine();
        Console.WriteLine("=================================================================");
        Console.WriteLine(ReadyActionLine(vrchatAlreadyRunning));
        Console.WriteLine($" Capture dir: {captureDir}");
        Console.WriteLine(" Press Ctrl+C in this window to stop and tear everything down.");
        Console.WriteLine("=================================================================");
        Console.WriteLine();
    }

    private static string OnOff(bool value) => value ? "on" : "off";
}
