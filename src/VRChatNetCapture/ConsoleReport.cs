using System.Reflection;

namespace VRChatNetCapture;

public static class ConsoleReport
{
    public static string AppName() => Path.GetFileName(Environment.ProcessPath) ?? "VRChatNetCapture";

    public static string Version()
    {
        var versionPath = Path.Combine(AppContext.BaseDirectory, "version.txt");
        return File.Exists(versionPath)
            ? File.ReadAllText(versionPath).Trim()
            : Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0";
    }

    public static void CertificateState(CertificateMetadata cert)
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
