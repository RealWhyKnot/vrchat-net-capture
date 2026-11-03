using System.Diagnostics;

namespace VRChatNetCapture;

internal static class UdpEndpointDiscovery
{
    private static readonly HashSet<int> ExcludedPorts = [5353];

    public static async Task<IReadOnlyList<int>> FindUdpPortsForProcessAsync(
        string processName,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        string name = Path.GetFileNameWithoutExtension(processName);
        if (string.IsNullOrWhiteSpace(name))
        {
            return [];
        }

        var pids = Process.GetProcessesByName(name).Select(process => process.Id).ToHashSet();
        if (pids.Count == 0)
        {
            return [];
        }

        ProcessResult result = await ProcessTools.RunAsync(
            "netstat.exe",
            ["-ano", "-p", "udp"],
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return result.ExitCode != 0 ? [] : ParseNetstatUdpPorts(result.Stdout, pids);
    }

    public static IReadOnlyList<int> ParseNetstatUdpPorts(string output, ISet<int> pids)
    {
        var ports = new SortedSet<int>();
        foreach (string rawLine in output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            string line = rawLine.Trim();
            if (!line.StartsWith("UDP", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string[] parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4 || !int.TryParse(parts[^1], System.Globalization.CultureInfo.InvariantCulture, out int pid) || !pids.Contains(pid))
            {
                continue;
            }

            int? port = ParseEndpointPort(parts[1]);
            if (port is > 0 and <= 65535 && !ExcludedPorts.Contains(port.Value))
            {
                ports.Add(port.Value);
            }
        }

        return [.. ports];
    }

    private static int? ParseEndpointPort(string endpoint)
    {
        int index = endpoint.LastIndexOf(':');
        return index < 0 || index == endpoint.Length - 1 ? null : int.TryParse(endpoint[(index + 1)..], System.Globalization.CultureInfo.InvariantCulture, out int port) ? port : null;
    }
}
