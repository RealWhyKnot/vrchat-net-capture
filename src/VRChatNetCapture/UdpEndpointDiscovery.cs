using System.Diagnostics;

namespace VRChatNetCapture;

public static class UdpEndpointDiscovery
{
    public static async Task<IReadOnlyList<int>> FindUdpPortsForProcessAsync(
        string processName,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        var name = Path.GetFileNameWithoutExtension(processName);
        if (string.IsNullOrWhiteSpace(name))
        {
            return [];
        }

        var pids = Process.GetProcessesByName(name).Select(process => process.Id).ToHashSet();
        if (pids.Count == 0)
        {
            return [];
        }

        var result = await ProcessTools.RunAsync(
            "netstat.exe",
            ["-ano", "-p", "udp"],
            cancellationToken: cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            return [];
        }

        return ParseNetstatUdpPorts(result.Stdout, pids);
    }

    public static IReadOnlyList<int> ParseNetstatUdpPorts(string output, ISet<int> pids)
    {
        var ports = new SortedSet<int>();
        foreach (var rawLine in output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Trim();
            if (!line.StartsWith("UDP", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4 || !int.TryParse(parts[^1], out var pid) || !pids.Contains(pid))
            {
                continue;
            }

            var port = ParseEndpointPort(parts[1]);
            if (port is > 0 and <= 65535)
            {
                ports.Add(port.Value);
            }
        }

        return ports.ToList();
    }

    private static int? ParseEndpointPort(string endpoint)
    {
        var index = endpoint.LastIndexOf(':');
        if (index < 0 || index == endpoint.Length - 1)
        {
            return null;
        }
        return int.TryParse(endpoint[(index + 1)..], out var port) ? port : null;
    }
}
