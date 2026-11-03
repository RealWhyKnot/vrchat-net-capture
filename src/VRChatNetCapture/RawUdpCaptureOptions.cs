using System.Globalization;

namespace VRChatNetCapture;

internal sealed class RawUdpCaptureOptions
{
    public string CaptureDir { get; init; } = "";
    public string Ports { get; init; } = "27000-27002,9000,9001";
    public string StopFile { get; init; } = "";
    public int? ParentPid { get; init; }

    public static RawUdpCaptureOptions Parse(string[] args)
    {
        string captureDir = "";
        string ports = "27000-27002,9000,9001";
        string stopFile = "";
        int? parentPid = null;
        int index = 0;
        while (index < args.Length)
        {
            string arg = args[index++];
            switch (arg.ToUpperInvariant())
            {
                case "--CAPTURE-DIR":
                    captureDir = RequireValue(args, ref index, arg);
                    break;
                case "--PORTS":
                    ports = RequireValue(args, ref index, arg);
                    break;
                case "--STOP-FILE":
                    stopFile = RequireValue(args, ref index, arg);
                    break;
                case "--PARENT-PID":
                    parentPid = ParseParentPid(RequireValue(args, ref index, arg));
                    break;
                default:
                    throw new CaptureArgumentException($"Unknown raw UDP worker argument '{arg}'.", nameof(args));
            }
        }
        if (string.IsNullOrWhiteSpace(captureDir))
        {
            throw new CaptureArgumentException("--capture-dir is required.", nameof(args));
        }
        _ = ParsePorts(ports);
        return new RawUdpCaptureOptions
        {
            CaptureDir = Path.GetFullPath(captureDir),
            Ports = ports,
            StopFile = string.IsNullOrWhiteSpace(stopFile) ? Path.Combine(Path.GetFullPath(captureDir), ".raw-udp.stop") : Path.GetFullPath(stopFile),
            ParentPid = parentPid,
        };
    }

    public static IReadOnlyList<int> ParsePorts(string ports)
    {
        var result = new SortedSet<int>();
        foreach (string rawPart in ports.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (rawPart.Contains('-', StringComparison.Ordinal))
            {
                string[] bounds = rawPart.Split('-', 2, StringSplitOptions.TrimEntries);
                int start = ParsePort(bounds[0]);
                int end = ParsePort(bounds[1]);
                if (end < start)
                {
                    throw new CaptureArgumentException($"Invalid port range '{rawPart}'.", nameof(ports));
                }
                for (int port = start; port <= end; port++)
                {
                    result.Add(port);
                }
            }
            else
            {
                result.Add(ParsePort(rawPart));
            }
        }
        return result.Count == 0 ? throw new CaptureArgumentException("At least one UDP port is required.", nameof(ports)) : [.. result];
    }

    public static string BuildWinDivertFilter(IEnumerable<int> ports)
    {
        IEnumerable<string> portTests = ports
            .Distinct()
            .Order()
            .Select(static port => $"udp.SrcPort == {port} or udp.DstPort == {port}");
        return "udp and (" + string.Join(" or ", portTests) + ")";
    }

    private static int ParsePort(string value)
    {
        return !int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int port) || port is < 1 or > 65535
            ? throw new CaptureArgumentException($"Invalid UDP port '{value}'.", nameof(value))
            : port;
    }

    private static int ParseParentPid(string value)
    {
        return !int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int pid) || pid <= 0
            ? throw new CaptureArgumentException($"Invalid parent PID '{value}'.", nameof(value))
            : pid;
    }

    private static string RequireValue(string[] args, ref int index, string option) => index >= args.Length ? throw new CaptureArgumentException($"{option} requires a value.", nameof(args)) : args[index++];
}
