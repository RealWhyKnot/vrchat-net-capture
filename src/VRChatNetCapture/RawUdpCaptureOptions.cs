using System.Globalization;

namespace VRChatNetCapture;

public sealed class RawUdpCaptureOptions
{
    public string CaptureDir { get; init; } = "";
    public string Ports { get; init; } = "27000-27002,9000,9001";
    public string StopFile { get; init; } = "";
    public int? ParentPid { get; init; }

    public static RawUdpCaptureOptions Parse(string[] args)
    {
        var captureDir = "";
        var ports = "27000-27002,9000,9001";
        var stopFile = "";
        int? parentPid = null;
        var index = 0;
        while (index < args.Length)
        {
            var arg = args[index++];
            switch (arg.ToLowerInvariant())
            {
                case "--capture-dir":
                    captureDir = RequireValue(args, ref index, arg);
                    break;
                case "--ports":
                    ports = RequireValue(args, ref index, arg);
                    break;
                case "--stop-file":
                    stopFile = RequireValue(args, ref index, arg);
                    break;
                case "--parent-pid":
                    parentPid = ParseParentPid(RequireValue(args, ref index, arg));
                    break;
                default:
                    throw new ArgumentException($"Unknown raw UDP worker argument '{arg}'.");
            }
        }
        if (string.IsNullOrWhiteSpace(captureDir))
        {
            throw new ArgumentException("--capture-dir is required.");
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
        foreach (var rawPart in ports.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (rawPart.Contains('-', StringComparison.Ordinal))
            {
                var bounds = rawPart.Split('-', 2, StringSplitOptions.TrimEntries);
                var start = ParsePort(bounds[0]);
                var end = ParsePort(bounds[1]);
                if (end < start)
                {
                    throw new ArgumentException($"Invalid port range '{rawPart}'.");
                }
                for (var port = start; port <= end; port++)
                {
                    result.Add(port);
                }
            }
            else
            {
                result.Add(ParsePort(rawPart));
            }
        }
        if (result.Count == 0)
        {
            throw new ArgumentException("At least one UDP port is required.");
        }
        return result.ToArray();
    }

    public static string BuildWinDivertFilter(IEnumerable<int> ports)
    {
        var portTests = ports
            .Distinct()
            .Order()
            .Select(static port => $"udp.SrcPort == {port} or udp.DstPort == {port}");
        return "udp and (" + string.Join(" or ", portTests) + ")";
    }

    private static int ParsePort(string value)
    {
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
        {
            throw new ArgumentException($"Invalid UDP port '{value}'.");
        }
        return port;
    }

    private static int ParseParentPid(string value)
    {
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var pid) || pid <= 0)
        {
            throw new ArgumentException($"Invalid parent PID '{value}'.");
        }
        return pid;
    }

    private static string RequireValue(string[] args, ref int index, string option)
    {
        if (index >= args.Length)
        {
            throw new ArgumentException($"{option} requires a value.");
        }
        return args[index++];
    }
}
