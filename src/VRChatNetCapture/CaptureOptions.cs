using System.Globalization;

namespace VRChatNetCapture;

internal sealed class CaptureOptions
{
    public string Command { get; init; } = "start";
    public string Mode { get; init; } = "regular";
    public int ListenPort { get; init; } = 8080;
    public string IgnoreHosts { get; init; } = "";
    public string MitmAllowHosts { get; init; } = "";
    public string MitmIgnoreHosts { get; init; } = "";
    public bool NoDefaultIgnoreHosts { get; init; }
    public bool CaptureAllProcesses { get; init; }
    public bool NoCertInstall { get; init; }
    public bool KeepCert { get; init; }
    public bool NoUpdatePrompt { get; init; }
    public bool NoAnalysisPrompts { get; init; }
    public bool PacketOnly { get; init; }
    public bool? DecodeOsc { get; init; }
    public bool StoreOscValues { get; init; }
    public bool? PhotonMetadata { get; init; }
    public bool? UnityMetadata { get; init; }
    public bool? RawUdpCapture { get; init; }
    public string RawUdpPorts { get; init; } = "27000-27002,9000,9001";
    public string? CaptureRoot { get; init; }
    public bool ShowHelp { get; init; }
    public bool ShowVersion { get; init; }

    public const string DefaultIgnoreHostsPattern =
        @"^([a-z0-9-]+\.)*(vrchat\.cloud|vrchat\.com|localhost\.youtube\.com):\d+$";

    public string EffectiveMitmIgnoreHosts
    {
        get
        {
            if (NoDefaultIgnoreHosts)
            {
                return MitmIgnoreHosts;
            }
            string extra = StripLeadingIgnoreCaseFlag(MitmIgnoreHosts).Trim();
            return extra.Length == 0
                ? $"(?i){DefaultIgnoreHostsPattern}"
                : $"(?i)(?:{DefaultIgnoreHostsPattern})|(?:{extra})";
        }
    }

    private static string StripLeadingIgnoreCaseFlag(string pattern) =>
        pattern.StartsWith("(?i)", StringComparison.Ordinal) ? pattern[4..] : pattern;

    public static CaptureOptions Parse(string[] args)
    {
        var options = new MutableOptions();
        int index = 0;
        if (args.Length > 0 && !args[0].StartsWith('-'))
        {
            options.Command = args[0];
            index = 1;
        }

        while (index < args.Length)
        {
            string arg = args[index++];
            if (!ParseFlag(arg, options) && !ParseValue(arg, args, ref index, options))
            {
                throw new CaptureArgumentException($"Unknown argument '{arg}'.", nameof(args));
            }
        }

        return !string.Equals(options.Command, "start", StringComparison.OrdinalIgnoreCase) && !string.Equals(options.Command, "stop", StringComparison.OrdinalIgnoreCase)
            ? throw new CaptureArgumentException("Command must be 'start' or 'stop'.", nameof(args))
            : !string.Equals(options.Mode, "regular", StringComparison.OrdinalIgnoreCase)
            ? throw new CaptureArgumentException("--mode local has been removed; only --mode regular is supported.", nameof(args))
            : options.ListenPort is < 1 or > 65535
            ? throw new CaptureArgumentException("--listen-port must be between 1 and 65535.", nameof(args))
            : options.ToImmutable();
    }

    private static bool ParseFlag(string arg, MutableOptions options)
    {
        switch (arg.ToUpperInvariant())
        {
            case "-H":
            case "--HELP":
            case "HELP":
                options.ShowHelp = true;
                return true;
            case "--VERSION":
                options.ShowVersion = true;
                return true;
            case "--NO-DEFAULT-IGNORE-HOSTS":
                options.NoDefaultIgnoreHosts = true;
                return true;
            case "--CAPTURE-ALL-PROCESSES":
                options.CaptureAllProcesses = true;
                return true;
            case "--NO-CERT-INSTALL":
                options.NoCertInstall = true;
                return true;
            case "--KEEP-CERT":
                options.KeepCert = true;
                return true;
            case "--NO-UPDATE-PROMPT":
                options.NoUpdatePrompt = true;
                return true;
            case "--NO-ANALYSIS-PROMPTS":
                options.NoAnalysisPrompts = true;
                return true;
            case "--PACKET-ONLY":
                options.PacketOnly = true;
                options.RawUdpCapture = true;
                return true;
            default:
                return ParseAnalysisFlag(arg, options);
        }
    }

    private static bool ParseAnalysisFlag(string arg, MutableOptions options)
    {
        switch (arg.ToUpperInvariant())
        {
            case "--DECODE-OSC":
                options.DecodeOsc = true;
                return true;
            case "--NO-DECODE-OSC":
                options.DecodeOsc = false;
                return true;
            case "--STORE-OSC-VALUES":
                options.StoreOscValues = true;
                return true;
            case "--PHOTON-METADATA":
                options.PhotonMetadata = true;
                return true;
            case "--NO-PHOTON-METADATA":
                options.PhotonMetadata = false;
                return true;
            case "--UNITY-METADATA":
                options.UnityMetadata = true;
                return true;
            case "--NO-UNITY-METADATA":
                options.UnityMetadata = false;
                return true;
            case "--RAW-UDP-CAPTURE":
                options.RawUdpCapture = true;
                return true;
            case "--NO-RAW-UDP-CAPTURE":
                options.RawUdpCapture = false;
                return true;
            default:
                return false;
        }
    }

    private static bool ParseValue(string arg, string[] args, ref int index, MutableOptions options)
    {
        switch (arg.ToUpperInvariant())
        {
            case "--MODE":
                options.Mode = RequireValue(args, ref index, arg);
                return true;
            case "--LISTEN-PORT":
                options.ListenPort = int.Parse(RequireValue(args, ref index, arg), CultureInfo.InvariantCulture);
                return true;
            case "--IGNORE-HOSTS":
                options.IgnoreHosts = RequireValue(args, ref index, arg);
                return true;
            case "--MITM-IGNORE-HOSTS":
                options.MitmIgnoreHosts = RequireValue(args, ref index, arg);
                return true;
            case "--MITM-ALLOW-HOSTS":
                options.MitmAllowHosts = RequireValue(args, ref index, arg);
                return true;
            case "--CAPTURE-ROOT":
                options.CaptureRoot = RequireValue(args, ref index, arg);
                return true;
            case "--RAW-UDP-PORTS":
                options.RawUdpPorts = RequireValue(args, ref index, arg);
                return true;
            default:
                return false;
        }
    }

    public static string Usage(string exeName) =>
        $"""
        Usage:
          {exeName} [start] [--listen-port 8080]
          {exeName} start --packet-only
          {exeName} stop

        Defaults:
          start, --mode regular, --listen-port 8080

        Options:
          --mode <mode>              Capture mode. Only regular is supported.
          --listen-port <port>       Local proxy port for explicit --mode regular. Default: 8080.
          --ignore-hosts <hosts>     Comma-separated hosts to skip writing.
          --mitm-allow-hosts <rx>    mitmproxy host:port regex to actively capture.
          --mitm-ignore-hosts <rx>   Extra mitmproxy host:port regex to pass through unmodified.
          --no-default-ignore-hosts  Also intercept VRChat infrastructure and the local video
                                     resolver. Worlds and videos will fail to load.
          --capture-all-processes    Decrypt and record every program that uses the system
                                     proxy. Default: only VRChat and programs it starts.
          --no-cert-install          Skip CurrentUser root CA install.
          --keep-cert                Keep a session-installed CA after stop.
          --no-update-prompt         Do not ask to update mitmproxy dependencies.
          --packet-only              Run passive raw UDP capture without mitmproxy or CA changes.
          --decode-osc               Decode observed OSC UDP datagrams.
          --store-osc-values         Store OSC argument values instead of redacting them.
          --photon-metadata          Summarize proxy-observed Photon-like UDP metadata.
          --unity-metadata           Run optional Unity bundle metadata peeks.
          --raw-udp-capture          Capture selected UDP packets with passive WinDivert.
          --raw-udp-ports <ports>    Raw UDP port list/ranges. Default: 27000-27002,9000,9001.
          --no-analysis-prompts      Do not ask optional analyzer questions.
          --capture-root <path>      Override captures directory parent.
          --version                  Print version.
          --help                     Print this help.
        """;

    private static string RequireValue(string[] args, ref int index, string option) => index >= args.Length ? throw new CaptureArgumentException($"{option} requires a value.", nameof(args)) : args[index++];

    private sealed class MutableOptions
    {
        public string Command { get; set; } = "start";
        public string Mode { get; set; } = "regular";
        public int ListenPort { get; set; } = 8080;
        public string IgnoreHosts { get; set; } = "";
        public string MitmAllowHosts { get; set; } = "";
        public string MitmIgnoreHosts { get; set; } = "";
        public bool NoDefaultIgnoreHosts { get; set; }
        public bool CaptureAllProcesses { get; set; }
        public bool NoCertInstall { get; set; }
        public bool KeepCert { get; set; }
        public bool NoUpdatePrompt { get; set; }
        public bool NoAnalysisPrompts { get; set; }
        public bool PacketOnly { get; set; }
        public bool? DecodeOsc { get; set; }
        public bool StoreOscValues { get; set; }
        public bool? PhotonMetadata { get; set; }
        public bool? UnityMetadata { get; set; }
        public bool? RawUdpCapture { get; set; }
        public string RawUdpPorts { get; set; } = "27000-27002,9000,9001";
        public string? CaptureRoot { get; set; }
        public bool ShowHelp { get; set; }
        public bool ShowVersion { get; set; }

        public CaptureOptions ToImmutable() =>
            new()
            {
                Command = string.Equals(Command, "start", StringComparison.OrdinalIgnoreCase) ? "start" : "stop",
                Mode = "regular",
                ListenPort = ListenPort,
                IgnoreHosts = IgnoreHosts,
                MitmAllowHosts = MitmAllowHosts,
                MitmIgnoreHosts = MitmIgnoreHosts,
                NoDefaultIgnoreHosts = NoDefaultIgnoreHosts,
                CaptureAllProcesses = CaptureAllProcesses,
                NoCertInstall = NoCertInstall,
                KeepCert = KeepCert,
                NoUpdatePrompt = NoUpdatePrompt,
                NoAnalysisPrompts = NoAnalysisPrompts,
                PacketOnly = PacketOnly,
                DecodeOsc = DecodeOsc,
                StoreOscValues = StoreOscValues,
                PhotonMetadata = PhotonMetadata,
                UnityMetadata = UnityMetadata,
                RawUdpCapture = RawUdpCapture,
                RawUdpPorts = RawUdpPorts,
                CaptureRoot = CaptureRoot,
                ShowHelp = ShowHelp,
                ShowVersion = ShowVersion,
            };
    }
}
