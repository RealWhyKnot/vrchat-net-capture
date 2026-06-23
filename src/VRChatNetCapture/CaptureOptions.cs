using System.Globalization;

namespace VRChatNetCapture;

public sealed class CaptureOptions
{
    public string Command { get; init; } = "start";
    public string Mode { get; init; } = "local";
    public string LocalTarget { get; init; } = "VRChat.exe";
    public int ListenPort { get; init; } = 8080;
    public string IgnoreHosts { get; init; } = "";
    public bool NoCertInstall { get; init; }
    public bool KeepCert { get; init; }
    public bool NoUpdatePrompt { get; init; }
    public bool NoAnalysisPrompts { get; init; }
    public bool? DecodeOsc { get; init; }
    public bool StoreOscValues { get; init; }
    public bool? PhotonMetadata { get; init; }
    public bool? UnityMetadata { get; init; }
    public string? CaptureRoot { get; init; }
    public bool ShowHelp { get; init; }
    public bool ShowVersion { get; init; }

    public static CaptureOptions Parse(string[] args)
    {
        var options = new MutableOptions();
        var index = 0;
        if (args.Length > 0 && !args[0].StartsWith("-", StringComparison.Ordinal))
        {
            options.Command = args[0].ToLowerInvariant();
            index = 1;
        }

        while (index < args.Length)
        {
            var arg = args[index++];
            switch (arg.ToLowerInvariant())
            {
                case "-h":
                case "--help":
                case "help":
                    options.ShowHelp = true;
                    break;
                case "--version":
                    options.ShowVersion = true;
                    break;
                case "--mode":
                    options.Mode = RequireValue(args, ref index, arg).ToLowerInvariant();
                    break;
                case "--local-target":
                    options.LocalTarget = RequireValue(args, ref index, arg);
                    break;
                case "--listen-port":
                    options.ListenPort = int.Parse(RequireValue(args, ref index, arg), CultureInfo.InvariantCulture);
                    break;
                case "--ignore-hosts":
                    options.IgnoreHosts = RequireValue(args, ref index, arg);
                    break;
                case "--capture-root":
                    options.CaptureRoot = RequireValue(args, ref index, arg);
                    break;
                case "--no-cert-install":
                    options.NoCertInstall = true;
                    break;
                case "--keep-cert":
                    options.KeepCert = true;
                    break;
                case "--no-update-prompt":
                    options.NoUpdatePrompt = true;
                    break;
                case "--no-analysis-prompts":
                    options.NoAnalysisPrompts = true;
                    break;
                case "--decode-osc":
                    options.DecodeOsc = true;
                    break;
                case "--no-decode-osc":
                    options.DecodeOsc = false;
                    break;
                case "--store-osc-values":
                    options.StoreOscValues = true;
                    break;
                case "--photon-metadata":
                    options.PhotonMetadata = true;
                    break;
                case "--no-photon-metadata":
                    options.PhotonMetadata = false;
                    break;
                case "--unity-metadata":
                    options.UnityMetadata = true;
                    break;
                case "--no-unity-metadata":
                    options.UnityMetadata = false;
                    break;
                default:
                    throw new ArgumentException($"Unknown argument '{arg}'.");
            }
        }

        if (options.Command is not ("start" or "stop"))
        {
            throw new ArgumentException("Command must be 'start' or 'stop'.");
        }
        if (options.Mode is not ("local" or "regular"))
        {
            throw new ArgumentException("--mode must be 'local' or 'regular'.");
        }
        if (options.ListenPort is < 1 or > 65535)
        {
            throw new ArgumentException("--listen-port must be between 1 and 65535.");
        }

        return options.ToImmutable();
    }

    public static string Usage(string exeName) =>
        $"""
        Usage:
          {exeName} [start] [--mode local|regular] [--local-target VRChat.exe] [--listen-port 8080]
          {exeName} stop

        Defaults:
          start, --mode local, --local-target VRChat.exe

        Options:
          --ignore-hosts <hosts>     Comma-separated hosts to skip writing.
          --no-cert-install          Skip CurrentUser root CA install.
          --keep-cert                Keep a session-installed CA after stop.
          --no-update-prompt         Do not ask to update mitmproxy dependencies.
          --decode-osc               Decode observed OSC UDP datagrams.
          --store-osc-values         Store OSC argument values instead of redacting them.
          --photon-metadata          Summarize Photon-like UDP stream metadata.
          --unity-metadata           Run optional Unity bundle metadata peeks.
          --no-analysis-prompts      Do not ask optional analyzer questions.
          --capture-root <path>      Override captures directory parent.
          --version                  Print version.
          --help                     Print this help.
        """;

    private static string RequireValue(string[] args, ref int index, string option)
    {
        if (index >= args.Length)
        {
            throw new ArgumentException($"{option} requires a value.");
        }
        return args[index++];
    }

    private sealed class MutableOptions
    {
        public string Command { get; set; } = "start";
        public string Mode { get; set; } = "local";
        public string LocalTarget { get; set; } = "VRChat.exe";
        public int ListenPort { get; set; } = 8080;
        public string IgnoreHosts { get; set; } = "";
        public bool NoCertInstall { get; set; }
        public bool KeepCert { get; set; }
        public bool NoUpdatePrompt { get; set; }
        public bool NoAnalysisPrompts { get; set; }
        public bool? DecodeOsc { get; set; }
        public bool StoreOscValues { get; set; }
        public bool? PhotonMetadata { get; set; }
        public bool? UnityMetadata { get; set; }
        public string? CaptureRoot { get; set; }
        public bool ShowHelp { get; set; }
        public bool ShowVersion { get; set; }

        public CaptureOptions ToImmutable() =>
            new()
            {
                Command = Command,
                Mode = Mode,
                LocalTarget = LocalTarget,
                ListenPort = ListenPort,
                IgnoreHosts = IgnoreHosts,
                NoCertInstall = NoCertInstall,
                KeepCert = KeepCert,
                NoUpdatePrompt = NoUpdatePrompt,
                NoAnalysisPrompts = NoAnalysisPrompts,
                DecodeOsc = DecodeOsc,
                StoreOscValues = StoreOscValues,
                PhotonMetadata = PhotonMetadata,
                UnityMetadata = UnityMetadata,
                CaptureRoot = CaptureRoot,
                ShowHelp = ShowHelp,
                ShowVersion = ShowVersion,
            };
    }
}
