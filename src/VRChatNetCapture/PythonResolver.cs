namespace VRChatNetCapture;

public static class PythonResolver
{
    public static async Task<PythonCommand?> FindPythonAsync(CancellationToken cancellationToken)
    {
        var py = await ProcessTools.RunAsync("where", ["py"], hidden: true, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (py.ExitCode == 0)
        {
            var candidate = new PythonCommand { FileName = "py", PrefixArgs = ["-3"] };
            if (await IsPython3Async(candidate, cancellationToken).ConfigureAwait(false))
            {
                return candidate;
            }
        }

        var python = await ProcessTools.RunAsync("where", ["python"], hidden: true, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (python.ExitCode == 0)
        {
            foreach (var line in python.Stdout.SplitLines())
            {
                var path = line.Trim();
                if (path.Length == 0 || path.EndsWith(@"WindowsApps\python.exe", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                var candidate = new PythonCommand { FileName = path };
                if (await IsPython3Async(candidate, cancellationToken).ConfigureAwait(false))
                {
                    return candidate;
                }
            }
        }

        return null;
    }

    public static async Task<int> RunPythonAsync(PythonCommand python, IEnumerable<string> args, CancellationToken cancellationToken)
    {
        var result = await ProcessTools.RunAsync(
            python.FileName,
            python.PrefixArgs.Concat(args),
            hidden: false,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(result.Stdout))
        {
            Console.Write(result.Stdout);
        }
        if (!string.IsNullOrWhiteSpace(result.Stderr))
        {
            Console.Error.Write(result.Stderr);
        }
        return result.ExitCode;
    }

    public static async Task<bool> IsMitmproxyImportableAsync(PythonCommand python, CancellationToken cancellationToken)
    {
        var result = await ProcessTools.RunAsync(
            python.FileName,
            python.PrefixArgs.Concat(["-c", "import mitmproxy, sys; sys.exit(0)"]),
            hidden: true,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return result.ExitCode == 0;
    }

    public static async Task<string?> ResolveMitmdumpAsync(PythonCommand python, CancellationToken cancellationToken)
    {
        const string script = """
            import os
            import sys
            import sysconfig

            cands = [sysconfig.get_path("scripts")]
            try:
                cands.append(sysconfig.get_path("scripts", "nt_user"))
            except Exception:
                pass
            cands.append(os.path.join(os.path.dirname(sys.executable), "Scripts"))
            for p in cands:
                if p:
                    print(p)
            """;

        var dirs = await ProcessTools.RunAsync(
            python.FileName,
            python.PrefixArgs.Concat(["-c", script]),
            hidden: true,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        if (dirs.ExitCode == 0)
        {
            foreach (var dir in dirs.Stdout.SplitLines().Select(static l => l.Trim()).Where(static l => l.Length > 0))
            {
                foreach (var name in new[] { "mitmdump.exe", "mitmdump" })
                {
                    var candidate = Path.Combine(dir, name);
                    if (File.Exists(candidate))
                    {
                        return candidate;
                    }
                }
            }
        }

        var where = await ProcessTools.RunAsync("where", ["mitmdump"], hidden: true, cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        return where.ExitCode == 0 ? where.Stdout.SplitLines().FirstOrDefault(static l => l.Trim().Length > 0)?.Trim() : null;
    }

    public static async Task<string?> GetMitmproxyVersionAsync(string mitmdumpPath, CancellationToken cancellationToken)
    {
        var result = await ProcessTools.RunAsync(mitmdumpPath, ["--version"], hidden: true, cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            return null;
        }
        foreach (var line in result.Stdout.SplitLines().Concat(result.Stderr.SplitLines()))
        {
            if (line.StartsWith("Mitmproxy:", StringComparison.OrdinalIgnoreCase))
            {
                return line["Mitmproxy:".Length..].Trim();
            }
        }
        return null;
    }

    public static bool SupportsLocalMode(string? mitmproxyVersion)
    {
        if (string.IsNullOrWhiteSpace(mitmproxyVersion))
        {
            return false;
        }
        var parts = mitmproxyVersion.Split('.');
        if (parts.Length < 2)
        {
            return false;
        }
        return int.TryParse(parts[0], out var major)
            && int.TryParse(parts[1], out var minor)
            && (major > 10 || (major == 10 && minor >= 2));
    }

    private static async Task<bool> IsPython3Async(PythonCommand python, CancellationToken cancellationToken)
    {
        var result = await ProcessTools.RunAsync(
            python.FileName,
            python.PrefixArgs.Concat(["--version"]),
            hidden: true,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return result.ExitCode == 0 && (result.Stdout + result.Stderr).Contains("Python 3.", StringComparison.OrdinalIgnoreCase);
    }
}

internal static class StringExtensions
{
    public static IEnumerable<string> SplitLines(this string value) =>
        value.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
}
