namespace VRChatNetCapture;

internal static class CaptureRuntime
{
    public static async Task<RuntimeInfo?> PrepareAsync(CaptureOptions options, CapturePaths paths, CancellationToken cancellationToken)
    {
        PythonCommand? python = await PythonResolver.FindPythonAsync(cancellationToken).ConfigureAwait(false);
        if (python is null)
        {
            await CaptureLog.ErrorAsync("[capture] ERROR: No real Python 3 found on PATH.", CancellationToken.None);
            return null;
        }
        CaptureLog.Info($"[capture] using python: {python.FileName} {string.Join(" ", python.PrefixArgs)}");

        if (!await PythonResolver.IsMitmproxyImportableAsync(python, cancellationToken).ConfigureAwait(false))
        {
            CaptureLog.Info("[capture] mitmproxy not installed in this Python -- installing...");
            int install = await PythonResolver.RunPythonAsync(
                python,
                ["-m", "pip", "install", "--user", "-r", paths.RequirementsPath],
                cancellationToken).ConfigureAwait(false);
            if (install != 0)
            {
                await CaptureLog.ErrorAsync("[capture] ERROR: pip install failed.", CancellationToken.None);
                return null;
            }
        }

        int update = await PromptAndUpdateMitmproxyAsync(python, options, paths, cancellationToken).ConfigureAwait(false);
        if (update != 0)
        {
            await CaptureLog.ErrorAsync("[capture] ERROR: mitmproxy update failed. Re-run with --no-update-prompt to skip it.", CancellationToken.None);
            return null;
        }

        string? mitmdumpPath = await PythonResolver.ResolveMitmdumpAsync(python, cancellationToken).ConfigureAwait(false);
        if (mitmdumpPath is null)
        {
            await CaptureLog.ErrorAsync("[capture] ERROR: Cannot locate mitmdump.", CancellationToken.None);
            return null;
        }
        string? version = await PythonResolver.GetMitmproxyVersionAsync(mitmdumpPath, cancellationToken).ConfigureAwait(false);
        CaptureLog.Info($"[capture] using mitmdump: {mitmdumpPath}");
        if (!string.IsNullOrWhiteSpace(version))
        {
            CaptureLog.Info($"[capture] mitmproxy version: {version}");
        }
        return new RuntimeInfo(python, mitmdumpPath, version);
    }
    private static async Task<int> PromptAndUpdateMitmproxyAsync(PythonCommand python, CaptureOptions options, CapturePaths paths, CancellationToken cancellationToken)
    {
        if (options.NoUpdatePrompt)
        {
            return 0;
        }
        if (!File.Exists(paths.RequirementsPath))
        {
            return 0;
        }
        if (Console.IsInputRedirected)
        {
            return 0;
        }
        Console.Write("[capture] Check for and install the latest mitmproxy now? [Y/n] ");
        string? answer = Console.ReadLine();
        return !string.IsNullOrWhiteSpace(answer) && !(answer[0] is 'y' or 'Y')
            ? 0
            : await PythonResolver.RunPythonAsync(
            python,
            ["-m", "pip", "install", "--upgrade", "-r", paths.RequirementsPath],
            cancellationToken).ConfigureAwait(false);
    }

}
