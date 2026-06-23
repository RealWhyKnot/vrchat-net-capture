using System.Diagnostics;
using System.Text;

namespace VRChatNetCapture;

public static class ProcessTools
{
    public static async Task<ProcessResult> RunAsync(
        string fileName,
        IEnumerable<string> args,
        string? workingDirectory = null,
        bool hidden = false,
        CancellationToken cancellationToken = default)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = hidden,
        };
        if (!string.IsNullOrWhiteSpace(workingDirectory))
        {
            startInfo.WorkingDirectory = workingDirectory;
        }
        foreach (var arg in args)
        {
            startInfo.ArgumentList.Add(arg);
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException($"Failed to start {fileName}.");
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        var stdoutTask = ReadToEndAsync(process.StandardOutput, stdout, cancellationToken);
        var stderrTask = ReadToEndAsync(process.StandardError, stderr, cancellationToken);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        await Task.WhenAll(stdoutTask, stderrTask).ConfigureAwait(false);
        return new ProcessResult { ExitCode = process.ExitCode, Stdout = stdout.ToString(), Stderr = stderr.ToString() };
    }

    public static Process StartInteractive(string fileName, IEnumerable<string> args, string workingDirectory)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = false,
            RedirectStandardError = false,
        };
        foreach (var arg in args)
        {
            startInfo.ArgumentList.Add(arg);
        }
        return Process.Start(startInfo) ?? throw new InvalidOperationException($"Failed to start {fileName}.");
    }

    private static async Task ReadToEndAsync(StreamReader reader, StringBuilder output, CancellationToken cancellationToken)
    {
        var buffer = new char[4096];
        while (true)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return;
            }
            output.Append(buffer, 0, read);
        }
    }
}
