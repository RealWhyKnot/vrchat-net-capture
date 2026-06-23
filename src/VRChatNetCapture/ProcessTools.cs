using System.Diagnostics;
using System.Security.Principal;
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

    public static Process StartBackground(
        string fileName,
        IEnumerable<string> args,
        string workingDirectory,
        bool elevate = false)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            WorkingDirectory = workingDirectory,
            UseShellExecute = elevate && !IsAdministrator(),
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        if (elevate && !IsAdministrator())
        {
            startInfo.Verb = "runas";
        }
        foreach (var arg in args)
        {
            startInfo.ArgumentList.Add(arg);
        }
        return Process.Start(startInfo) ?? throw new InvalidOperationException($"Failed to start {fileName}.");
    }

    public static bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
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
