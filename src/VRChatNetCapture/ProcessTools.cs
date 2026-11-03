using System.Diagnostics;
using System.Globalization;
using System.Security.Principal;
using System.Text;

namespace VRChatNetCapture;

internal static class ProcessTools
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
        foreach (string arg in args)
        {
            startInfo.ArgumentList.Add(arg);
        }

        using Process process = Process.Start(startInfo) ?? throw new InvalidOperationException($"Failed to start {fileName}.");
        Track(process, requireTracked: false);
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        Task stdoutTask = ReadToEndAsync(process.StandardOutput, stdout, cancellationToken);
        Task stderrTask = ReadToEndAsync(process.StandardError, stderr, cancellationToken);
        try
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            await Task.WhenAll(stdoutTask, stderrTask).ConfigureAwait(false);
            return new ProcessResult { ExitCode = process.ExitCode, Stdout = stdout.ToString(), Stderr = stderr.ToString() };
        }
        finally
        {
            TryKill(process);
        }
    }

    public static Process StartInteractive(
        string fileName,
        IEnumerable<string> args,
        string workingDirectory,
        bool requireTracked = true)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = false,
            RedirectStandardError = false,
        };
        foreach (string arg in args)
        {
            startInfo.ArgumentList.Add(arg);
        }
        Process process = Process.Start(startInfo) ?? throw new InvalidOperationException($"Failed to start {fileName}.");
        Track(process, requireTracked);
        return process;
    }

    public static Process StartBackground(
        string fileName,
        IEnumerable<string> args,
        string workingDirectory,
        bool elevate = false,
        bool requireTracked = true)
    {
        if (elevate && !IsAdministrator() && requireTracked)
        {
            throw new InvalidOperationException("Tracked child processes cannot be launched through UAC elevation. Run VRChat Net Capture as Administrator.");
        }
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
        foreach (string arg in args)
        {
            startInfo.ArgumentList.Add(arg);
        }
        Process process = Process.Start(startInfo) ?? throw new InvalidOperationException($"Failed to start {fileName}.");
        Track(process, requireTracked);
        return process;
    }

    public static bool IsRunning(string processName)
    {
        try
        {
            return Process.GetProcessesByName(processName).Length > 0;
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            Trace.TraceError("{0}", ex);
            return false;
        }
        catch (InvalidOperationException ex)
        {
            Trace.TraceError("{0}", ex);
            return false;
        }
    }

    public static void WritePidFile(string path, Process process)
    {
        long? startTicks;
        try
        {
            startTicks = process.StartTime.ToUniversalTime().Ticks;
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            Trace.TraceError("{0}", ex);
            startTicks = null;
        }
        catch (InvalidOperationException ex)
        {
            Trace.TraceError("{0}", ex);
            startTicks = null;
        }
        File.WriteAllText(path, startTicks is null ? $"{process.Id}" : $"{process.Id} {startTicks}");
    }

    public static Process? OpenRecordedProcess(string pidFile)
    {
        if (!File.Exists(pidFile))
        {
            return null;
        }
        string[] fields = File.ReadAllText(pidFile).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length == 0 || !int.TryParse(fields[0], NumberStyles.None, CultureInfo.InvariantCulture, out int pid))
        {
            return null;
        }
        long? startTicks = null;
        if (fields.Length > 1)
        {
            if (!long.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out long ticks))
            {
                return null;
            }
            startTicks = ticks;
        }

        Process process;
        try
        {
            process = Process.GetProcessById(pid);
        }
        catch (ArgumentException ex)
        {
            Trace.TraceError("{0}", ex);
            return null;
        }
        catch (InvalidOperationException ex)
        {
            Trace.TraceError("{0}", ex);
            return null;
        }
        if (IsRecordedProcess(process, startTicks, File.GetLastWriteTimeUtc(pidFile)))
        {
            return process;
        }
        process.Dispose();
        return null;
    }

    public static bool IsRecordedProcess(Process process, long? startTicks, DateTime pidFileWrittenUtc)
    {
        DateTime started;
        try
        {
            started = process.StartTime.ToUniversalTime();
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            Trace.TraceError("{0}", ex);
            return false;
        }
        catch (InvalidOperationException ex)
        {
            Trace.TraceError("{0}", ex);
            return false;
        }
        return startTicks is long ticks ? started.Ticks == ticks : started <= pidFileWrittenUtc;
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
        char[] buffer = new char[4096];
        while (true)
        {
            int read = await reader.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return;
            }
            output.Append(buffer, 0, read);
        }
    }

    private static void Track(Process process, bool requireTracked)
    {
        ChildProcessTracker? tracker = ChildProcessTracker.Current;
        if (tracker is null)
        {
            if (requireTracked)
            {
                TryKill(process);
                throw new InvalidOperationException("Child process tracking is not active.");
            }
            return;
        }

        bool tracked = false;
        try
        {
            tracker.Add(process);
            tracked = true;
        }
        catch (System.ComponentModel.Win32Exception ex) when (!requireTracked)
        {
            Trace.TraceError("{0}", ex);
        }
        catch (InvalidOperationException ex) when (!requireTracked)
        {
            Trace.TraceError("{0}", ex);
        }
        finally
        {
            if (!tracked && requireTracked)
            {
                TryKill(process);
            }
        }
    }

    public static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(3000);
            }
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            Trace.TraceError("{0}", ex);
        }
        catch (InvalidOperationException ex)
        {
            Trace.TraceError("{0}", ex);
        }
    }
}
