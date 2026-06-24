using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace VRChatNetCapture;

public sealed class ChildProcessTracker : IDisposable
{
    private static readonly object Sync = new();
    private static ChildProcessTracker? current;
    private readonly ChildProcessTracker? previous;
    private readonly SafeJobHandle? job;
    private bool disposed;

    private ChildProcessTracker(SafeJobHandle? job, ChildProcessTracker? previous)
    {
        this.job = job;
        this.previous = previous;
    }

    public static ChildProcessTracker? Current
    {
        get
        {
            lock (Sync)
            {
                return current;
            }
        }
    }

    public static ChildProcessTracker Create()
    {
        var previous = Current;
        var job = OperatingSystem.IsWindows() ? CreateKillOnCloseJob() : null;
        var tracker = new ChildProcessTracker(job, previous);
        lock (Sync)
        {
            current = tracker;
        }
        return tracker;
    }

    public void Add(Process process)
    {
        if (disposed)
        {
            throw new ObjectDisposedException(nameof(ChildProcessTracker));
        }
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        if (job is null || job.IsInvalid)
        {
            throw new InvalidOperationException("Child process tracking is unavailable.");
        }
        if (!AssignProcessToJobObject(job, process.Handle))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), $"Failed to attach child process {process.Id} to the capture job.");
        }
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }
        disposed = true;
        lock (Sync)
        {
            if (ReferenceEquals(current, this))
            {
                current = previous;
            }
        }
        job?.Dispose();
    }

    private static SafeJobHandle CreateKillOnCloseJob()
    {
        var job = CreateJobObject(IntPtr.Zero, null);
        if (job.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "Failed to create child process tracking job.");
        }

        var info = new JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new JobObjectBasicLimitInformation
            {
                LimitFlags = JobObjectLimitKillOnJobClose,
            },
        };
        var length = Marshal.SizeOf<JobObjectExtendedLimitInformation>();
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformationClass, ref info, (uint)length))
        {
            var error = Marshal.GetLastPInvokeError();
            job.Dispose();
            throw new Win32Exception(error, "Failed to configure child process tracking job.");
        }
        return job;
    }

    private const int JobObjectExtendedLimitInformationClass = 9;
    private const int JobObjectLimitKillOnJobClose = 0x00002000;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeJobHandle CreateJobObject(IntPtr securityAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        SafeJobHandle job,
        int informationClass,
        ref JobObjectExtendedLimitInformation jobObjectInformation,
        uint jobObjectInformationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(SafeJobHandle job, IntPtr process);

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public int LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public int ActiveProcessLimit;
        public IntPtr Affinity;
        public int PriorityClass;
        public int SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    private sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeJobHandle()
            : base(ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle() => CloseHandle(handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
    }
}
