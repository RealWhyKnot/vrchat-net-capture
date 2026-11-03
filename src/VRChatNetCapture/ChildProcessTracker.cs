using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace VRChatNetCapture;

internal sealed partial class ChildProcessTracker : IDisposable
{
    private static readonly Lock Sync = new();
    private static ChildProcessTracker? CurrentTracker;
    private readonly ChildProcessTracker? _previous;
    private readonly SafeJobHandle? _job;
    private bool _disposed;

    private ChildProcessTracker(SafeJobHandle? jobHandle, ChildProcessTracker? previousTracker)
    {
        _job = jobHandle;
        _previous = previousTracker;
    }

    public static ChildProcessTracker? Current
    {
        get
        {
            lock (Sync)
            {
                return CurrentTracker;
            }
        }
    }

    public static ChildProcessTracker Create()
    {
        ChildProcessTracker? previousTracker = Current;
        SafeJobHandle? jobHandle = OperatingSystem.IsWindows() ? CreateKillOnCloseJob() : null;
        var tracker = new ChildProcessTracker(jobHandle, previousTracker);
        lock (Sync)
        {
            CurrentTracker = tracker;
        }
        return tracker;
    }

    public void Add(Process process)
    {
        ObjectDisposedException.ThrowIf(_disposed, nameof(ChildProcessTracker));
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        if (_job is null || _job.IsInvalid)
        {
            throw new InvalidOperationException("Child process tracking is unavailable.");
        }
        if (!AssignProcessToJobObject(_job, process.Handle))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), $"Failed to attach child process {process.Id} to the capture job.");
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        lock (Sync)
        {
            if (ReferenceEquals(CurrentTracker, this))
            {
                CurrentTracker = _previous;
            }
        }
        _job?.Dispose();
    }

    private static SafeJobHandle CreateKillOnCloseJob()
    {
        SafeJobHandle jobHandle = CreateJobObject(IntPtr.Zero, name: null);
        if (jobHandle.IsInvalid)
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
        int length = Marshal.SizeOf<JobObjectExtendedLimitInformation>();
        if (!SetInformationJobObject(jobHandle, JobObjectExtendedLimitInformationClass, ref info, (uint)length))
        {
            int error = Marshal.GetLastPInvokeError();
            jobHandle.Dispose();
            throw new Win32Exception(error, "Failed to configure child process tracking job.");
        }
        return jobHandle;
    }

    private const int JobObjectExtendedLimitInformationClass = 9;
    private const int JobObjectLimitKillOnJobClose = 0x00002000;

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("kernel32.dll", EntryPoint = "CreateJobObjectW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeJobHandle CreateJobObject(IntPtr securityAttributes, string? name);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetInformationJobObject(
        SafeJobHandle jobHandle,
        int informationClass,
        ref JobObjectExtendedLimitInformation jobObjectInformation,
        uint jobObjectInformationLength);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AssignProcessToJobObject(SafeJobHandle jobHandle, IntPtr process);

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

    private sealed partial class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeJobHandle()
            : base(ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle() => CloseHandle(handle);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [LibraryImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool CloseHandle(IntPtr handle);
    }
}
