using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Reports;
using BenchmarkDotNet.Running;
using VRChatNetCapture;
using VRChatNetCapture.Benchmarks;

AppDomain.CurrentDomain.UnhandledException += (_, eventArgs) =>
{
    if (eventArgs.ExceptionObject is Exception error)
    {
        CaptureLog.Unhandled(error);
    }
};
TaskScheduler.UnobservedTaskException += (_, eventArgs) => CaptureLog.Unhandled(eventArgs.Exception);
ManualConfig config = ManualConfig.Create(DefaultConfig.Instance).AddJob(Job.Default.DontEnforcePowerPlan().AsMutator());
Summary[] summaries = [.. BenchmarkSwitcher.FromAssembly(typeof(PacketBenchmarks).Assembly).Run(args, config)];
return summaries.Length == 0 || Array.Exists(summaries, summary => summary.HasCriticalValidationErrors || summary.Reports.Any(report => !report.Success)) ? 1 : 0;
