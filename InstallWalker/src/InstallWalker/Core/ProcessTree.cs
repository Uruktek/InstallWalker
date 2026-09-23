using System.Collections.Concurrent;
using System.Management;

namespace InstallWalker.Core;

/// <summary>
/// Tracks the installer's process tree (and any msiexec.exe started during the session) by
/// polling Win32_Process, which exposes parent PID and full command line.
/// </summary>
public sealed class ProcessTree : IDisposable
{
    private readonly ConcurrentDictionary<int, ProcessRecord> _tracked = new();
    private readonly DateTime _sessionStart;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;
    private int _rootPid;
    private ManagementEventWatcher? _startWatcher;

    public event Action<ProcessRecord>? ProcessStarted;
    public event Action<ProcessRecord>? ProcessExited;

    public ProcessTree(DateTime sessionStart) => _sessionStart = sessionStart;

    public IReadOnlyCollection<ProcessRecord> Processes => _tracked.Values.ToList();
    public int RootPid => _rootPid;

    public bool AnyAlive => _tracked.Values.Any(p => p.Exited == null);

    public void Start(int rootPid)
    {
        _rootPid = rootPid;
        if (rootPid > 0) PollOnce();
        TryStartTraceWatcher();
        _loop = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                try { PollOnce(); } catch { /* WMI hiccup - retry next tick */ }
                try { await Task.Delay(700, _cts.Token); } catch { break; }
            }
        });
    }

    /// <summary>Attach a PID after the fact (used when monitoring without launching).</summary>
    public void SetRoot(int pid) { _rootPid = pid; PollOnce(); }

    private void TryStartTraceWatcher()
    {
        // Instant notification for short-lived children; polling still backs it up.
        try
        {
            _startWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
            _startWatcher.EventArrived += (_, _) => { try { PollOnce(); } catch { } };
            _startWatcher.Start();
        }
        catch { _startWatcher = null; }
    }

    private readonly object _pollLock = new();

    private void PollOnce()
    {
        if (!OperatingSystem.IsWindows()) return;
        lock (_pollLock)
        {
            var snapshot = new Dictionary<int, (int ppid, string name, string? exe, string? cmd, DateTime created)>();
            using (var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate FROM Win32_Process"))
            using (var results = searcher.Get())
            {
                foreach (ManagementObject mo in results)
                {
                    using (mo)
                    {
                        int pid = Convert.ToInt32(mo["ProcessId"]);
                        int ppid = Convert.ToInt32(mo["ParentProcessId"]);
                        DateTime created = DateTime.MinValue;
                        if (mo["CreationDate"] is string cd)
                            try { created = ManagementDateTimeConverter.ToDateTime(cd); } catch { }
                        snapshot[pid] = (ppid, mo["Name"] as string ?? "", mo["ExecutablePath"] as string, mo["CommandLine"] as string, created);
                    }
                }
            }

            // Newly seen processes that belong to the tree.
            bool added;
            do
            {
                added = false;
                foreach (var (pid, info) in snapshot)
                {
                    if (_tracked.ContainsKey(pid)) continue;
                    bool isRoot = pid == _rootPid;
                    bool childOfTracked = _tracked.TryGetValue(info.ppid, out var parent) && parent.Exited == null
                                          && info.created >= parent.Started.AddSeconds(-1);
                    // The Windows Installer service spawns msiexec.exe outside our tree.
                    bool msiServer = info.name.Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase)
                                     && info.created >= _sessionStart;
                    if (!isRoot && !childOfTracked && !msiServer) continue;
                    if (!isRoot && info.created != DateTime.MinValue && info.created < _sessionStart.AddSeconds(-2)) continue;

                    var rec = new ProcessRecord
                    {
                        Pid = pid, ParentPid = info.ppid, Name = info.name,
                        ExecutablePath = info.exe, CommandLine = info.cmd,
                        Started = info.created == DateTime.MinValue ? DateTime.Now : info.created,
                        Depth = isRoot ? 0 : childOfTracked ? parent!.Depth + 1 : -1,
                    };
                    if (_tracked.TryAdd(pid, rec)) { added = true; ProcessStarted?.Invoke(rec); }
                }
            } while (added);

            // Exits.
            foreach (var rec in _tracked.Values)
            {
                if (rec.Exited != null) continue;
                if (!snapshot.TryGetValue(rec.Pid, out var now) || (now.created != DateTime.MinValue && Math.Abs((now.created - rec.Started).TotalSeconds) > 2))
                {
                    rec.Exited = DateTime.Now;
                    ProcessExited?.Invoke(rec);
                }
            }
        }
    }

    /// <summary>One-shot helper: all current descendants of a PID.</summary>
    public static IEnumerable<int> GetDescendants(int rootPid)
    {
        if (!OperatingSystem.IsWindows()) return Enumerable.Empty<int>();
        var parentOf = new Dictionary<int, int>();
        try
        {
            using var s = new ManagementObjectSearcher("SELECT ProcessId, ParentProcessId FROM Win32_Process");
            using var r = s.Get();
            foreach (ManagementObject mo in r)
                using (mo) parentOf[Convert.ToInt32(mo["ProcessId"])] = Convert.ToInt32(mo["ParentProcessId"]);
        }
        catch { return Enumerable.Empty<int>(); }

        var result = new HashSet<int>();
        var queue = new Queue<int>(); queue.Enqueue(rootPid);
        while (queue.Count > 0)
        {
            var cur = queue.Dequeue();
            foreach (var (pid, ppid) in parentOf)
                if (ppid == cur && pid != cur && result.Add(pid)) queue.Enqueue(pid);
        }
        return result;
    }

    public void Stop()
    {
        _cts.Cancel();
        try { _startWatcher?.Stop(); } catch { }
        try { _loop?.Wait(2000); } catch { }
        try { PollOnce(); } catch { }
    }

    public void Dispose()
    {
        Stop();
        _startWatcher?.Dispose();
        _cts.Dispose();
    }
}
