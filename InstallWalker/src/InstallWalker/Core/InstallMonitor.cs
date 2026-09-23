using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace InstallWalker.Core;

public sealed class MonitorOptions
{
    public List<string> WatchRoots { get; set; } = DefaultRoots();
    public List<string> Exclusions { get; set; } = DefaultExclusions();
    public bool CaptureRegistry { get; set; } = true;
    /// <summary>Copy .msi/.msp/.exe/.cab payloads out of temp before the installer cleans them up.</summary>
    public bool PreservePayloads { get; set; } = true;
    public string CaptureDir { get; set; } = Path.Combine(AppContext.BaseDirectory, "Captures");

    public static List<string> DefaultRoots()
    {
        var sys = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
        return new List<string> { sys };
    }

    public static List<string> DefaultExclusions() => new()
    {
        @"\$Recycle.Bin\", @"\System Volume Information\", @"\Windows\Prefetch\", @"\Windows\Logs\",
        @"\Windows\SoftwareDistribution\", @"\Windows\System32\LogFiles\", @"\Windows\System32\winevt\",
        @"\Windows\System32\config\", @"\Windows\ServiceProfiles\", @"\Windows\WinSxS\Temp\",
        @"\Windows\System32\sru\", @"\Windows\System32\Tasks\Microsoft\", @"\Windows\bootstat.dat",
        @"\ProgramData\Microsoft\Windows Defender\", @"\ProgramData\Microsoft\Windows\WER\",
        @"\ProgramData\Microsoft\Diagnosis\", @"\ProgramData\Microsoft\Search\", @"\ProgramData\USOPrivate\",
        @"\ProgramData\Microsoft\Network\", @"\ProgramData\Microsoft\Windows\DeviceMetadataCache\",
        @"\AppData\Local\Microsoft\Windows\Explorer\", @"\AppData\Local\Microsoft\Windows\INetCache\",
        @"\AppData\Local\Microsoft\Windows\WebCache\", @"\AppData\Local\Microsoft\Edge\",
        @"\AppData\Local\Google\Chrome\", @"\AppData\Local\Mozilla\", @"\AppData\Roaming\Mozilla\",
        @"\AppData\Local\Packages\", @"\AppData\Local\ConnectedDevicesPlatform\",
        @"\AppData\Local\Microsoft\Windows\Notifications\", @"\AppData\Local\Microsoft\OneDrive\",
        @"\AppData\Local\Claude\", @"\AppData\Roaming\Claude\", @"\AppData\Local\AnthropicClaude\",
        @"\AppData\Local\Microsoft\Windows\UsrClass.dat", @"\NTUSER.DAT", @"\ntuser.dat.LOG",
        @"\pagefile.sys", @"\swapfile.sys", @"\hiberfil.sys", ".etl", ".pf",
    };
}

/// <summary>
/// Orchestrates one capture session: file system watchers, temp tracking, the installer's process
/// tree, registry before/after, and runtime silent-switch discovery.
/// </summary>
public sealed class InstallMonitor : IDisposable
{
    private readonly MonitorOptions _options;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, FileRecord> _files = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, TempLocation> _temps = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, SilentCandidate> _candidates = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _analyzed = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<string> _log = new();
    private readonly string[] _tempRoots;
    private readonly string _ownDir;
    private RegistrySnapshot? _regBefore;

    public DateTime Started { get; private set; }
    public DateTime? Stopped { get; private set; }
    public bool IsRunning { get; private set; }
    public ProcessTree? Processes { get; private set; }
    public List<RegistryChange> RegistryChanges { get; private set; } = new();
    public string? InstallerPath { get; private set; }
    public int OverflowCount;

    public IReadOnlyCollection<FileRecord> Files => _files.Values.ToList();
    public IReadOnlyCollection<TempLocation> TempLocations => _temps.Values.ToList();
    public IReadOnlyCollection<SilentCandidate> Candidates => _candidates.Values.ToList();

    /// <summary>Raised from worker threads; the UI marshals it.</summary>
    public event Action<SilentCandidate>? CandidateFound;
    public event Action<string>? Log;

    public InstallMonitor(MonitorOptions options)
    {
        _options = options;
        var t = new[]
        {
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        };
        _tempRoots = t.Select(p => Path.TrimEndingDirectorySeparator(Path.GetFullPath(p)) + "\\").Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        _ownDir = Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory) + "\\";
    }

    // ------------------------------------------------------------------ lifecycle

    /// <summary>Takes the "before" registry snapshot and arms the watchers. Call before launching.</summary>
    public async Task ArmAsync()
    {
        Started = DateTime.Now;
        if (_options.CaptureRegistry)
        {
            WriteLog("Capturing registry baseline...");
            var sw = Stopwatch.StartNew();
            _regBefore = await Task.Run(() => RegistrySnapshot.Capture());
            WriteLog($"Registry baseline: {_regBefore.KeyCount:N0} keys in {sw.Elapsed.TotalSeconds:N1}s.");
        }
        foreach (var root in _options.WatchRoots.Where(Directory.Exists))
        {
            try
            {
                var w = new FileSystemWatcher(root)
                {
                    IncludeSubdirectories = true,
                    InternalBufferSize = 64 * 1024,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.Size,
                };
                w.Created += (_, e) => OnFs("Created", e.FullPath, null);
                w.Changed += (_, e) => OnFs("Changed", e.FullPath, null);
                w.Deleted += (_, e) => OnFs("Deleted", e.FullPath, null);
                w.Renamed += (_, e) => OnFs("Renamed", e.FullPath, e.OldFullPath);
                w.Error += (_, e) => { Interlocked.Increment(ref OverflowCount); WriteLog("Watcher buffer overflow - some events lost: " + e.GetException().Message); };
                w.EnableRaisingEvents = true;
                _watchers.Add(w);
                WriteLog("Watching " + root);
            }
            catch (Exception ex) { WriteLog($"Cannot watch {root}: {ex.Message}"); }
        }
        Started = DateTime.Now;
        IsRunning = true;
    }

    /// <summary>Launches the installer (MSI through msiexec) and starts tracking its process tree.</summary>
    public Process? Launch(string installerPath, string arguments)
    {
        InstallerPath = installerPath;
        var ext = Path.GetExtension(installerPath).ToLowerInvariant();
        ProcessStartInfo psi = ext switch
        {
            ".msi" => new ProcessStartInfo("msiexec.exe", $"/i \"{installerPath}\" {arguments}".Trim()),
            ".msp" => new ProcessStartInfo("msiexec.exe", $"/p \"{installerPath}\" {arguments}".Trim()),
            _ => new ProcessStartInfo(installerPath, arguments),
        };
        psi.UseShellExecute = false;
        psi.WorkingDirectory = Path.GetDirectoryName(installerPath) ?? Environment.CurrentDirectory;
        WriteLog($"Launching: {psi.FileName} {psi.Arguments}");
        var p = Process.Start(psi);
        StartProcessTracking(p?.Id ?? 0);
        return p;
    }

    /// <summary>Tracking without a known root: still catches msiexec and all file/registry activity.</summary>
    public void StartProcessTracking(int rootPid)
    {
        Processes = new ProcessTree(Started);
        Processes.ProcessStarted += OnProcessStarted;
        Processes.ProcessExited += r => WriteLog($"Process exited: {r.Name} (PID {r.Pid})");
        Processes.Start(rootPid);
    }

    public async Task StopAsync()
    {
        if (!IsRunning) return;
        IsRunning = false;
        foreach (var w in _watchers) { try { w.EnableRaisingEvents = false; w.Dispose(); } catch { } }
        _watchers.Clear();
        Processes?.Stop();
        Stopped = DateTime.Now;

        await Task.Run(() =>
        {
            foreach (var f in _files.Values)
            {
                try
                {
                    if (Directory.Exists(f.Path)) f.IsDirectory = true;
                    else if (File.Exists(f.Path)) f.Size = new FileInfo(f.Path).Length;
                }
                catch { }
            }
        });

        if (_regBefore != null)
        {
            WriteLog("Capturing registry after-snapshot and diffing...");
            var after = await Task.Run(() => RegistrySnapshot.Capture());
            RegistryChanges = await Task.Run(() => RegistrySnapshot.Diff(_regBefore, after));
            WriteLog($"Registry: {RegistryChanges.Count:N0} changes.");
            AnalyzeUninstallEntries(after);
        }

        // Late analysis: uninstallers and cached MSIs that landed on disk.
        foreach (var f in _files.Values.Where(f => f.NetResult == "Added" && !f.IsDirectory))
        {
            var n = f.FileName.ToLowerInvariant();
            if (f.Path.StartsWith(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Installer"), StringComparison.OrdinalIgnoreCase) && n.EndsWith(".msi"))
                AnalyzeDiscovered(f.Path, "Cached by Windows Installer", Confidence.High);
        }
        WriteLog($"Session stopped. {_files.Count:N0} paths, {_temps.Count} temp locations, {_candidates.Count} silent candidates.");
    }

    // ------------------------------------------------------------------ file events

    private void OnFs(string change, string path, string? oldPath)
    {
        if (!IsRunning || IsExcluded(path)) return;
        var now = DateTime.Now;

        if (change == "Renamed" && oldPath != null && _files.TryGetValue(oldPath, out var old))
        {
            old.LastChange = "Deleted"; old.LastSeen = now; old.EventCount++;
        }

        var rec = _files.AddOrUpdate(path,
            p => new FileRecord
            {
                Path = p, FirstSeen = now, LastSeen = now, FirstChange = change, LastChange = change,
                Area = Classify(p), RenamedFrom = oldPath,
            },
            (_, r) => { r.LastSeen = now; r.LastChange = change == "Changed" && r.LastChange == "Created" ? "Created" : change; r.EventCount++; return r; });

        if (rec.Area == FileArea.Temp && change is "Created" or "Renamed") TrackTemp(path, now);

        // Installer payloads dropped during the run: analyse them for silent switches.
        if (change is "Created" or "Renamed" or "Changed")
        {
            var ext = Path.GetExtension(path).ToLowerInvariant();
            if (rec.Area == FileArea.Temp && ext is ".msi" or ".msp" or ".exe" or ".cab" or ".mst")
            {
                if (_options.PreservePayloads) QueuePreserve(path);
                if (ext is ".msi" or ".msp")
                    QueueAnalyze(path, "Extracted to temp during install", Confidence.High, delayMs: 1500);
            }
        }
    }

    private bool IsExcluded(string path)
    {
        if (path.StartsWith(_ownDir, StringComparison.OrdinalIgnoreCase)) return true;
        foreach (var ex in _options.Exclusions)
            if (ex.Length > 0 && path.Contains(ex, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private string? TempRootOf(string path) =>
        _tempRoots.FirstOrDefault(r => path.StartsWith(r, StringComparison.OrdinalIgnoreCase));

    public FileArea Classify(string path)
    {
        if (TempRootOf(path) != null) return FileArea.Temp;
        var p = path.ToLowerInvariant();
        if (p.EndsWith(".lnk") || p.Contains(@"\start menu\") || p.Contains(@"\desktop\")) return FileArea.Shortcut;
        if (p.Contains(@"\program files") || p.Contains(@"\programdata\")) return FileArea.Install;
        if (p.Contains(@"\appdata\")) return FileArea.UserProfile;
        if (p.Contains(@"\windows\")) return FileArea.System;
        return FileArea.Other;
    }

    /// <summary>Groups temp activity by the top-level folder (or file) created directly under a temp root.</summary>
    private void TrackTemp(string path, DateTime now)
    {
        var root = TempRootOf(path);
        if (root == null) return;
        var rel = path[root.Length..];
        var first = rel.Split('\\', 2)[0];
        if (first.Length == 0) return;
        var top = root + first;
        var loc = _temps.GetOrAdd(top, t =>
        {
            WriteLog("New temp location: " + t);
            return new TempLocation { Path = t, FirstSeen = now, Reason = "Created during install" };
        });
        loc.FileCount++;
        RecomputePrimaryTemp();
    }

    private void RecomputePrimaryTemp()
    {
        var list = _temps.Values.ToList();
        if (list.Count == 0) return;
        var primary = list.FirstOrDefault(t => t.Reason.StartsWith("Installer process ran from"))
                      ?? list.OrderByDescending(t => t.FileCount).ThenBy(t => t.FirstSeen).First();
        foreach (var t in list) t.IsPrimary = ReferenceEquals(t, primary);
    }

    public TempLocation? PrimaryTemp => _temps.Values.FirstOrDefault(t => t.IsPrimary);

    // ------------------------------------------------------------------ process events

    private static readonly Regex MsiPathInCmd = new(@"(?:/i|/package|/p|/update)\s*""?(?<p>[^""]+?\.ms[ip])""?(?=\s|$)", RegexOptions.IgnoreCase);

    private void OnProcessStarted(ProcessRecord r)
    {
        WriteLog($"Process started: {r.Name} (PID {r.Pid}, parent {r.ParentPid}) {r.CommandLine}");

        // Child exe launched from temp -> that folder is the installer's working temp location.
        if (r.ExecutablePath != null && TempRootOf(r.ExecutablePath) is { } root && r.Depth >= 0)
        {
            var first = r.ExecutablePath[root.Length..].Split('\\', 2)[0];
            var top = root + first;
            var loc = _temps.GetOrAdd(top, t => new TempLocation { Path = t, FirstSeen = DateTime.Now });
            loc.Reason = $"Installer process ran from here ({r.Name})";
            RecomputePrimaryTemp();
            if (r.Depth > 0 && r.ExecutablePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                QueueAnalyze(r.ExecutablePath, $"Child installer launched from temp (PID {r.Pid})", Confidence.Medium);
        }

        if (r.CommandLine == null) return;

        // Bootstrapper handing an MSI to msiexec: the most reliable silent path.
        if (r.Name.Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase))
        {
            var m = MsiPathInCmd.Match(r.CommandLine);
            if (m.Success)
            {
                var msi = m.Groups["p"].Value.Trim();
                AddCandidate(new SilentCandidate
                {
                    Technology = "Windows Installer (observed)", Confidence = Confidence.Confirmed,
                    Source = $"msiexec child process (PID {r.Pid})",
                    Command = r.CommandLine,
                    Notes = "Exact command line the bootstrapper used. Copy the MSI out of temp before it is cleaned up.",
                    Kind = "Info",
                });
                QueueAnalyze(msi, "MSI passed to msiexec by the installer", Confidence.Confirmed);
            }
        }
        else if (r.Depth > 0)
        {
            // Any silent-looking switches the bootstrapper passes to its own children are strong hints.
            var hints = HelpProbe.ExtractSwitches(r.CommandLine)
                .Where(s => Regex.IsMatch(s, @"^(/|--?)(s|q|qn|quiet|silent|verysilent|passive|norestart|suppressmsgboxes|sp-|exenoui|unattended|mode[=:]unattended)\b", RegexOptions.IgnoreCase))
                .ToList();
            if (hints.Count > 0)
                AddCandidate(new SilentCandidate
                {
                    Technology = "Observed child command line", Confidence = Confidence.Medium,
                    Source = $"{r.Name} (PID {r.Pid})", Command = r.CommandLine, Kind = "Info",
                    Notes = "The installer launched a child with silent-style switches: " + string.Join(" ", hints),
                });
        }
    }

    // ------------------------------------------------------------------ payload capture

    private readonly ConcurrentDictionary<string, string> _preserved = new(StringComparer.OrdinalIgnoreCase);
    public IReadOnlyDictionary<string, string> PreservedPayloads => _preserved;
    public string SessionCaptureDir => Path.Combine(_options.CaptureDir, Started.ToString("yyyyMMdd_HHmmss"));

    /// <summary>Waits until the file stops growing, then copies it into the session capture folder.</summary>
    private void QueuePreserve(string path)
    {
        if (_preserved.ContainsKey(path)) return;
        _preserved[path] = "";
        _ = Task.Run(async () =>
        {
            long lastLen = -1;
            for (int i = 0; i < 40; i++)
            {
                await Task.Delay(500);
                try
                {
                    if (!File.Exists(path)) break;
                    var len = new FileInfo(path).Length;
                    if (len > 0 && len == lastLen)
                    {
                        Directory.CreateDirectory(SessionCaptureDir);
                        var root = TempRootOf(path) ?? "";
                        var rel = path[root.Length..].Replace('\\', '_');
                        var dest = Path.Combine(SessionCaptureDir, rel);
                        using (var src = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                        using (var dst = File.Create(dest))
                            await src.CopyToAsync(dst);
                        _preserved[path] = dest;
                        WriteLog($"Preserved payload {Path.GetFileName(path)} -> {dest}");
                        return;
                    }
                    lastLen = len;
                }
                catch { /* still locked or being written - retry */ }
            }
            _preserved.TryRemove(path, out _);
        });
    }

    // ------------------------------------------------------------------ analysis

    public void AddCandidate(SilentCandidate c)
    {
        var key = c.Kind + "|" + c.Command;
        if (_candidates.TryAdd(key, c)) CandidateFound?.Invoke(c);
    }

    private void QueueAnalyze(string path, string why, Confidence conf, int delayMs = 300) =>
        _ = Task.Run(async () =>
        {
            if (_analyzed.ContainsKey(path)) return;
            await Task.Delay(delayMs);
            // Wait for the file to stop growing so MSI tables can be opened.
            long last = -1;
            for (int i = 0; i < 40; i++)
            {
                try { var len = File.Exists(path) ? new FileInfo(path).Length : -2; if (len == last) break; last = len; } catch { }
                await Task.Delay(500);
            }
            AnalyzeDiscovered(path, why, conf);
        });

    private void AnalyzeDiscovered(string path, string why, Confidence conf)
    {
        if (!_analyzed.TryAdd(path, 0)) return;
        try
        {
            if (!File.Exists(path))
            {
                // The installer may already have deleted it; fall back to our preserved copy.
                if (_preserved.TryGetValue(path, out var copy) && File.Exists(copy)) path = copy; else return;
            }
            var result = InstallerAnalyzer.Analyze(path);
            WriteLog($"Analyzed {path}: {result.Technology}");
            foreach (var c in result.Candidates)
            {
                AddCandidate(new SilentCandidate
                {
                    Technology = result.Technology, Command = c.Command, Kind = c.Kind, Notes = c.Notes,
                    Source = $"{why}: {Path.GetFileName(path)}",
                    Confidence = c.Confidence == Confidence.Low ? Confidence.Low : (Confidence)Math.Min((int)c.Confidence, (int)conf),
                });
            }
        }
        catch (Exception ex) { WriteLog($"Analyze failed for {path}: {ex.Message}"); }
    }

    private void AnalyzeUninstallEntries(RegistrySnapshot after)
    {
        var uninstallKeys = RegistryChanges
            .Where(c => c.Change is "KeyAdded" or "ValueChanged" or "ValueAdded" && c.Key.Contains(@"\CurrentVersion\Uninstall\", StringComparison.OrdinalIgnoreCase))
            .Select(c => c.Key)
            .Select(k => { var i = k.IndexOf(@"\Uninstall\", StringComparison.OrdinalIgnoreCase); var rest = k[(i + 11)..]; var slash = rest.IndexOf('\\'); return slash < 0 ? k : k[..(i + 11 + slash)]; })
            .Distinct(StringComparer.OrdinalIgnoreCase);

        foreach (var key in uninstallKeys)
        {
            if (!after.Keys.TryGetValue(key, out var v)) continue;
            v.TryGetValue("DisplayName", out var name);
            if (string.IsNullOrEmpty(name)) continue;
            v.TryGetValue("DisplayVersion", out var ver);
            v.TryGetValue("UninstallString", out var un);
            v.TryGetValue("QuietUninstallString", out var qun);
            v.TryGetValue("InstallLocation", out var loc);
            var keyName = key[(key.LastIndexOf('\\') + 1)..];

            AddCandidate(new SilentCandidate
            {
                Technology = "Detection rule", Kind = "Info", Confidence = Confidence.Confirmed, Source = "Uninstall registry key",
                Command = key.Replace("HKLM\\", "HKEY_LOCAL_MACHINE\\").Replace("HKCU\\", "HKEY_CURRENT_USER\\"),
                Notes = $"{name} {ver}".Trim() + (string.IsNullOrEmpty(loc) ? "" : $" - InstallLocation: {loc}"),
            });

            if (!string.IsNullOrEmpty(qun))
                AddCandidate(new SilentCandidate { Technology = name, Kind = "Uninstall", Confidence = Confidence.Confirmed, Source = "QuietUninstallString", Command = qun });

            var guid = Regex.Match(keyName + " " + un, @"\{[0-9A-Fa-f\-]{36}\}");
            if (un != null && un.Contains("msiexec", StringComparison.OrdinalIgnoreCase) && guid.Success)
            {
                AddCandidate(new SilentCandidate { Technology = name, Kind = "Uninstall", Confidence = Confidence.Confirmed, Source = "UninstallString (MSI)",
                    Command = $"msiexec.exe /x {guid.Value} /qn /norestart" });
                AddCandidate(new SilentCandidate { Technology = "Windows Installer", Kind = "Info", Confidence = Confidence.Confirmed, Source = "Uninstall key",
                    Command = $"ProductCode {guid.Value}", Notes = "Use as an MSI product-code detection rule." });
            }
            else if (!string.IsNullOrEmpty(un))
            {
                var exe = Regex.Match(un, "^\"([^\"]+)\"|^(\\S+\\.exe)", RegexOptions.IgnoreCase);
                var exePath = exe.Groups[1].Success ? exe.Groups[1].Value : exe.Groups[2].Value;
                string? silent = null;
                if (File.Exists(exePath))
                {
                    var a = InstallerAnalyzer.Analyze(exePath);
                    silent = a.Technology switch
                    {
                        "Inno Setup" => "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART",
                        "NSIS (Nullsoft)" => "/S",
                        "InstallShield" => "/s",
                        _ => null,
                    };
                }
                AddCandidate(new SilentCandidate
                {
                    Technology = name, Kind = "Uninstall", Source = "UninstallString",
                    Confidence = silent != null ? Confidence.High : Confidence.Low,
                    Command = silent != null ? $"{un} {silent}" : un,
                    Notes = silent != null ? "Uninstaller technology identified from its binary." : "Raw UninstallString - no silent switch identified.",
                });
            }
        }
    }

    // ------------------------------------------------------------------ misc

    private void WriteLog(string msg)
    {
        var line = $"{DateTime.Now:HH:mm:ss.fff}  {msg}";
        _log.Enqueue(line);
        Log?.Invoke(line);
    }

    public IEnumerable<string> LogLines => _log.ToArray();

    public void Dispose()
    {
        foreach (var w in _watchers) w.Dispose();
        _watchers.Clear();
        Processes?.Dispose();
    }
}
