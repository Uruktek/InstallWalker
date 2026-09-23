using Microsoft.Win32;
using System.Text;

namespace InstallWalker.Core;

/// <summary>
/// Before/after snapshot of the registry areas installers normally touch. New vendor keys found
/// at the depth limit are walked fully so everything under them is reported.
/// </summary>
public sealed class RegistrySnapshot
{
    public sealed record Target(RegistryHive Hive, string Path, int Depth, string[] NoRecurse);

    public static readonly Target[] DefaultTargets =
    {
        new(RegistryHive.LocalMachine, @"SOFTWARE", 2, new[] { "Classes", "Microsoft", "WOW6432Node" }),
        new(RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node", 2, new[] { "Classes", "Microsoft" }),
        new(RegistryHive.LocalMachine, @"SOFTWARE\Classes", 1, Array.Empty<string>()),
        new(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 1, Array.Empty<string>()),
        new(RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", 1, Array.Empty<string>()),
        new(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, Array.Empty<string>()),
        new(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", 0, Array.Empty<string>()),
        new(RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", 0, Array.Empty<string>()),
        new(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths", 1, Array.Empty<string>()),
        new(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products", 0, Array.Empty<string>()),
        new(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts", 0, Array.Empty<string>()),
        new(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers", 1, Array.Empty<string>()),
        new(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services", 1, Array.Empty<string>()),
        new(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", 0, Array.Empty<string>()),
        new(RegistryHive.CurrentUser,  @"Software", 2, new[] { "Classes", "Microsoft" }),
        new(RegistryHive.CurrentUser,  @"Software\Classes", 1, Array.Empty<string>()),
        new(RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Uninstall", 1, Array.Empty<string>()),
        new(RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Run", 0, Array.Empty<string>()),
        new(RegistryHive.CurrentUser,  @"Environment", 0, Array.Empty<string>()),
    };

    private const int MaxNewSubtreeKeys = 5000;

    // key path -> (value name -> data). Key path is "HKLM\SOFTWARE\Vendor".
    private readonly Dictionary<string, Dictionary<string, string>> _keys = new(StringComparer.OrdinalIgnoreCase);
    // Keys captured at the depth limit (their children were not walked).
    private readonly HashSet<string> _frontier = new(StringComparer.OrdinalIgnoreCase);

    public int KeyCount => _keys.Count;
    public IReadOnlyDictionary<string, Dictionary<string, string>> Keys => _keys;

    public static RegistrySnapshot Capture(IEnumerable<Target>? targets = null)
    {
        var snap = new RegistrySnapshot();
        if (!OperatingSystem.IsWindows()) return snap;
        foreach (var t in targets ?? DefaultTargets)
        {
            try
            {
                using var root = RegistryKey.OpenBaseKey(t.Hive, RegistryView.Registry64);
                using var key = root.OpenSubKey(t.Path);
                if (key != null) snap.Walk(key, HiveName(t.Hive) + "\\" + t.Path, 0, t.Depth, t.NoRecurse);
            }
            catch { /* access denied etc. */ }
        }
        return snap;
    }

    private void Walk(RegistryKey key, string path, int depth, int maxDepth, string[] noRecurse)
    {
        if (!_keys.ContainsKey(path)) _keys[path] = ReadValues(key);
        if (depth >= maxDepth) { _frontier.Add(path); return; }
        string[] subs;
        try { subs = key.GetSubKeyNames(); } catch { return; }
        foreach (var sub in subs)
        {
            try
            {
                using var child = key.OpenSubKey(sub);
                if (child == null) continue;
                var childPath = path + "\\" + sub;
                bool stop = depth == 0 && noRecurse.Contains(sub, StringComparer.OrdinalIgnoreCase);
                if (stop) { if (!_keys.ContainsKey(childPath)) _keys[childPath] = ReadValues(child); continue; }
                Walk(child, childPath, depth + 1, maxDepth, noRecurse);
            }
            catch { }
        }
    }

    private static Dictionary<string, string> ReadValues(RegistryKey key)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var name in key.GetValueNames())
            {
                try { values[name] = Format(key, name); } catch { }
            }
        }
        catch { }
        return values;
    }

    public static string Format(RegistryKey key, string name)
    {
        var kind = key.GetValueKind(name);
        var v = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        return kind switch
        {
            RegistryValueKind.Binary when v is byte[] b => "hex:" + Convert.ToHexString(b.AsSpan(0, Math.Min(b.Length, 128))) + (b.Length > 128 ? "..." : ""),
            RegistryValueKind.MultiString when v is string[] a => string.Join(" | ", a),
            RegistryValueKind.DWord when v is int i => $"{i} (0x{i:X8})",
            RegistryValueKind.QWord when v is long l => $"{l} (0x{l:X16})",
            _ => v?.ToString() ?? ""
        };
    }

    public static string HiveName(RegistryHive h) => h switch
    {
        RegistryHive.LocalMachine => "HKLM",
        RegistryHive.CurrentUser => "HKCU",
        RegistryHive.ClassesRoot => "HKCR",
        RegistryHive.Users => "HKU",
        _ => h.ToString()
    };

    /// <summary>Compares two snapshots. Keys that are new under a frontier are walked fully.</summary>
    public static List<RegistryChange> Diff(RegistrySnapshot before, RegistrySnapshot after)
    {
        var changes = new List<RegistryChange>();
        foreach (var (key, afterValues) in after._keys.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (!before._keys.TryGetValue(key, out var beforeValues))
            {
                changes.Add(new RegistryChange { Change = "KeyAdded", Key = key });
                foreach (var (n, d) in afterValues)
                    changes.Add(new RegistryChange { Change = "ValueAdded", Key = key, ValueName = DisplayName(n), NewData = d });
                if (after._frontier.Contains(key)) AddSubtree(key, changes);
                continue;
            }
            foreach (var (n, d) in afterValues)
            {
                if (!beforeValues.TryGetValue(n, out var old))
                    changes.Add(new RegistryChange { Change = "ValueAdded", Key = key, ValueName = DisplayName(n), NewData = d });
                else if (old != d)
                    changes.Add(new RegistryChange { Change = "ValueChanged", Key = key, ValueName = DisplayName(n), OldData = old, NewData = d });
            }
            foreach (var (n, d) in beforeValues)
                if (!afterValues.ContainsKey(n))
                    changes.Add(new RegistryChange { Change = "ValueDeleted", Key = key, ValueName = DisplayName(n), OldData = d });
        }
        foreach (var key in before._keys.Keys)
            if (!after._keys.ContainsKey(key))
                changes.Add(new RegistryChange { Change = "KeyDeleted", Key = key });
        return changes;
    }

    private static string DisplayName(string n) => n.Length == 0 ? "(Default)" : n;

    /// <summary>Walks everything below a newly created key that sat at the depth limit.</summary>
    private static void AddSubtree(string keyPath, List<RegistryChange> changes)
    {
        if (!OperatingSystem.IsWindows()) return;
        var sep = keyPath.IndexOf('\\');
        if (sep < 0) return;
        var hive = keyPath[..sep] switch { "HKLM" => RegistryHive.LocalMachine, "HKCU" => RegistryHive.CurrentUser, _ => (RegistryHive?)null };
        if (hive == null) return;
        try
        {
            using var root = RegistryKey.OpenBaseKey(hive.Value, RegistryView.Registry64);
            using var key = root.OpenSubKey(keyPath[(sep + 1)..]);
            if (key == null) return;
            int count = 0;
            void Recurse(RegistryKey k, string path)
            {
                foreach (var sub in k.GetSubKeyNames())
                {
                    if (++count > MaxNewSubtreeKeys) return;
                    using var c = k.OpenSubKey(sub);
                    if (c == null) continue;
                    var p = path + "\\" + sub;
                    changes.Add(new RegistryChange { Change = "KeyAdded", Key = p });
                    foreach (var (n, d) in ReadValues(c))
                        changes.Add(new RegistryChange { Change = "ValueAdded", Key = p, ValueName = DisplayName(n), NewData = d });
                    Recurse(c, p);
                }
            }
            Recurse(key, keyPath);
        }
        catch { }
    }

    /// <summary>Exports changes as a .reg file (additions and modifications only).</summary>
    public static string ToRegFile(IEnumerable<RegistryChange> changes)
    {
        var sb = new StringBuilder("Windows Registry Editor Version 5.00\r\n");
        foreach (var g in changes.Where(c => c.Change is "KeyAdded" or "ValueAdded" or "ValueChanged").GroupBy(c => c.Key))
        {
            var full = g.Key.Replace("HKLM\\", "HKEY_LOCAL_MACHINE\\").Replace("HKCU\\", "HKEY_CURRENT_USER\\");
            sb.Append("\r\n[").Append(full).Append("]\r\n");
            foreach (var c in g.Where(c => c.ValueName != null))
            {
                var name = c.ValueName == "(Default)" ? "@" : "\"" + Esc(c.ValueName!) + "\"";
                var data = c.NewData ?? "";
                if (data.StartsWith("hex:")) continue; // truncated binary - not safely reproducible
                var m = System.Text.RegularExpressions.Regex.Match(data, @"^(-?\d+) \(0x([0-9A-F]{8})\)$");
                sb.Append(name).Append('=').Append(m.Success ? "dword:" + m.Groups[2].Value.ToLowerInvariant() : "\"" + Esc(data) + "\"").Append("\r\n");
            }
        }
        return sb.ToString();
    }

    private static string Esc(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");
}
