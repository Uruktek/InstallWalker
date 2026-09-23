namespace InstallWalker.Core;

public enum FileArea { Install, Temp, Shortcut, UserProfile, System, Other }

public enum Confidence { Low = 1, Medium = 2, High = 3, Confirmed = 4 }

/// <summary>One file path seen changing during the session (deduplicated by path).</summary>
public sealed class FileRecord
{
    public required string Path { get; init; }
    public string FileName => System.IO.Path.GetFileName(Path);
    public string Directory => System.IO.Path.GetDirectoryName(Path) ?? "";
    public DateTime FirstSeen { get; init; }
    public DateTime LastSeen { get; set; }
    /// <summary>First change type observed (Created, Changed, Deleted, Renamed).</summary>
    public string FirstChange { get; init; } = "";
    public string LastChange { get; set; } = "";
    public int EventCount { get; set; } = 1;
    public string? RenamedFrom { get; set; }
    public FileArea Area { get; init; }
    public long? Size { get; set; }
    public bool IsDirectory { get; set; }

    /// <summary>Created and then deleted during the run, e.g. extracted payloads in temp.</summary>
    public bool Transient => FirstChange == "Created" && LastChange == "Deleted";

    /// <summary>Net effect after the run.</summary>
    public string NetResult =>
        Transient ? "Transient" :
        LastChange == "Deleted" ? "Deleted" :
        FirstChange == "Created" || FirstChange == "Renamed" ? "Added" : "Modified";
}

public sealed class SilentCandidate
{
    public required string Technology { get; init; }
    public required string Command { get; init; }
    public Confidence Confidence { get; init; }
    /// <summary>Where the suggestion came from: signature scan, MSI tables, child process, uninstall key...</summary>
    public string Source { get; init; } = "";
    public string Notes { get; init; } = "";
    public string Kind { get; init; } = "Install"; // Install | Uninstall | Info
}

public sealed class ProcessRecord
{
    public int Pid { get; init; }
    public int ParentPid { get; init; }
    public string Name { get; init; } = "";
    public string? ExecutablePath { get; init; }
    public string? CommandLine { get; init; }
    public DateTime Started { get; init; }
    public DateTime? Exited { get; set; }
    public int Depth { get; init; }
}

public sealed class RegistryChange
{
    public required string Change { get; init; }   // KeyAdded, KeyDeleted, ValueAdded, ValueChanged, ValueDeleted
    public required string Key { get; init; }
    public string? ValueName { get; init; }
    public string? OldData { get; init; }
    public string? NewData { get; init; }
}

public sealed class TempLocation
{
    public required string Path { get; init; }
    public DateTime FirstSeen { get; init; }
    public string Reason { get; set; } = "";
    public int FileCount { get; set; }
    public bool IsPrimary { get; set; }
}
