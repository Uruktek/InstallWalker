using System.Diagnostics;
using System.Text;

namespace InstallWalker.Core;

/// <summary>Result of statically inspecting an installer file before (or during) a run.</summary>
public sealed class AnalysisResult
{
    public required string Path { get; init; }
    public string Technology { get; set; } = "Unknown";
    public List<string> Evidence { get; } = new();
    public List<SilentCandidate> Candidates { get; } = new();
    public Dictionary<string, string> Info { get; } = new();
}

/// <summary>
/// Identifies the installer technology from file extension, PE sections, version resources,
/// and byte signatures in the stub and overlay, then proposes silent command lines.
/// </summary>
public static class InstallerAnalyzer
{
    private const int HeadBytes = 12 * 1024 * 1024;
    private const int TailBytes = 12 * 1024 * 1024;
    private static readonly byte[] OleSignature = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
    private static readonly byte[] SevenZipSignature = { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C };

    private sealed record Signature(string Technology, string[] Markers, int Priority);

    // Higher priority wins when several technologies match (e.g. an InstallShield wrapper that embeds 7-Zip).
    private static readonly Signature[] Signatures =
    {
        new("WiX Burn bundle",        new[] { ".wixburn", "WixBundleManifest", "WixBurn" }, 95),
        new("Inno Setup",             new[] { "Inno Setup Setup Data", "Inno Setup", "JR.Inno.Setup" }, 90),
        new("NSIS (Nullsoft)",        new[] { "NullsoftInst", "Nullsoft.NSIS", "Nullsoft Install System" }, 90),
        new("InstallShield",          new[] { "InstallShield", "ISSetupStream", "ISSetupPrerequisites" }, 85),
        new("Advanced Installer",     new[] { "Advanced Installer", "Caphyon" }, 85),
        new("InstallAware",           new[] { "InstallAware", "MimarSinan" }, 80),
        new("Wise Installer",         new[] { "WiseMain", "Wise Installation" }, 80),
        new("Setup Factory",          new[] { "Setup Factory" }, 75),
        new("InstallAnywhere",        new[] { "InstallAnywhere", "Zero G Software" }, 75),
        new("Squirrel (Electron)",    new[] { "SquirrelSetup", "Squirrel.Windows", "Update.exe --install" }, 75),
        new("Smart Install Maker",    new[] { "Smart Install Maker" }, 70),
        new("Clickteam Install Creator", new[] { "Clickteam" }, 60),
        new("IExpress / WExtract",    new[] { "IExpress", "WEXTRACT", "wextract_cleanup" }, 55),
        new("WinRAR SFX",             new[] { "WinRAR SFX", "WinRAR self-extracting" }, 50),
        new("7-Zip SFX",              new[] { ";!@Install@!UTF-8!", "7zSfx", "7-Zip SFX", "7zS.sfx" }, 45),
    };

    public static AnalysisResult Analyze(string path)
    {
        var r = new AnalysisResult { Path = path };
        if (!File.Exists(path)) { r.Evidence.Add("File not found."); return r; }

        var ext = System.IO.Path.GetExtension(path).ToLowerInvariant();
        var quoted = Quote(path);
        var name = System.IO.Path.GetFileNameWithoutExtension(path);
        var log = Quote($@"%TEMP%\{name}_install.log");

        switch (ext)
        {
            case ".msi":
                AnalyzeMsi(path, r, log);
                return r;
            case ".msp":
                r.Technology = "Windows Installer patch (MSP)";
                r.Candidates.Add(new SilentCandidate { Technology = r.Technology, Confidence = Confidence.High, Source = "File extension",
                    Command = $"msiexec.exe /p {quoted} /qn /norestart /l*v {log}" });
                return r;
            case ".msix": case ".msixbundle": case ".appx": case ".appxbundle":
                r.Technology = "MSIX / AppX package";
                r.Candidates.Add(new SilentCandidate { Technology = r.Technology, Confidence = Confidence.High, Source = "File extension",
                    Command = $"powershell -NoProfile -Command \"Add-AppxPackage -Path '{path}'\"", Notes = "Per-user install." });
                r.Candidates.Add(new SilentCandidate { Technology = r.Technology, Confidence = Confidence.High, Source = "File extension",
                    Command = $"DISM.exe /Online /Add-ProvisionedAppxPackage /PackagePath:{quoted} /SkipLicense", Notes = "Provision for all users." });
                return r;
        }

        AnalyzeExe(path, r, quoted, log);
        return r;
    }

    // ---------------------------------------------------------------- MSI

    private static void AnalyzeMsi(string path, AnalysisResult r, string log)
    {
        r.Technology = "Windows Installer (MSI)";
        var q = Quote(path);
        Dictionary<string, string> props = new();
        try { props = MsiDatabase.ReadProperties(path); }
        catch (Exception ex) { r.Evidence.Add("Could not read MSI Property table: " + ex.Message); }

        foreach (var key in new[] { "ProductName", "ProductVersion", "Manufacturer", "ProductCode", "UpgradeCode", "ALLUSERS", "ARPNOMODIFY" })
            if (props.TryGetValue(key, out var v)) r.Info[key] = v;

        var dirProps = props.Keys.Where(k => k is "INSTALLDIR" or "INSTALLFOLDER" or "APPDIR" or "TARGETDIR" or "INSTALLLOCATION" or "APPLICATIONFOLDER").ToList();
        var publicProps = props.Keys.Where(k => k.Length > 1 && k == k.ToUpperInvariant() && char.IsLetter(k[0])).OrderBy(k => k).ToList();
        if (publicProps.Count > 0) r.Info["Public properties"] = string.Join(", ", publicProps.Take(40)) + (publicProps.Count > 40 ? " ..." : "");

        r.Candidates.Add(new SilentCandidate
        {
            Technology = r.Technology, Confidence = Confidence.Confirmed, Source = "MSI database",
            Command = $"msiexec.exe /i {q} /qn /norestart /l*v {log}",
            Notes = "Standard Windows Installer switches. Add PROPERTY=value pairs to customise."
        });
        if (dirProps.Count > 0)
            r.Candidates.Add(new SilentCandidate
            {
                Technology = r.Technology, Confidence = Confidence.High, Source = "MSI Property table",
                Command = $"msiexec.exe /i {q} /qn /norestart {dirProps[0]}=\"C:\\Program Files\\{San(props.GetValueOrDefault("ProductName", "App"))}\" /l*v {log}",
                Notes = $"Custom install folder via {dirProps[0]}."
            });
        if (props.ContainsKey("ALLUSERS") || props.ContainsKey("MSIINSTALLPERUSER"))
            r.Candidates.Add(new SilentCandidate
            {
                Technology = r.Technology, Confidence = Confidence.High, Source = "MSI Property table",
                Command = $"msiexec.exe /i {q} /qn /norestart ALLUSERS=1 /l*v {log}",
                Notes = "Force a per-machine install."
            });
        if (props.TryGetValue("ProductCode", out var pc))
            r.Candidates.Add(new SilentCandidate
            {
                Technology = r.Technology, Kind = "Uninstall", Confidence = Confidence.Confirmed, Source = "MSI ProductCode",
                Command = $"msiexec.exe /x {pc} /qn /norestart"
            });
        r.Evidence.Add($"MSI Property table: {props.Count} properties read.");
    }

    // ---------------------------------------------------------------- EXE

    private static void AnalyzeExe(string path, AnalysisResult r, string q, string log)
    {
        // Version resource strings often name the tool outright ("This installation was built with Inno Setup.").
        var haystackExtra = new StringBuilder();
        try
        {
            var vi = FileVersionInfo.GetVersionInfo(path);
            AddInfo(r, "Product", vi.ProductName); AddInfo(r, "Company", vi.CompanyName);
            AddInfo(r, "Description", vi.FileDescription); AddInfo(r, "Version", vi.ProductVersion);
            AddInfo(r, "Comments", vi.Comments); AddInfo(r, "Original filename", vi.OriginalFilename);
            haystackExtra.Append(vi.Comments).Append('|').Append(vi.FileDescription).Append('|')
                         .Append(vi.InternalName).Append('|').Append(vi.LegalTrademarks).Append('|').Append(vi.ProductName);
        }
        catch { /* not a PE with resources */ }

        byte[] head, tail; long length;
        try { (head, tail, length) = ReadHeadTail(path); }
        catch (Exception ex) { r.Evidence.Add("Could not read file: " + ex.Message); return; }

        var sections = ReadPeSections(head, out long overlayOffset);
        if (sections.Count > 0) r.Info["PE sections"] = string.Join(" ", sections);
        if (overlayOffset > 0 && overlayOffset < length)
            r.Info["Overlay"] = $"{(length - overlayOffset) / 1024:N0} KB appended after the PE image";

        var matches = new List<(Signature sig, string marker)>();
        foreach (var sig in Signatures)
        {
            foreach (var m in sig.Markers)
            {
                bool hit = sections.Contains(m, StringComparer.OrdinalIgnoreCase)
                           || haystackExtra.ToString().Contains(m, StringComparison.OrdinalIgnoreCase)
                           || ContainsAscii(head, m) || ContainsAscii(tail, m)
                           || ContainsUtf16(head, m) || ContainsUtf16(tail, m);
                if (hit) { matches.Add((sig, m)); break; }
            }
        }

        bool embeddedMsi = IndexOf(head, OleSignature, 4096) >= 0 || IndexOf(tail, OleSignature, 0) >= 0;
        bool embedded7z = IndexOf(head, SevenZipSignature, 4096) >= 0 || IndexOf(tail, SevenZipSignature, 0) >= 0;
        if (embeddedMsi) r.Evidence.Add("Embedded OLE compound file found (very likely an MSI payload).");
        if (embedded7z) r.Evidence.Add("Embedded 7-Zip archive found.");
        bool electron = ContainsAscii(head, "app-64.7z") || ContainsAscii(tail, "app-64.7z") || ContainsAscii(head, "electron-builder");

        foreach (var (sig, marker) in matches.OrderByDescending(m => m.sig.Priority))
            r.Evidence.Add($"{sig.Technology}: matched \"{marker}\"");

        var primary = matches.OrderByDescending(m => m.sig.Priority).Select(m => m.sig.Technology).FirstOrDefault();
        r.Technology = primary ?? (embeddedMsi ? "EXE wrapper around an MSI" : "Unknown EXE");

        bool first = true;
        foreach (var tech in matches.OrderByDescending(m => m.sig.Priority).Select(m => m.sig.Technology).Distinct())
        {
            AddExeCandidates(r, tech, q, log, first ? Confidence.High : Confidence.Medium, embeddedMsi, electron);
            first = false;
        }

        if (embeddedMsi)
            r.Candidates.Add(new SilentCandidate
            {
                Technology = "Embedded MSI", Confidence = Confidence.Medium, Source = "Overlay scan",
                Command = "(run it once with InstallWalker - the extracted .msi path will appear here)",
                Kind = "Info",
                Notes = "Bootstrappers usually unpack the MSI to %TEMP% and hand it to msiexec. Capture that MSI and deploy it directly."
            });

        if (matches.Count == 0)
        {
            r.Evidence.Add("No known installer signature found - falling back to common switches.");
            foreach (var sw in new[] { "/S", "/silent", "/quiet /norestart", "/VERYSILENT /NORESTART", "/s", "-s", "--silent", "/qn" })
                r.Candidates.Add(new SilentCandidate { Technology = "Generic guess", Confidence = Confidence.Low, Source = "Heuristic",
                    Command = $"{q} {sw}", Notes = "Untested guess. Try 'Probe help' to see what the installer documents." });
        }
    }

    private static void AddExeCandidates(AnalysisResult r, string tech, string q, string log, Confidence c, bool embeddedMsi, bool electron)
    {
        void Add(string cmd, string notes = "", Confidence? conf = null, string kind = "Install") =>
            r.Candidates.Add(new SilentCandidate { Technology = tech, Command = cmd, Notes = notes, Confidence = conf ?? c, Source = "Signature scan", Kind = kind });

        switch (tech)
        {
            case "WiX Burn bundle":
                Add($"{q} /quiet /norestart /log {log}", "Burn bundles accept /quiet or /passive (progress bar only).");
                Add($"{q} /layout \"C:\\Temp\\{San(System.IO.Path.GetFileNameWithoutExtension(r.Path))}\"", "Extracts all payloads (MSIs) for inspection.", Confidence.Medium, "Info");
                Add($"{q} /uninstall /quiet /norestart", "", null, "Uninstall");
                break;
            case "Inno Setup":
                Add($"{q} /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /LOG={log}", "Add /DIR=\"C:\\Path\" to set the install folder, /ALLUSERS or /CURRENTUSER to force scope.");
                Add($"{q} /SILENT /SUPPRESSMSGBOXES /NORESTART /SP-", "Shows progress only.", Confidence.Medium);
                Add("\"<InstallDir>\\unins000.exe\" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART", "", null, "Uninstall");
                break;
            case "NSIS (Nullsoft)":
                if (electron)
                {
                    Add($"{q} /S /allusers", "electron-builder NSIS: /allusers for per-machine, /currentuser for per-user.");
                    Add($"{q} /S", "", Confidence.Medium);
                }
                else
                    Add($"{q} /S", "/S is case-sensitive. Optional /D=C:\\Path must be LAST and unquoted.");
                Add("\"<InstallDir>\\uninstall.exe\" /S", "Uninstaller name varies (uninst.exe, Uninstall <App>.exe).", null, "Uninstall");
                break;
            case "InstallShield":
                if (embeddedMsi)
                    Add($"{q} /s /v\"/qn REBOOT=ReallySuppress /l*v {log.Trim('"')}\"", "InstallShield Basic MSI / Suite: /s silences setup.exe, /v passes args to msiexec.");
                Add($"{q} /r /f1\"C:\\Temp\\setup.iss\"", "InstallScript: record a response file first (runs interactively).", Confidence.Medium, "Info");
                Add($"{q} /s /f1\"C:\\Temp\\setup.iss\" /f2\"C:\\Temp\\setup.log\"", "InstallScript: replay the recorded response file.", Confidence.Medium);
                if (!embeddedMsi)
                    Add($"{q} /s /v\"/qn\"", "Try if the package turns out to be Basic MSI.", Confidence.Low);
                break;
            case "Advanced Installer":
                Add($"{q} /exenoui /qn /norestart", "/exenoui hides the bootstrapper UI; the rest goes to msiexec.");
                Add($"{q} /extract \"C:\\Temp\\extracted\"", "Extracts the embedded MSI.", Confidence.Medium, "Info");
                break;
            case "InstallAware":
                Add($"{q} /s", "Some builds also need /l=\"log\"; MSI-mode packages accept msiexec properties.");
                break;
            case "Wise Installer":
                Add($"{q} /s");
                break;
            case "Setup Factory":
                Add($"{q} /S", "Only works if the author enabled silent mode.");
                break;
            case "InstallAnywhere":
                Add($"{q} -i silent", "Optionally -f installer.properties for a response file.");
                break;
            case "Squirrel (Electron)":
                Add($"{q} --silent", "Squirrel installs per-user into %LOCALAPPDATA%.");
                Add("\"%LOCALAPPDATA%\\<App>\\Update.exe\" --uninstall -s", "", null, "Uninstall");
                break;
            case "Smart Install Maker":
                Add($"{q} /s");
                break;
            case "Clickteam Install Creator":
                Add($"{q} /S");
                break;
            case "IExpress / WExtract":
                Add($"{q} /Q", "Quiet mode; the author's post-extract command still runs.");
                Add($"{q} /Q /T:\"C:\\Temp\\extracted\" /C", "Extract only.", Confidence.Medium, "Info");
                break;
            case "WinRAR SFX":
                Add($"{q} /S", "Silent extraction; the SFX may then run an inner setup - watch the Processes tab.");
                break;
            case "7-Zip SFX":
                Add($"{q} -y", "7-Zip SFX: -y answers yes to all prompts; inner setup shows up as a child process.");
                Add($"{q} -y -gm2 -o\"C:\\Temp\\extracted\"", "Extract only (7zSD modified modules).", Confidence.Low, "Info");
                break;
        }
    }

    // ---------------------------------------------------------------- helpers

    public static string Quote(string s) => s.Contains(' ') || s.Contains('%') ? $"\"{s}\"" : s;

    private static string San(string s) => new(s.Where(ch => !System.IO.Path.GetInvalidFileNameChars().Contains(ch)).ToArray());

    private static void AddInfo(AnalysisResult r, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) r.Info[key] = value.Trim();
    }

    private static (byte[] head, byte[] tail, long length) ReadHeadTail(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        long len = fs.Length;
        var head = new byte[(int)Math.Min(len, HeadBytes)];
        fs.ReadExactly(head);
        byte[] tail = Array.Empty<byte>();
        if (len > HeadBytes)
        {
            long start = Math.Max(HeadBytes, len - TailBytes);
            tail = new byte[len - start];
            fs.Seek(start, SeekOrigin.Begin);
            fs.ReadExactly(tail);
        }
        return (head, tail, len);
    }

    /// <summary>Returns section names and the offset where the overlay (appended data) begins.</summary>
    private static List<string> ReadPeSections(byte[] b, out long overlayOffset)
    {
        overlayOffset = 0;
        var names = new List<string>();
        try
        {
            if (b.Length < 0x40 || b[0] != 'M' || b[1] != 'Z') return names;
            int pe = BitConverter.ToInt32(b, 0x3C);
            if (pe <= 0 || pe + 24 > b.Length || b[pe] != 'P' || b[pe + 1] != 'E') return names;
            int numSections = BitConverter.ToUInt16(b, pe + 6);
            int optSize = BitConverter.ToUInt16(b, pe + 20);
            int table = pe + 24 + optSize;
            for (int i = 0; i < numSections && table + (i + 1) * 40 <= b.Length; i++)
            {
                int s = table + i * 40;
                names.Add(Encoding.ASCII.GetString(b, s, 8).TrimEnd('\0'));
                long rawSize = BitConverter.ToUInt32(b, s + 16);
                long rawPtr = BitConverter.ToUInt32(b, s + 20);
                overlayOffset = Math.Max(overlayOffset, rawPtr + rawSize);
            }
        }
        catch { }
        return names;
    }

    private static bool ContainsAscii(byte[] data, string s) =>
        data.Length > 0 && data.AsSpan().IndexOf(Encoding.ASCII.GetBytes(s)) >= 0;

    private static bool ContainsUtf16(byte[] data, string s) =>
        data.Length > 0 && data.AsSpan().IndexOf(Encoding.Unicode.GetBytes(s)) >= 0;

    private static int IndexOf(byte[] data, byte[] needle, int start) =>
        data.Length <= start ? -1 : data.AsSpan(start).IndexOf(needle);
}
