# InstallWalker

Follows a Windows installer (EXE, MSI, MSP, MSIX) from start to end and records what it changed, so you can build a silent install.

## What it does

| Area | How |
|---|---|
| **Silent-switch discovery (before running)** | Checks PE sections, version resources and byte signatures in the stub and overlay. It recognises WiX Burn, Inno Setup, NSIS (including electron-builder), InstallShield (Basic MSI and InstallScript), Advanced Installer, InstallAware, Wise, Setup Factory, InstallAnywhere, Squirrel, Smart Install Maker, Clickteam, IExpress, WinRAR SFX, 7-Zip SFX, MSI, MSP and MSIX. For MSIs it reads the Property table (ProductCode, INSTALLDIR and so on) through `msi.dll`. |
| **Help probe** (optional button) | Runs the EXE with `/?`, `/help` and `--help`. It captures console output and dialog text, pulls out anything that looks like a switch, then kills the process tree. |
| **Silent-switch discovery (during the run)** | Watches the installer's process tree through WMI. When a bootstrapper hands an MSI to `msiexec`, the exact command line and the MSI path are shown with **Confirmed** confidence. Child EXEs launched from temp are analysed too. |
| **Files and paths** | Uses `FileSystemWatcher` on the system drive (you can change this in Settings) with a noise-exclusion list. Each path gets a net result: Added, Modified, Deleted or Transient (created and then deleted). Each path is also sorted into an area: Install, Temp, Shortcut, UserProfile or System. |
| **Installer temp location** | Groups temp activity by the top-level folder created under `%TEMP%`, `C:\Windows\Temp` and so on. The folder a child installer process actually ran from is marked as primary (★). |
| **Payload preservation** | Copies `.msi`, `.msp`, `.mst`, `.cab` and `.exe` files from temp into `Captures\<timestamp>\` next to InstallWalker, before the installer deletes them. |
| **Registry** | Takes a snapshot before and after the run of the Uninstall, Run, App Paths and Services keys, Environment, fonts, and vendor keys under HKLM/HKCU `SOFTWARE`. New vendor keys are walked all the way down. |
| **Uninstall and detection** | New Uninstall keys produce `QuietUninstallString` / `msiexec /x {GUID} /qn` commands, a detection-rule key path and the ProductCode. |
| **Export** | Writes `report.json`, `files.csv`, `registry.csv`, `changes.reg`, `silent-commands.txt`, `install.cmd`, `uninstall.cmd` and `session.log`. |

## Build

Needs the .NET 8 SDK on Windows 10 or 11.

```
cd src\InstallWalker
dotnet build -c Release
```

To build a single self-contained EXE:

```
dotnet publish src\InstallWalker -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish
```

Or run `build.cmd`.

## Use

1. Run `InstallWalker.exe`. It asks for elevation, because it needs admin to see Program Files, HKLM and other processes' command lines.
2. Browse to or drop in the installer. **Analyze** runs automatically and fills the silent-commands list.
3. Optional: **Probe help (/?)** to read the installer's own switch documentation.
4. **Launch & Monitor**, then click through the install as normal. When the installer's process tree exits, auto-stop waits 8 s and then takes the final snapshot. You can also press **Stop**.
5. Review the **Files & paths**, **Temp locations**, **Processes** and **Registry** tabs. Right-click a silent command and choose **Test this command now** to re-run the installer with that command and check that it really is silent.
6. **Export report...**

Tip: use a clean VM snapshot for each capture. Background Windows activity still shows up, so extend the exclusion list in **Settings** if a path is noisy.

## Layout

```
src/InstallWalker/
  Program.cs                 entry point
  app.manifest               requireAdministrator, PerMonitorV2 DPI, long paths
  Core/InstallerAnalyzer.cs  signature detection and silent-switch table
  Core/MsiDatabase.cs        msi.dll P/Invoke (Property table)
  Core/HelpProbe.cs          /? probe, window-text capture, switch extraction
  Core/ProcessTree.cs        WMI process tree tracking (plus msiexec service children)
  Core/RegistrySnapshot.cs   before/after snapshot, diff, .reg export
  Core/InstallMonitor.cs     session orchestration: watchers, temp, payloads, discovery
  Core/ReportExporter.cs     JSON/CSV/.reg/.cmd export
  UI/MainForm.cs             WinForms UI (code only, no designer file)
```

## Known limits / next steps

- `FileSystemWatcher` can overflow when there is a burst of activity. The overflow count is shown in the status bar. ETW kernel file tracing (TraceEvent) would give per-process attribution with no losses.
- Registry changes deeper than depth 2 under **existing** vendor keys are not seen. An ETW registry provider or a full hive diff would close that gap.
- Services, scheduled tasks, firewall rules, drivers and MSIX provisioning are only partly covered, through the Services key and the file watcher.
