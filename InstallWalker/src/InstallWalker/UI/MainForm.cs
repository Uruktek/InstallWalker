using System.Diagnostics;
using InstallWalker.Core;

namespace InstallWalker.UI;

public sealed class MainForm : Form
{
    // ---- top bar
    private readonly TextBox _txtInstaller = new() { Dock = DockStyle.Fill, PlaceholderText = "Pick or drop an .exe / .msi / .msp / .msix installer" };
    private readonly Button _btnBrowse = new() { Text = "Browse...", AutoSize = true };
    private readonly Button _btnAnalyze = new() { Text = "Analyze", AutoSize = true };
    private readonly Button _btnProbe = new() { Text = "Probe help (/?)", AutoSize = true };
    private readonly TextBox _txtArgs = new() { Dock = DockStyle.Fill, PlaceholderText = "Optional arguments passed when launching (leave empty for a normal interactive install)" };
    private readonly Button _btnLaunch = new() { Text = "▶ Launch && Monitor", AutoSize = true, Font = new Font(SystemFonts.MessageBoxFont!, FontStyle.Bold) };
    private readonly Button _btnMonitorOnly = new() { Text = "Monitor only", AutoSize = true };
    private readonly Button _btnStop = new() { Text = "■ Stop", AutoSize = true, Enabled = false };
    private readonly Button _btnExport = new() { Text = "Export report...", AutoSize = true, Enabled = false };
    private readonly CheckBox _chkAutoStop = new() { Text = "Auto-stop when installer exits", AutoSize = true, Checked = true };
    private readonly Label _lblTech = new() { AutoSize = true, Text = "Technology: (not analyzed)", Font = new Font(SystemFonts.MessageBoxFont!, FontStyle.Bold) };
    private readonly LinkLabel _lnkTemp = new() { AutoSize = true, Text = "Installer temp location: (not started)" };

    // ---- silent commands
    private readonly ListView _lvSilent = MakeList(("Confidence", 80), ("Kind", 70), ("Technology", 150), ("Command", 520), ("Source", 200), ("Notes", 400));

    // ---- tabs
    private readonly TabControl _tabs = new() { Dock = DockStyle.Fill };
    private readonly ListView _lvFiles = MakeList(("Result", 75), ("Area", 80), ("File name", 220), ("Directory", 520), ("Size", 90), ("First seen", 90), ("Events", 55));
    private readonly TextBox _txtFilter = new() { Width = 260, PlaceholderText = "Filter path..." };
    private readonly ComboBox _cboArea = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120 };
    private readonly CheckBox _chkHideTransient = new() { Text = "Hide transient", AutoSize = true };
    private readonly CheckBox _chkHideDirs = new() { Text = "Hide folders", AutoSize = true };
    private readonly CheckBox _chkOnlyAdded = new() { Text = "Only added", AutoSize = true };
    private readonly Label _lblFileCount = new() { AutoSize = true, Padding = new Padding(8, 6, 0, 0) };
    private readonly ListView _lvTemp = MakeList(("Primary", 60), ("Path", 520), ("Files", 60), ("First seen", 90), ("Reason", 350));
    private readonly ListView _lvProc = MakeList(("PID", 60), ("Parent", 60), ("Depth", 50), ("Name", 160), ("Started", 90), ("Exited", 90), ("Command line", 800));
    private readonly ListView _lvReg = MakeList(("Change", 100), ("Key", 520), ("Value", 160), ("Old data", 200), ("New data", 300));
    private readonly TextBox _txtInfo = MakeTextArea();
    private readonly TextBox _txtLog = MakeTextArea();
    private readonly TextBox _txtRoots = MakeTextArea(readOnly: false);
    private readonly TextBox _txtExcl = MakeTextArea(readOnly: false);
    private readonly CheckBox _chkRegistry = new() { Text = "Capture registry before/after", Checked = true, AutoSize = true };
    private readonly CheckBox _chkPreserve = new() { Text = "Preserve payloads (.msi/.exe/.cab) extracted to temp", Checked = true, AutoSize = true };

    private readonly ToolStripStatusLabel _status = new() { Spring = true, TextAlign = ContentAlignment.MiddleLeft, Text = "Ready. Run as administrator for full coverage." };
    private readonly ToolStripStatusLabel _counts = new();
    private readonly System.Windows.Forms.Timer _refresh = new() { Interval = 500 };

    private InstallMonitor? _monitor;
    private AnalysisResult? _analysis;
    private List<FileRecord> _fileView = new();
    private List<RegistryChange> _regView = new();
    private int _fileSortCol = 3; private bool _fileSortDesc;
    private DateTime? _treeGoneSince;
    private Process? _rootProcess;
    private Font? _boldFont;

    public MainForm(string? initialInstaller)
    {
        Text = "InstallWalker – follow an installer from start to end";
        Width = 1400; Height = 900; StartPosition = FormStartPosition.CenterScreen;
        Font = SystemFonts.MessageBoxFont!;
        AllowDrop = true;
        BuildLayout();
        WireEvents();
        _txtRoots.Text = string.Join(Environment.NewLine, MonitorOptions.DefaultRoots());
        _txtExcl.Text = string.Join(Environment.NewLine, MonitorOptions.DefaultExclusions());
        _cboArea.Items.AddRange(new object[] { "All areas" }.Concat(Enum.GetNames<FileArea>()).ToArray());
        _cboArea.SelectedIndex = 0;
        if (initialInstaller != null) { _txtInstaller.Text = initialInstaller; _ = AnalyzeAsync(); }
    }

    // =====================================================================================
    // Layout
    // =====================================================================================

    private void BuildLayout()
    {
        var top = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 6, Padding = new Padding(8, 8, 8, 4) };
        top.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        top.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (int i = 0; i < 4; i++) top.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        top.Controls.Add(new Label { Text = "Installer:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
        top.Controls.Add(_txtInstaller, 1, 0);
        top.Controls.Add(_btnBrowse, 2, 0);
        top.Controls.Add(_btnAnalyze, 3, 0);
        top.Controls.Add(_btnProbe, 4, 0);

        top.Controls.Add(new Label { Text = "Arguments:", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 1);
        top.Controls.Add(_txtArgs, 1, 1);
        var actions = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = Padding.Empty };
        actions.Controls.AddRange(new Control[] { _btnLaunch, _btnMonitorOnly, _btnStop, _btnExport });
        top.Controls.Add(actions, 2, 1);
        top.SetColumnSpan(actions, 4);

        var info = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 4, 0, 0) };
        info.Controls.AddRange(new Control[] { _lblTech, new Label { Width = 30 }, _lnkTemp, new Label { Width = 30 }, _chkAutoStop });
        top.Controls.Add(info, 0, 2);
        top.SetColumnSpan(info, 6);

        // Silent commands group
        var grpSilent = new GroupBox { Text = "Silent install / uninstall commands discovered  (double-click to copy)", Dock = DockStyle.Fill, Padding = new Padding(6) };
        grpSilent.Controls.Add(_lvSilent);
        var silentMenu = new ContextMenuStrip();
        silentMenu.Items.Add("Copy command", null, (_, _) => CopySelected(_lvSilent, 3));
        silentMenu.Items.Add("Copy row", null, (_, _) => CopySelected(_lvSilent, -1));
        silentMenu.Items.Add("Test this command now (launch && monitor)", null, (_, _) => TestSelectedCommand());
        _lvSilent.ContextMenuStrip = silentMenu;

        // Files tab
        var filesTop = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4) };
        filesTop.Controls.AddRange(new Control[] { _txtFilter, _cboArea, _chkOnlyAdded, _chkHideTransient, _chkHideDirs, _lblFileCount });
        _lvFiles.VirtualMode = true;
        _lvFiles.RetrieveVirtualItem += (_, e) => e.Item = e.ItemIndex < _fileView.Count ? FileItem(_fileView[e.ItemIndex]) : new ListViewItem(new string[7]);
        var filesMenu = new ContextMenuStrip();
        filesMenu.Items.Add("Open containing folder", null, (_, _) => OpenSelectedFileFolder());
        filesMenu.Items.Add("Copy full path", null, (_, _) => CopyFilePaths());
        _lvFiles.ContextMenuStrip = filesMenu;
        AddTab("Files && paths", _lvFiles, filesTop);

        AddTab("Temp locations", _lvTemp);
        AddTab("Processes", _lvProc);

        _lvReg.VirtualMode = true;
        _lvReg.RetrieveVirtualItem += (_, e) =>
        {
            if (e.ItemIndex >= _regView.Count) { e.Item = new ListViewItem(new string[5]); return; }
            var r = _regView[e.ItemIndex];
            e.Item = new ListViewItem(new[] { r.Change, r.Key, r.ValueName ?? "", r.OldData ?? "", r.NewData ?? "" })
            {
                ForeColor = r.Change.EndsWith("Deleted") ? Color.Firebrick : r.Change.EndsWith("Added") ? Color.DarkGreen : Color.DarkGoldenrod
            };
        };
        AddTab("Registry", _lvReg);
        AddTab("Installer info", _txtInfo);
        AddTab("Log", _txtLog);

        var settings = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 3, Padding = new Padding(6) };
        settings.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 35));
        settings.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 65));
        settings.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        settings.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        settings.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        settings.Controls.Add(new Label { Text = "Watch roots (one per line, recursive):", AutoSize = true }, 0, 0);
        settings.Controls.Add(new Label { Text = "Exclude paths containing (one per line):", AutoSize = true }, 1, 0);
        settings.Controls.Add(_txtRoots, 0, 1);
        settings.Controls.Add(_txtExcl, 1, 1);
        var opts = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill };
        opts.Controls.AddRange(new Control[] { _chkRegistry, _chkPreserve });
        settings.Controls.Add(opts, 0, 2);
        settings.SetColumnSpan(opts, 2);
        AddTab("Settings", settings);

        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterDistance = 230 };
        split.Panel1.Controls.Add(grpSilent);
        split.Panel2.Controls.Add(_tabs);

        var strip = new StatusStrip();
        strip.Items.AddRange(new ToolStripItem[] { _status, _counts });

        Controls.Add(split);
        Controls.Add(top);
        Controls.Add(strip);
        Load += (_, _) => split.SplitterDistance = 240;
    }

    private void AddTab(string title, Control content, Control? header = null)
    {
        var page = new TabPage(title);
        page.Controls.Add(content);
        if (header != null) page.Controls.Add(header);
        _tabs.TabPages.Add(page);
    }

    private static ListView MakeList(params (string title, int width)[] cols)
    {
        var lv = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, HideSelection = false };
        foreach (var (t, w) in cols) lv.Columns.Add(t, w);
        typeof(ListView).GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)?.SetValue(lv, true);
        return lv;
    }

    private static TextBox MakeTextArea(bool readOnly = true) => new()
    {
        Dock = DockStyle.Fill, Multiline = true, ScrollBars = ScrollBars.Both, WordWrap = false,
        ReadOnly = readOnly, Font = new Font(FontFamily.GenericMonospace, 9f), BackColor = readOnly ? SystemColors.Window : SystemColors.Window,
    };

    // =====================================================================================
    // Events
    // =====================================================================================

    private void WireEvents()
    {
        _btnBrowse.Click += (_, _) => Browse();
        _btnAnalyze.Click += async (_, _) => await AnalyzeAsync();
        _btnProbe.Click += async (_, _) => await ProbeAsync();
        _btnLaunch.Click += async (_, _) => await StartSessionAsync(launch: true);
        _btnMonitorOnly.Click += async (_, _) => await StartSessionAsync(launch: false);
        _btnStop.Click += async (_, _) => await StopSessionAsync();
        _btnExport.Click += (_, _) => Export();
        _refresh.Tick += (_, _) => RefreshViews();
        _lnkTemp.LinkClicked += (_, _) => { if (_monitor?.PrimaryTemp is { } t) OpenFolder(t.Path); };
        _lvSilent.DoubleClick += (_, _) => CopySelected(_lvSilent, 3);
        _lvTemp.DoubleClick += (_, _) => { if (_lvTemp.SelectedItems.Count > 0) OpenFolder(_lvTemp.SelectedItems[0].SubItems[1].Text); };
        _lvFiles.DoubleClick += (_, _) => OpenSelectedFileFolder();
        _lvFiles.ColumnClick += (_, e) => { _fileSortDesc = _fileSortCol == e.Column && !_fileSortDesc; _fileSortCol = e.Column; RebuildFileView(); };
        _txtFilter.TextChanged += (_, _) => RebuildFileView();
        _cboArea.SelectedIndexChanged += (_, _) => RebuildFileView();
        _chkHideTransient.CheckedChanged += (_, _) => RebuildFileView();
        _chkHideDirs.CheckedChanged += (_, _) => RebuildFileView();
        _chkOnlyAdded.CheckedChanged += (_, _) => RebuildFileView();
        DragEnter += (_, e) => e.Effect = e.Data?.GetDataPresent(DataFormats.FileDrop) == true ? DragDropEffects.Copy : DragDropEffects.None;
        DragDrop += async (_, e) =>
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } f) { _txtInstaller.Text = f[0]; await AnalyzeAsync(); }
        };
        FormClosing += (_, _) => { _refresh.Stop(); _monitor?.Dispose(); };
    }

    private void Browse()
    {
        using var dlg = new OpenFileDialog
        {
            Filter = "Installers (*.exe;*.msi;*.msp;*.msix;*.msixbundle;*.appx)|*.exe;*.msi;*.msp;*.msix;*.msixbundle;*.appx|All files (*.*)|*.*",
            Title = "Choose installer"
        };
        if (dlg.ShowDialog(this) == DialogResult.OK) { _txtInstaller.Text = dlg.FileName; _ = AnalyzeAsync(); }
    }

    // =====================================================================================
    // Static analysis
    // =====================================================================================

    private async Task AnalyzeAsync()
    {
        var path = _txtInstaller.Text.Trim('"', ' ');
        if (!File.Exists(path)) { SetStatus("Installer not found."); return; }
        SetStatus("Analyzing " + Path.GetFileName(path) + "...");
        UseWaitCursor = true;
        try
        {
            _analysis = await Task.Run(() => InstallerAnalyzer.Analyze(path));
            _lblTech.Text = "Technology: " + _analysis.Technology;
            _lvSilent.Items.Clear();
            foreach (var c in _analysis.Candidates) AddSilentRow(c);
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("File: " + path).AppendLine("Technology: " + _analysis.Technology).AppendLine();
            sb.AppendLine("--- Details ---");
            foreach (var (k, v) in _analysis.Info) sb.AppendLine($"{k,-20} {v}");
            sb.AppendLine().AppendLine("--- Evidence ---");
            foreach (var e in _analysis.Evidence) sb.AppendLine("• " + e);
            _txtInfo.Text = sb.ToString();
            SetStatus($"Analysis done: {_analysis.Technology}, {_analysis.Candidates.Count} candidate command(s).");
        }
        catch (Exception ex) { SetStatus("Analysis failed: " + ex.Message); }
        finally { UseWaitCursor = false; }
    }

    private async Task ProbeAsync()
    {
        var path = _txtInstaller.Text.Trim('"', ' ');
        if (!File.Exists(path) || !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        { SetStatus("Help probe only applies to .exe installers."); return; }
        if (MessageBox.Show(this,
                "This runs the installer with /?, /help and --help for a few seconds each, reads any output or dialog text, then kills it.\n\n" +
                "Most installers only show a help box, but an installer that ignores these switches may begin its normal UI (it is terminated before you can click through). Continue?",
                "Probe help", MessageBoxButtons.OKCancel, MessageBoxIcon.Information) != DialogResult.OK) return;

        _btnProbe.Enabled = false;
        SetStatus("Probing help output...");
        try
        {
            var results = await HelpProbe.RunAsync(path, TimeSpan.FromSeconds(5), CancellationToken.None);
            var sb = new System.Text.StringBuilder(_txtInfo.Text).AppendLine().AppendLine("--- Help probe ---");
            foreach (var r in results)
            {
                sb.AppendLine($"[{r.Argument}] switches found: {(r.Switches.Count == 0 ? "(none)" : string.Join(" ", r.Switches))}");
                if (r.Text.Length > 0) sb.AppendLine(r.Text.Replace("\n", Environment.NewLine + "    ")).AppendLine();
            }
            _txtInfo.Text = sb.ToString();

            var all = results.SelectMany(r => r.Switches).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var silent = all.Where(s => System.Text.RegularExpressions.Regex.IsMatch(s,
                @"^(/|--?)(s|q|qn|quiet|silent|verysilent|passive|unattended|norestart|suppressmsgboxes|sp-|exenoui|mode)", System.Text.RegularExpressions.RegexOptions.IgnoreCase)).ToList();
            if (silent.Count > 0)
            {
                var c = new SilentCandidate
                {
                    Technology = "Documented by installer", Confidence = Confidence.High, Source = "Help probe",
                    Command = $"{InstallerAnalyzer.Quote(path)} {string.Join(" ", silent)}",
                    Notes = "All switches found in help text: " + string.Join(" ", all),
                };
                _analysis?.Candidates.Add(c);
                AddSilentRow(c);
            }
            _tabs.SelectedIndex = 4;
            SetStatus($"Help probe finished: {all.Count} switch(es) found.");
        }
        catch (Exception ex) { SetStatus("Probe failed: " + ex.Message); }
        finally { _btnProbe.Enabled = true; }
    }

    // =====================================================================================
    // Monitoring session
    // =====================================================================================

    private async Task StartSessionAsync(bool launch, string? overrideArgs = null)
    {
        var path = _txtInstaller.Text.Trim('"', ' ');
        if (launch && !File.Exists(path)) { SetStatus("Choose an installer first."); return; }
        if (launch && _analysis == null) await AnalyzeAsync();

        _monitor?.Dispose();
        var options = new MonitorOptions
        {
            WatchRoots = Lines(_txtRoots.Text),
            Exclusions = Lines(_txtExcl.Text),
            CaptureRegistry = _chkRegistry.Checked,
            PreservePayloads = _chkPreserve.Checked,
        };
        _monitor = new InstallMonitor(options);
        _monitor.Log += line => BeginInvokeSafe(() => _txtLog.AppendText(line + Environment.NewLine));
        _monitor.CandidateFound += c => BeginInvokeSafe(() => AddSilentRow(c));

        _lvTemp.Items.Clear(); _lvProc.Items.Clear(); _txtLog.Clear();
        _fileView.Clear(); _lvFiles.VirtualListSize = 0; _regView.Clear(); _lvReg.VirtualListSize = 0;
        _treeGoneSince = null;
        SetRunning(true);
        SetStatus("Arming watchers and taking registry baseline...");

        await _monitor.ArmAsync();

        if (launch)
        {
            try
            {
                _rootProcess = _monitor.Launch(path, overrideArgs ?? _txtArgs.Text.Trim());
                SetStatus($"Monitoring {Path.GetFileName(path)} (PID {_rootProcess?.Id}). Complete the install, then press Stop (or let auto-stop do it).");
            }
            catch (Exception ex)
            {
                SetStatus("Launch failed: " + ex.Message);
                await StopSessionAsync();
                return;
            }
        }
        else
        {
            _monitor.StartProcessTracking(0);
            SetStatus("Monitoring the whole system. Start your installer now, then press Stop when it's done.");
        }
        _refresh.Start();
    }

    private async Task StopSessionAsync()
    {
        if (_monitor == null) return;
        _refresh.Stop();
        _btnStop.Enabled = false;
        SetStatus("Stopping - collecting final state and diffing registry...");
        UseWaitCursor = true;
        try { await _monitor.StopAsync(); }
        finally { UseWaitCursor = false; }
        RefreshViews();
        _regView = _monitor.RegistryChanges;
        _lvReg.VirtualListSize = _regView.Count;
        _lvReg.Invalidate();
        SetRunning(false);
        _btnExport.Enabled = true;
        SetStatus($"Done. {_monitor.Files.Count:N0} paths, {_monitor.RegistryChanges.Count:N0} registry changes, {_lvSilent.Items.Count} commands. Use Export to save everything.");
    }

    private void TestSelectedCommand()
    {
        if (_lvSilent.SelectedItems.Count == 0 || _monitor?.IsRunning == true) return;
        var cmd = _lvSilent.SelectedItems[0].SubItems[3].Text;
        var path = _txtInstaller.Text.Trim('"', ' ');
        var q = InstallerAnalyzer.Quote(path);
        string? args = null;
        if (cmd.StartsWith(q, StringComparison.OrdinalIgnoreCase)) args = cmd[q.Length..].Trim();
        else if (cmd.StartsWith("msiexec.exe /i " + q, StringComparison.OrdinalIgnoreCase)) args = cmd[("msiexec.exe /i " + q).Length..].Trim();
        if (args == null) { MessageBox.Show(this, "Only commands for the selected installer can be tested from here.", "Test command"); return; }
        if (MessageBox.Show(this, $"Launch the installer with:\n\n{args}\n\nand monitor it?", "Test silent command", MessageBoxButtons.OKCancel) == DialogResult.OK)
        {
            _txtArgs.Text = args;
            _ = StartSessionAsync(launch: true, overrideArgs: args);
        }
    }

    private void SetRunning(bool running)
    {
        _btnLaunch.Enabled = _btnMonitorOnly.Enabled = _btnAnalyze.Enabled = _btnProbe.Enabled = _btnBrowse.Enabled = !running;
        _btnStop.Enabled = running;
        _txtRoots.ReadOnly = _txtExcl.ReadOnly = running;
        if (running) _btnExport.Enabled = false;
    }

    // =====================================================================================
    // Refresh
    // =====================================================================================

    private void RefreshViews()
    {
        if (_monitor == null) return;
        RebuildFileView();

        // Temp
        var temps = _monitor.TempLocations.OrderByDescending(t => t.IsPrimary).ThenBy(t => t.FirstSeen).ToList();
        _lvTemp.BeginUpdate();
        _lvTemp.Items.Clear();
        foreach (var t in temps)
            _lvTemp.Items.Add(new ListViewItem(new[] { t.IsPrimary ? "★" : "", t.Path, t.FileCount.ToString(), t.FirstSeen.ToString("HH:mm:ss"), t.Reason })
            { Font = t.IsPrimary ? (_boldFont ??= new Font(_lvTemp.Font, FontStyle.Bold)) : _lvTemp.Font });
        _lvTemp.EndUpdate();
        _lnkTemp.Text = "Installer temp location: " + (_monitor.PrimaryTemp?.Path ?? "(none detected yet)");

        // Processes
        var procs = _monitor.Processes?.Processes.OrderBy(p => p.Started).ToList() ?? new();
        if (procs.Count != _lvProc.Items.Count || procs.Any(p => p.Exited != null))
        {
            _lvProc.BeginUpdate();
            _lvProc.Items.Clear();
            foreach (var p in procs)
                _lvProc.Items.Add(new ListViewItem(new[]
                {
                    p.Pid.ToString(), p.ParentPid.ToString(), p.Depth < 0 ? "msi svc" : p.Depth.ToString(),
                    (p.Depth > 0 ? new string(' ', p.Depth * 2) : "") + p.Name,
                    p.Started.ToString("HH:mm:ss"), p.Exited?.ToString("HH:mm:ss") ?? "running", p.CommandLine ?? p.ExecutablePath ?? ""
                }) { ForeColor = p.Exited == null ? Color.DarkGreen : SystemColors.GrayText });
            _lvProc.EndUpdate();
        }

        _counts.Text = $"Files: {_monitor.Files.Count:N0}   Temp: {temps.Count}   Processes: {procs.Count}   Overflows: {_monitor.OverflowCount}";
        CheckAutoStop(procs);
    }

    private void CheckAutoStop(List<ProcessRecord> procs)
    {
        if (!_chkAutoStop.Checked || _monitor is not { IsRunning: true } || _rootProcess == null) return;
        // Ignore the long-lived Windows Installer service host (msiexec /V).
        bool alive = procs.Any(p => p.Exited == null &&
            !(p.Depth < 0 && (p.CommandLine?.Contains(" /V", StringComparison.OrdinalIgnoreCase) ?? false)));
        bool rootExited;
        try { rootExited = _rootProcess.HasExited; } catch { rootExited = true; }
        if (rootExited && !alive)
        {
            _treeGoneSince ??= DateTime.Now;
            var left = 8 - (DateTime.Now - _treeGoneSince.Value).TotalSeconds;
            SetStatus($"Installer finished - settling, auto-stop in {Math.Max(0, left):N0}s...");
            if (left <= 0) _ = StopSessionAsync();
        }
        else _treeGoneSince = null;
    }

    private void RebuildFileView()
    {
        if (_monitor == null) return;
        IEnumerable<FileRecord> q = _monitor.Files;
        var f = _txtFilter.Text.Trim();
        if (f.Length > 0) q = q.Where(r => r.Path.Contains(f, StringComparison.OrdinalIgnoreCase));
        if (_cboArea.SelectedIndex > 0 && Enum.TryParse<FileArea>(_cboArea.SelectedItem as string, out var area)) q = q.Where(r => r.Area == area);
        if (_chkHideTransient.Checked) q = q.Where(r => !r.Transient);
        if (_chkHideDirs.Checked) q = q.Where(r => !r.IsDirectory);
        if (_chkOnlyAdded.Checked) q = q.Where(r => r.NetResult == "Added");

        Func<FileRecord, object> key = _fileSortCol switch
        {
            0 => r => r.NetResult, 1 => r => r.Area.ToString(), 2 => r => r.FileName, 4 => r => r.Size ?? -1,
            5 => r => r.FirstSeen, 6 => r => r.EventCount, _ => r => r.Path,
        };
        q = _fileSortDesc ? q.OrderByDescending(key) : q.OrderBy(key);
        _fileView = q.ToList();
        _lvFiles.VirtualListSize = _fileView.Count;
        _lvFiles.Invalidate();
        _lblFileCount.Text = $"{_fileView.Count:N0} shown";
    }

    private static ListViewItem FileItem(FileRecord r)
    {
        var item = new ListViewItem(new[]
        {
            r.NetResult, r.Area.ToString(), r.IsDirectory ? r.FileName + "\\" : r.FileName, r.Directory,
            r.Size is long s ? FormatSize(s) : "", r.FirstSeen.ToString("HH:mm:ss"), r.EventCount.ToString()
        });
        item.ForeColor = r.NetResult switch
        {
            "Added" => Color.DarkGreen, "Deleted" => Color.Firebrick, "Transient" => SystemColors.GrayText, _ => Color.DarkGoldenrod
        };
        if (r.Area == FileArea.Temp) item.BackColor = Color.FromArgb(255, 250, 235);
        return item;
    }

    private void AddSilentRow(SilentCandidate c)
    {
        foreach (ListViewItem existing in _lvSilent.Items)
            if (existing.SubItems[1].Text == c.Kind && existing.SubItems[3].Text == c.Command) return;
        var item = new ListViewItem(new[] { c.Confidence.ToString(), c.Kind, c.Technology, c.Command, c.Source, c.Notes })
        {
            ForeColor = c.Confidence switch
            {
                Confidence.Confirmed => Color.DarkGreen, Confidence.High => Color.ForestGreen,
                Confidence.Medium => Color.DarkGoldenrod, _ => SystemColors.GrayText
            },
            Tag = c,
        };
        // Keep the best install commands at the top.
        int rank(SilentCandidate s) => (s.Kind == "Install" ? 100 : s.Kind == "Uninstall" ? 50 : 0) + (int)s.Confidence * 10;
        int idx = 0;
        while (idx < _lvSilent.Items.Count && _lvSilent.Items[idx].Tag is SilentCandidate o && rank(o) >= rank(c)) idx++;
        _lvSilent.Items.Insert(idx, item);
    }

    // =====================================================================================
    // Export & helpers
    // =====================================================================================

    private void Export()
    {
        if (_monitor == null) return;
        using var dlg = new FolderBrowserDialog { Description = "Choose where to save the InstallWalker report", UseDescriptionForTitle = true };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        var name = Path.GetFileNameWithoutExtension(_monitor.InstallerPath ?? "session");
        var folder = Path.Combine(dlg.SelectedPath, $"InstallWalker_{name}_{_monitor.Started:yyyyMMdd_HHmmss}");
        try
        {
            ReportExporter.Export(_monitor, _analysis, folder);
            SetStatus("Report exported to " + folder);
            OpenFolder(folder);
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Export failed", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    private void CopySelected(ListView lv, int column)
    {
        if (lv.SelectedItems.Count == 0) return;
        var text = string.Join(Environment.NewLine, lv.SelectedItems.Cast<ListViewItem>().Select(i =>
            column >= 0 ? i.SubItems[column].Text : string.Join("\t", i.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(s => s.Text))));
        Clipboard.SetText(text);
        SetStatus("Copied to clipboard.");
    }

    private void CopyFilePaths()
    {
        var paths = _lvFiles.SelectedIndices.Cast<int>().Select(i => _fileView[i].Path).ToList();
        if (paths.Count > 0) { Clipboard.SetText(string.Join(Environment.NewLine, paths)); SetStatus($"Copied {paths.Count} path(s)."); }
    }

    private void OpenSelectedFileFolder()
    {
        if (_lvFiles.SelectedIndices.Count == 0) return;
        var r = _fileView[_lvFiles.SelectedIndices[0]];
        if (File.Exists(r.Path)) Process.Start("explorer.exe", $"/select,\"{r.Path}\"");
        else OpenFolder(r.Directory);
    }

    private void OpenFolder(string path)
    {
        if (Directory.Exists(path)) Process.Start("explorer.exe", $"\"{path}\"");
        else SetStatus("Folder no longer exists (the installer probably cleaned it up): " + path);
    }

    private static List<string> Lines(string s) =>
        s.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

    private static string FormatSize(long b) =>
        b >= 1 << 30 ? $"{b / (double)(1 << 30):N1} GB" : b >= 1 << 20 ? $"{b / (double)(1 << 20):N1} MB" : b >= 1024 ? $"{b / 1024.0:N0} KB" : $"{b} B";

    private void SetStatus(string s) => _status.Text = s;

    private void BeginInvokeSafe(Action a)
    {
        if (IsDisposed || !IsHandleCreated) return;
        try { BeginInvoke(a); } catch (ObjectDisposedException) { } catch (InvalidOperationException) { }
    }
}
