using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace InstallWalker.Core;

/// <summary>
/// Runs the installer with a help switch (/?, /help, --help), captures console output and the
/// text of any window it opens, then kills it. Many installers document their switches this way.
/// </summary>
public static partial class HelpProbe
{
    public sealed class ProbeResult
    {
        public string Argument { get; init; } = "";
        public string Text { get; set; } = "";
        public List<string> Switches { get; } = new();
    }

    public static async Task<List<ProbeResult>> RunAsync(string exePath, TimeSpan perAttempt, CancellationToken ct)
    {
        var results = new List<ProbeResult>();
        foreach (var arg in new[] { "/?", "/help", "--help" })
        {
            ct.ThrowIfCancellationRequested();
            var pr = await ProbeOnceAsync(exePath, arg, perAttempt, ct);
            results.Add(pr);
            // Stop early once something useful was documented.
            if (pr.Switches.Count >= 2) break;
        }
        return results;
    }

    private static async Task<ProbeResult> ProbeOnceAsync(string exePath, string arg, TimeSpan wait, CancellationToken ct)
    {
        var result = new ProbeResult { Argument = arg };
        var psi = new ProcessStartInfo(exePath, arg)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = false,
            WorkingDirectory = Path.GetDirectoryName(exePath) ?? Environment.CurrentDirectory,
        };

        var output = new StringBuilder();
        using var p = new Process { StartInfo = psi, EnableRaisingEvents = true };
        p.OutputDataReceived += (_, e) => { if (e.Data != null) lock (output) output.AppendLine(e.Data); };
        p.ErrorDataReceived += (_, e) => { if (e.Data != null) lock (output) output.AppendLine(e.Data); };

        try
        {
            p.Start();
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
        }
        catch (Exception ex)
        {
            result.Text = "Could not start: " + ex.Message;
            return result;
        }

        var windowText = new StringBuilder();
        var deadline = DateTime.UtcNow + wait;
        while (DateTime.UtcNow < deadline && !ct.IsCancellationRequested)
        {
            await Task.Delay(400, CancellationToken.None);
            var pids = ProcessTree.GetDescendants(p.Id).Append(p.Id).ToHashSet();
            var text = CaptureWindowText(pids);
            if (text.Length > windowText.Length) { windowText.Clear(); windowText.Append(text); }
            if (p.HasExited) break;
        }

        try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch { }
        try { p.WaitForExit(2000); } catch { }

        string all;
        lock (output) all = (output + Environment.NewLine + windowText).Trim();
        result.Text = all;
        result.Switches.AddRange(ExtractSwitches(all));
        return result;
    }

    /// <summary>Pulls switch-looking tokens (/S, /VERYSILENT, --silent, -q, /qn, /D=...) out of help text.</summary>
    public static IEnumerable<string> ExtractSwitches(string text)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match m in SwitchRegex().Matches(text))
        {
            var sw = m.Groups["sw"].Value.TrimEnd('.', ',', ';', ':', ')');
            if (sw.Length < 2 || sw.Length > 40) continue;
            if (seen.Add(sw)) yield return sw;
        }
    }

    [GeneratedRegex(@"(?:^|[\s\[\(""'])(?<sw>(?:--|/|-)[A-Za-z][A-Za-z0-9_\-]*(?:[=:][^\s\]\)""']*)?)", RegexOptions.Multiline)]
    private static partial Regex SwitchRegex();

    // ---------------------------------------------------------------- window text capture

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool EnumChildWindows(IntPtr parent, EnumWindowsProc cb, IntPtr lParam);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, IntPtr wParam, StringBuilder lParam, uint flags, uint timeout, out IntPtr result);
    [DllImport("user32.dll")]
    private static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam, uint flags, uint timeout, out IntPtr result);

    private const uint WM_GETTEXT = 0x000D, WM_GETTEXTLENGTH = 0x000E, SMTO_ABORTIFHUNG = 0x0002;

    public static string CaptureWindowText(HashSet<int> pids)
    {
        var sb = new StringBuilder();
        EnumWindows((hwnd, _) =>
        {
            GetWindowThreadProcessId(hwnd, out var pid);
            if (!pids.Contains((int)pid)) return true;
            AppendText(hwnd, sb);
            EnumChildWindows(hwnd, (child, _) => { AppendText(child, sb); return true; }, IntPtr.Zero);
            return true;
        }, IntPtr.Zero);
        return sb.ToString();
    }

    private static void AppendText(IntPtr hwnd, StringBuilder sb)
    {
        if (SendMessageTimeout(hwnd, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero, SMTO_ABORTIFHUNG, 500, out var lenPtr) == IntPtr.Zero) return;
        int len = (int)lenPtr;
        if (len <= 0 || len > 65536) return;
        var buf = new StringBuilder(len + 1);
        if (SendMessageTimeout(hwnd, WM_GETTEXT, (IntPtr)(len + 1), buf, SMTO_ABORTIFHUNG, 500, out _) == IntPtr.Zero) return;
        var t = buf.ToString().Trim();
        if (t.Length > 0) sb.AppendLine(t);
    }
}
