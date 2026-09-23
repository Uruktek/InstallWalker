using InstallWalker.UI;

namespace InstallWalker;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) =>
            MessageBox.Show(e.Exception.ToString(), "InstallWalker - unexpected error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);

        // Optional: InstallWalker.exe "C:\path\setup.exe" pre-loads the installer.
        var initial = args.Length > 0 && File.Exists(args[0]) ? args[0] : null;
        Application.Run(new MainForm(initial));
    }
}
