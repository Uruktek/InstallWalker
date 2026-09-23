using System.Runtime.InteropServices;
using System.Text;

namespace InstallWalker.Core;

/// <summary>Minimal read-only access to an MSI's Property table through msi.dll.</summary>
public static class MsiDatabase
{
    private const int ERROR_SUCCESS = 0;
    private const int ERROR_NO_MORE_ITEMS = 259;
    private const int ERROR_MORE_DATA = 234;
    private static readonly IntPtr MSIDBOPEN_READONLY = IntPtr.Zero;

    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    private static extern int MsiOpenDatabaseW(string szDatabasePath, IntPtr szPersist, out IntPtr phDatabase);

    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    private static extern int MsiDatabaseOpenViewW(IntPtr hDatabase, string szQuery, out IntPtr phView);

    [DllImport("msi.dll")]
    private static extern int MsiViewExecute(IntPtr hView, IntPtr hRecord);

    [DllImport("msi.dll")]
    private static extern int MsiViewFetch(IntPtr hView, out IntPtr phRecord);

    [DllImport("msi.dll", CharSet = CharSet.Unicode)]
    private static extern int MsiRecordGetStringW(IntPtr hRecord, uint iField, StringBuilder? szValueBuf, ref uint pcchValueBuf);

    [DllImport("msi.dll")]
    private static extern int MsiCloseHandle(IntPtr hAny);

    /// <summary>Returns every row of the Property table, or an empty dictionary on failure.</summary>
    public static Dictionary<string, string> ReadProperties(string msiPath)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var row in Query(msiPath, "SELECT `Property`, `Value` FROM `Property`", 2))
            result[row[0]] = row[1];
        return result;
    }

    /// <summary>True when the MSI has a table with this name (e.g. "Dialog" – no dialogs means /qn is the only mode).</summary>
    public static int CountRows(string msiPath, string table)
    {
        try { return Query(msiPath, $"SELECT * FROM `{table}`", 1).Count(); }
        catch { return -1; }
    }

    public static IEnumerable<string[]> Query(string msiPath, string sql, int columns)
    {
        if (!OperatingSystem.IsWindows()) yield break;
        IntPtr db = IntPtr.Zero, view = IntPtr.Zero;
        var rows = new List<string[]>();
        try
        {
            if (MsiOpenDatabaseW(msiPath, MSIDBOPEN_READONLY, out db) != ERROR_SUCCESS) yield break;
            if (MsiDatabaseOpenViewW(db, sql, out view) != ERROR_SUCCESS) yield break;
            if (MsiViewExecute(view, IntPtr.Zero) != ERROR_SUCCESS) yield break;
            while (MsiViewFetch(view, out var rec) == ERROR_SUCCESS)
            {
                try
                {
                    var row = new string[columns];
                    for (uint i = 1; i <= columns; i++) row[i - 1] = GetString(rec, i);
                    rows.Add(row);
                }
                finally { MsiCloseHandle(rec); }
            }
        }
        finally
        {
            if (view != IntPtr.Zero) MsiCloseHandle(view);
            if (db != IntPtr.Zero) MsiCloseHandle(db);
        }
        foreach (var r in rows) yield return r;
    }

    private static string GetString(IntPtr rec, uint field)
    {
        uint len = 0;
        var sb = new StringBuilder("");
        int rc = MsiRecordGetStringW(rec, field, sb, ref len);
        if (rc == ERROR_MORE_DATA)
        {
            len++;
            sb = new StringBuilder((int)len);
            rc = MsiRecordGetStringW(rec, field, sb, ref len);
        }
        return rc == ERROR_SUCCESS ? sb.ToString() : "";
    }
}
