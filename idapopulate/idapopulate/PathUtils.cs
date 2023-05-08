using Microsoft.Win32;
using System.Reflection;

namespace idapopulate;

internal static class PathUtils
{
    public static string FindGameRoot()
    {
        // stolen from FFXIVLauncher/src/XIVLauncher/AppUtil.cs
        foreach (var registryView in new RegistryView[] { RegistryView.Registry32, RegistryView.Registry64 })
        {
            using (var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, registryView))
            {
                // Should return "C:\Program Files (x86)\SquareEnix\FINAL FANTASY XIV - A Realm Reborn\boot\ffxivboot.exe" if installed with default options.
                using (var subkey = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{2B41E132-07DF-4925-A3D3-F2D1765CCDFE}"))
                {
                    if (subkey != null && subkey.GetValue("DisplayIcon", null) is string path)
                    {
                        // DisplayIcon includes "boot\ffxivboot.exe", need to remove it
                        var basePath = Directory.GetParent(path)?.Parent?.FullName;
                        if (basePath != null)
                        {
                            var gamePath = Path.Join(basePath, "game");
                            if (Directory.Exists(gamePath))
                            {
                                return gamePath;
                            }
                        }
                    }
                }
            }
        }
        return "D:\\installed\\SquareEnix\\FINAL FANTASY XIV - A Realm Reborn\\game";
    }

    public static FileInfo? FindFileAmongParents(string suffix)
    {
        var dir = new FileInfo(Assembly.GetExecutingAssembly().Location).Directory;
        while (dir != null)
        {
            var yml = new FileInfo(dir.FullName + suffix);
            if (yml.Exists)
                return yml;
            dir = dir.Parent;
        }
        return null;
    }
}
