using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace VRChatNetCapture;

public static class ProxyManager
{
    private const string InternetSettingsPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    public static ProxySettings Read()
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsPath, writable: false)
            ?? throw new InvalidOperationException("Could not open WinINET Internet Settings registry key.");
        return new ProxySettings
        {
            ProxyEnable = Convert.ToInt32(key.GetValue("ProxyEnable") ?? 0),
            ProxyServer = key.GetValue("ProxyServer") as string,
            ProxyOverride = key.GetValue("ProxyOverride") as string,
            AutoConfigUrl = key.GetValue("AutoConfigURL") as string,
        };
    }

    public static void Save(string path)
    {
        JsonFiles.Write(path, Read());
    }

    public static void SetLocalProxy(int port)
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsPath, writable: true)
            ?? throw new InvalidOperationException("Could not open WinINET Internet Settings registry key.");
        key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
        key.SetValue("ProxyServer", $"127.0.0.1:{port}", RegistryValueKind.String);
        key.SetValue("ProxyOverride", "<local>", RegistryValueKind.String);
        key.DeleteValue("AutoConfigURL", throwOnMissingValue: false);
        NotifyWinInet();
    }

    public static void Restore(ProxySettings settings)
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsPath, writable: true)
            ?? throw new InvalidOperationException("Could not open WinINET Internet Settings registry key.");
        key.SetValue("ProxyEnable", settings.ProxyEnable, RegistryValueKind.DWord);
        SetOrDelete(key, "ProxyServer", settings.ProxyServer);
        SetOrDelete(key, "ProxyOverride", settings.ProxyOverride);
        SetOrDelete(key, "AutoConfigURL", settings.AutoConfigUrl);
        NotifyWinInet();
    }

    private static void SetOrDelete(RegistryKey key, string name, string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            key.DeleteValue(name, throwOnMissingValue: false);
        }
        else
        {
            key.SetValue(name, value, RegistryValueKind.String);
        }
    }

    private static void NotifyWinInet()
    {
        InternetSetOption(IntPtr.Zero, 95, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
    }

    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
}
