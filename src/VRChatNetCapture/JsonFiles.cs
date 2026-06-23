using System.Text.Json;

namespace VRChatNetCapture;

public static class JsonFiles
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public static void Write<T>(string path, T value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(value, Options));
    }

    public static T? Read<T>(string path)
    {
        if (!File.Exists(path))
        {
            return default;
        }
        return JsonSerializer.Deserialize<T>(File.ReadAllText(path));
    }
}
