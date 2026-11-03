namespace VRChatNetCapture;

internal static class StringExtensions
{
    public static IEnumerable<string> SplitLines(this string value) =>
        value.Split(["\r\n", "\n"], StringSplitOptions.None);
}
