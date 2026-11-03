using System.Buffers.Binary;
using System.Globalization;

namespace VRChatNetCapture;

internal static class PacketAddressFormatter
{
    public static int Format(ReadOnlySpan<byte> address, Span<char> destination)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 45, nameof(destination));
        if (address.Length == 4)
        {
            return FormatIpv4(address, destination);
        }
        ArgumentOutOfRangeException.ThrowIfNotEqual(address.Length, 16, nameof(address));
        Span<ushort> groups = stackalloc ushort[8];
        for (int index = 0; index < groups.Length; index++)
        {
            groups[index] = BinaryPrimitives.ReadUInt16BigEndian(address.Slice(index * 2, 2));
        }
        bool hasEmbeddedIpv4 = HasEmbeddedIpv4(groups);
        int written = FormatGroups(groups[..(hasEmbeddedIpv4 ? 6 : 8)], destination);
        if (hasEmbeddedIpv4)
        {
            if (destination[written - 1] != ':')
            {
                destination[written++] = ':';
            }
            written += FormatIpv4(address[12..], destination[written..]);
        }
        return written;
    }

    private static int FormatIpv4(ReadOnlySpan<byte> address, Span<char> destination)
    {
        int written = 0;
        foreach (byte value in address)
        {
            if (written > 0)
            {
                destination[written++] = '.';
            }
            if (!value.TryFormat(destination[written..], out int count, provider: CultureInfo.InvariantCulture))
            {
                throw new InvalidOperationException();
            }
            written += count;
        }
        return written;
    }

    private static bool HasEmbeddedIpv4(ReadOnlySpan<ushort> groups)
    {
        bool hasCompatiblePrefix = groups[..4].IndexOfAnyExcept((ushort)0) < 0 && groups[6] != 0;
        bool isMapped = groups[4] == 0 && groups[5] is 0 or 0xFFFF;
        bool isTranslated = groups[4] == 0xFFFF && groups[5] == 0;
        return (hasCompatiblePrefix && (isMapped || isTranslated)) || (groups[4] == 0 && groups[5] == 0x5EFE);
    }

    private static (int Start, int Length) FindZeroRun(ReadOnlySpan<ushort> groups)
    {
        int start = -1;
        int length = 1;
        int current = 0;
        for (int index = 0; index < groups.Length; index++)
        {
            current = groups[index] == 0 ? current + 1 : 0;
            if (current > length)
            {
                start = index - current + 1;
                length = current;
            }
        }
        return (start, length);
    }

    private static int FormatGroups(ReadOnlySpan<ushort> groups, Span<char> destination)
    {
        (int start, int length) = FindZeroRun(groups);
        int written = 0;
        for (int index = 0; index < groups.Length; index++)
        {
            if (index == start)
            {
                destination[written++] = ':';
                destination[written++] = ':';
                index += length - 1;
                continue;
            }
            if (written > 0 && destination[written - 1] != ':')
            {
                destination[written++] = ':';
            }
            if (!groups[index].TryFormat(destination[written..], out int count, "x", CultureInfo.InvariantCulture))
            {
                throw new InvalidOperationException();
            }
            written += count;
        }
        return written;
    }
}
