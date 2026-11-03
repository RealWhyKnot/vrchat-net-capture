using System.Buffers;

namespace VRChatNetCapture;

internal sealed class CapturePacketBuffers : IDisposable
{
    private bool _isDisposed;

    public byte[] Packet { get; } = ArrayPool<byte>.Shared.Rent(ushort.MaxValue);
    public byte[] Address { get; } = new byte[80];

    public void Dispose()
    {
        if (!_isDisposed)
        {
            _isDisposed = true;
            ArrayPool<byte>.Shared.Return(Packet, clearArray: true);
        }
    }
}
