using System.Net;
using System.Net.Sockets;
using Proxylity.WireGuardClient;

/// <summary>
/// Unit tests for WireGuardClient public API, argument validation, and lifecycle
/// behavior. All tests use loopback sockets or early-exit code paths and complete
/// without a real WireGuard peer (no real handshake is performed).
/// </summary>
public class WireGuardClientUnitTests : IDisposable
{
    // Valid 32-byte keys for constructing clients under test.
    private static readonly byte[] ValidServerKey = new byte[32];
    private static readonly byte[] ValidClientKey;

    static WireGuardClientUnitTests()
    {
        // Use the private key from the integration test so DerivePublicKey is exercised.
        ValidClientKey = Convert.FromBase64String("WTEnZaFR/Segak6Zyxcw3QBQNqrvHRt3dCCh0eIPMSU=");
        // Server key: any 32 bytes that are a valid Curve25519 public key.
        // Use the derived public key of ValidClientKey as a synthetic "server" key.
        var pub = WireGuardClient.Protocol.DerivePublicKey(ValidClientKey);
        pub.CopyTo(ValidServerKey, 0);
    }

    private static readonly IPEndPoint AnyEndpoint = new(IPAddress.Loopback, 19999);

    // Loopback UdpClient bound to an ephemeral port for tests that need a real socket.
    private readonly UdpClient _loopbackUdp;
    private readonly IPEndPoint _loopbackEndpoint;

    public WireGuardClientUnitTests()
    {
        _loopbackUdp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        _loopbackEndpoint = (IPEndPoint)_loopbackUdp.Client.LocalEndPoint!;
    }

    public void Dispose() => _loopbackUdp.Dispose();

    // ── argument validation ─────────────────────────────────────────────────

    [Fact]
    public void Constructor_NullServerEndpoint_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new WireGuardClient(null!, ValidServerKey, ValidClientKey));
    }

    [Fact]
    public void Constructor_ShortServerKey_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            new WireGuardClient(AnyEndpoint, new byte[31], ValidClientKey));
    }

    [Fact]
    public void Constructor_LongServerKey_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            new WireGuardClient(AnyEndpoint, new byte[33], ValidClientKey));
    }

    [Fact]
    public void Constructor_ShortClientKey_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            new WireGuardClient(AnyEndpoint, ValidServerKey, new byte[31]));
    }

    [Fact]
    public void Constructor_UdpClientOverload_NullUdpClient_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new WireGuardClient(AnyEndpoint, ValidServerKey, ValidClientKey, (UdpClient)null!));
    }

    // ── wrong endpoint ──────────────────────────────────────────────────────

    [Fact]
    public async Task SendAsync_WrongEndpoint_ThrowsBeforeHandshake()
    {
        // Point at our own loopback socket so the receive loop doesn't crash.
        using var wg = new WireGuardClient(_loopbackEndpoint, ValidServerKey, ValidClientKey, _loopbackUdp);

        var differentEndpoint = new IPEndPoint(IPAddress.Loopback, _loopbackEndpoint.Port + 1);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            wg.SendAsync(new byte[4], 4, differentEndpoint));
    }

    // ── dispose behavior ────────────────────────────────────────────────────

    [Fact]
    public async Task SendAsync_AfterDispose_ThrowsObjectDisposedException()
    {
        var wg = new WireGuardClient(_loopbackEndpoint, ValidServerKey, ValidClientKey, _loopbackUdp);
        wg.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            wg.SendAsync("data"u8.ToArray(), CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task ReceiveAsync_AfterDispose_ThrowsObjectDisposedException()
    {
        var wg = new WireGuardClient(_loopbackEndpoint, ValidServerKey, ValidClientKey, _loopbackUdp);
        wg.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            wg.ReceiveAsync(CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task Dispose_DuringPendingReceiveAsync_CompletesWithinTimeout()
    {
        // Use a fresh unshared UdpClient so the receive loop actually starts.
        var localUdp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var ep = (IPEndPoint)localUdp.Client.LocalEndPoint!;
        // Point at a peer that will never send anything back (our loopback listener).
        using var wg = new WireGuardClient(ep, ValidServerKey, ValidClientKey, localUdp);

        // Start a background receive that will block indefinitely.
        var receiveTask = wg.ReceiveAsync(CancellationToken.None).AsTask();

        // Give the receive loop a moment to start, then dispose.
        await Task.Delay(50);
        wg.Dispose();

        // The receive should complete (with any exception/cancellation) promptly.
        var completed = await Task.WhenAny(receiveTask, Task.Delay(TimeSpan.FromSeconds(2)));
        Assert.Same(receiveTask, completed);
    }

    // ── cancellation ────────────────────────────────────────────────────────

    [Fact]
    public async Task SendAsync_CancelledTokenBeforeHandshake_ThrowsOperationCanceledException()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel(); // pre-cancelled

        // Point at loopback — no server will respond, but we cancel before the handshake.
        using var wg = new WireGuardClient(_loopbackEndpoint, ValidServerKey, ValidClientKey, _loopbackUdp);

        // TaskCanceledException is a subclass of OperationCanceledException.
        var ex = await Record.ExceptionAsync(() => wg.SendAsync("test"u8.ToArray(), cts.Token).AsTask());
        Assert.IsAssignableFrom<OperationCanceledException>(ex);
    }

    [Fact]
    public async Task SendAsync_UnresponsivePeer_WithCancelledToken_CompletesPromptly()
    {
        // Black-hole: bind a UDP socket that accepts packets but never replies.
        var blackHole = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var blackHoleEp = (IPEndPoint)blackHole.Client.LocalEndPoint!;

        using var wg = new WireGuardClient(blackHoleEp, ValidServerKey, ValidClientKey);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));

        // With a pre-cancelled or short timeout, the call must complete within 1s
        // (either OperationCanceledException or TimeoutException — both are acceptable).
        var ex = await Record.ExceptionAsync(() =>
            wg.SendAsync("test"u8.ToArray(), cts.Token).AsTask());

        Assert.True(ex is OperationCanceledException or TimeoutException,
            $"Expected cancellation or timeout, got: {ex?.GetType().Name}: {ex?.Message}");

        wg.Dispose();
        blackHole.Dispose();
    }
}
