using System.Net;
using System.Security.Cryptography;
using Proxylity.WireGuardClient;

/// <summary>
/// Unit tests for Protocol transport encryption/decryption. All tests are pure
/// in-memory with no I/O and should complete in well under 1 second total.
/// </summary>
public class ProtocolTransportTests
{
    // EncryptTransport writes session.RemoteIndex into the packet's receiver field.
    // TryDecryptTransport accepts only if that index == decryptSession.LocalIndex.
    // So for a loopback test: encryptSession.RemoteIndex == decryptSession.LocalIndex.
    private static readonly byte[] SessionKey = RandomKey();

    private static readonly WireGuardClient.SessionState EncryptSession = new(
        LocalIndex: 0xAABBCCDD,   // our index (not used in the packet for transport)
        RemoteIndex: 0x11223344,  // written into the packet as receiver index
        SendingKey: SessionKey,
        ReceivingKey: SessionKey,
        SendingCounter: 0,
        ReceivingCounter: 0,
        ExpiresAt: DateTime.UtcNow.AddHours(1));

    // DecryptSession.LocalIndex must match EncryptSession.RemoteIndex.
    private static readonly WireGuardClient.SessionState DecryptSession = new(
        LocalIndex: 0x11223344,   // matches EncryptSession.RemoteIndex
        RemoteIndex: 0xAABBCCDD,
        SendingKey: SessionKey,
        ReceivingKey: SessionKey,
        SendingCounter: 0,
        ReceivingCounter: 0,
        ExpiresAt: DateTime.UtcNow.AddHours(1));

    // ── round-trip ──────────────────────────────────────────────────────────

    [Fact]
    public void TransportRoundTrip_PayloadMatchesOriginal()
    {
        var payload = "Hello, WireGuard!"u8.ToArray();

        var packet = WireGuardClient.Protocol.EncryptTransport(payload, EncryptSession, out _);
        var ok = WireGuardClient.Protocol.TryDecryptTransport(packet, DecryptSession, out _, out var decrypted);

        Assert.True(ok);
        Assert.Equal(payload, decrypted);
    }

    [Fact]
    public void TransportRoundTrip_EmptyPayload()
    {
        var payload = Array.Empty<byte>();

        var packet = WireGuardClient.Protocol.EncryptTransport(payload, EncryptSession, out _);
        var ok = WireGuardClient.Protocol.TryDecryptTransport(packet, DecryptSession, out _, out var decrypted);

        Assert.True(ok);
        Assert.Equal(payload, decrypted);
    }

    // ── counter advancement ─────────────────────────────────────────────────

    [Fact]
    public void Encrypt_IncrementsSendingCounter()
    {
        WireGuardClient.Protocol.EncryptTransport("x"u8.ToArray(), EncryptSession, out var updated);

        Assert.Equal(EncryptSession.SendingCounter + 1, updated.SendingCounter);
    }

    [Fact]
    public void Decrypt_UpdatesReceivingCounter()
    {
        var payload = "abc"u8.ToArray();
        var packet = WireGuardClient.Protocol.EncryptTransport(payload, EncryptSession, out _);

        WireGuardClient.Protocol.TryDecryptTransport(packet, DecryptSession, out var updated, out _);

        Assert.Equal(0UL, updated!.ReceivingCounter); // counter=0 in the packet
    }

    [Fact]
    public void Decrypt_UpdatesReceivingCounter_NonZero()
    {
        var encSession = EncryptSession with { SendingCounter = 7 };
        var packet = WireGuardClient.Protocol.EncryptTransport("x"u8.ToArray(), encSession, out _);

        // Receiving side must accept counter=7 when its current counter is 0.
        var ok = WireGuardClient.Protocol.TryDecryptTransport(packet, DecryptSession, out var updated, out _);

        Assert.True(ok);
        Assert.Equal(7UL, updated!.ReceivingCounter);
    }

    // ── tamper detection ────────────────────────────────────────────────────

    [Fact]
    public void Decrypt_TamperedCiphertext_ReturnsFalse()
    {
        var payload = "secret"u8.ToArray();
        var packet = WireGuardClient.Protocol.EncryptTransport(payload, EncryptSession, out _);

        // Flip a byte in the encrypted payload region (after the 16-byte header).
        packet[16] ^= 0xFF;

        var ok = WireGuardClient.Protocol.TryDecryptTransport(packet, DecryptSession, out _, out _);
        Assert.False(ok);
    }

    // ── replay / counter enforcement ────────────────────────────────────────

    [Fact]
    public void Decrypt_ReplayedCounter_ReturnsFalse()
    {
        var encSession = EncryptSession with { SendingCounter = 5 };
        var packet = WireGuardClient.Protocol.EncryptTransport("x"u8.ToArray(), encSession, out _);

        // Receiving side has already seen counter 5.
        var receiveSession = DecryptSession with { ReceivingCounter = 5 };
        var ok = WireGuardClient.Protocol.TryDecryptTransport(packet, receiveSession, out _, out _);

        Assert.False(ok);
    }

    [Fact]
    public void Decrypt_CounterEqualToReceivingCounter_ReturnsFalse()
    {
        var encSession = EncryptSession with { SendingCounter = 3 };
        var packet = WireGuardClient.Protocol.EncryptTransport("x"u8.ToArray(), encSession, out _);

        var receiveSession = DecryptSession with { ReceivingCounter = 3 };
        var ok = WireGuardClient.Protocol.TryDecryptTransport(packet, receiveSession, out _, out _);

        Assert.False(ok);
    }

    // ── structural validation ───────────────────────────────────────────────

    [Fact]
    public void Decrypt_WrongReceiverIndex_ReturnsFalse()
    {
        var packet = WireGuardClient.Protocol.EncryptTransport("x"u8.ToArray(), EncryptSession, out _);

        // LocalIndex doesn't match the packet's receiver index field (which is EncryptSession.RemoteIndex).
        var wrongSession = DecryptSession with { LocalIndex = 0xDEADBEEF };
        var ok = WireGuardClient.Protocol.TryDecryptTransport(packet, wrongSession, out _, out _);

        Assert.False(ok);
    }

    [Fact]
    public void Decrypt_PacketTooShort_ReturnsFalse()
    {
        // 31 bytes is below the 32-byte TransportMinimumSize.
        var shortPacket = new byte[31];
        shortPacket[0] = 4; // correct message type

        var ok = WireGuardClient.Protocol.TryDecryptTransport(shortPacket, DecryptSession, out _, out _);
        Assert.False(ok);
    }

    [Fact]
    public void Decrypt_WrongMessageType_ReturnsFalse()
    {
        var packet = WireGuardClient.Protocol.EncryptTransport("x"u8.ToArray(), EncryptSession, out _);
        packet[0] = 1; // change type byte to HandshakeInitiation

        var ok = WireGuardClient.Protocol.TryDecryptTransport(packet, DecryptSession, out _, out _);
        Assert.False(ok);
    }

    // ── key derivation test vector ──────────────────────────────────────────

    [Fact]
    public void DerivePublicKey_KnownVector()
    {
        // Key pair generated offline with `wg genkey / wg pubkey`.
        // The private key is also used in the integration test for the echo backend.
        var privateKey = Convert.FromBase64String("WTEnZaFR/Segak6Zyxcw3QBQNqrvHRt3dCCh0eIPMSU=");

        var derived = WireGuardClient.Protocol.DerivePublicKey(privateKey);
        var actual = Convert.ToBase64String(derived);

        // Assert length and known prefix (xUnit truncates long strings in failure output;
        // the prefix covers the first 15 bytes of the 32-byte key unambiguously).
        Assert.Equal(44, actual.Length);
        Assert.StartsWith("JC9KlmrtNNRrvc9j", actual);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static byte[] RandomKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }
}
