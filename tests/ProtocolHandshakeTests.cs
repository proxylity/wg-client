using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Blake2Fast;
using NSec.Cryptography;
using Proxylity.WireGuardClient;

/// <summary>
/// End-to-end Noise_IKpsk2 handshake round-trip tests. A <see cref="ServerHandshakeHelper"/>
/// class implements the server side of the handshake entirely in memory, with no
/// network I/O. The resulting session keys are then cross-verified with transport
/// encrypt/decrypt to confirm both sides derived the same symmetric keys.
/// </summary>
public class ProtocolHandshakeTests
{
    [Fact]
    public void Handshake_RoundTrip_ProducesValidSession()
    {
        // Arrange: generate a fresh server key pair for this test.
        var serverPrivateKey = GeneratePrivateKey();
        var serverPublicKey = WireGuardClient.Protocol.DerivePublicKey(serverPrivateKey);

        var clientPrivateKey = GeneratePrivateKey();
        var clientPublicKey = WireGuardClient.Protocol.DerivePublicKey(clientPrivateKey);

        // Act: client creates initiation.
        var pending = WireGuardClient.Protocol.CreateHandshakeInitiation(clientPrivateKey, clientPublicKey, serverPublicKey);

        // Server processes initiation and builds a response.
        var (responsePacket, serverSendingKey, serverReceivingKey) =
            ServerHandshakeHelper.BuildResponse(pending.Packet, serverPrivateKey, serverPublicKey);

        // Client processes the response.
        var ok = WireGuardClient.Protocol.TryCompleteHandshake(
            responsePacket, clientPrivateKey, pending, out var clientSession, out var errorMessage);

        // Assert: handshake succeeded.
        Assert.True(ok, $"TryCompleteHandshake failed: {errorMessage}");
        Assert.NotNull(clientSession);

        // Cross-verify: client encrypts with SendingKey (key1); server decrypts with ReceivingKey (key1).
        // Server encrypts with SendingKey (key2); client decrypts with ReceivingKey (key2).
        Assert.Equal(clientSession!.SendingKey, serverReceivingKey);
        Assert.Equal(clientSession!.ReceivingKey, serverSendingKey);
    }

    [Fact]
    public void Handshake_TransportCrossVerification_ClientToServer()
    {
        var serverPrivateKey = GeneratePrivateKey();
        var serverPublicKey = WireGuardClient.Protocol.DerivePublicKey(serverPrivateKey);
        var clientPrivateKey = GeneratePrivateKey();
        var clientPublicKey = WireGuardClient.Protocol.DerivePublicKey(clientPrivateKey);

        var pending = WireGuardClient.Protocol.CreateHandshakeInitiation(clientPrivateKey, clientPublicKey, serverPublicKey);
        var (responsePacket, serverSendingKey, serverReceivingKey) =
            ServerHandshakeHelper.BuildResponse(pending.Packet, serverPrivateKey, serverPublicKey);

        WireGuardClient.Protocol.TryCompleteHandshake(responsePacket, clientPrivateKey, pending, out var clientSession, out _);
        Assert.NotNull(clientSession);

        // Build the server-side decrypt session.
        var serverDecryptSession = new WireGuardClient.SessionState(
            LocalIndex: clientSession!.RemoteIndex,  // server's local index = client's remote index
            RemoteIndex: clientSession.LocalIndex,
            SendingKey: serverSendingKey,
            ReceivingKey: serverReceivingKey,
            SendingCounter: 0,
            ReceivingCounter: 0,
            ExpiresAt: DateTime.UtcNow.AddHours(1));

        var payload = "client→server"u8.ToArray();
        var packet = WireGuardClient.Protocol.EncryptTransport(payload, clientSession, out _);

        var decryptOk = WireGuardClient.Protocol.TryDecryptTransport(packet, serverDecryptSession, out _, out var decrypted);

        Assert.True(decryptOk, "Server could not decrypt client transport packet.");
        Assert.Equal(payload, decrypted);
    }

    [Fact]
    public void Handshake_TransportCrossVerification_ServerToClient()
    {
        var serverPrivateKey = GeneratePrivateKey();
        var serverPublicKey = WireGuardClient.Protocol.DerivePublicKey(serverPrivateKey);
        var clientPrivateKey = GeneratePrivateKey();
        var clientPublicKey = WireGuardClient.Protocol.DerivePublicKey(clientPrivateKey);

        var pending = WireGuardClient.Protocol.CreateHandshakeInitiation(clientPrivateKey, clientPublicKey, serverPublicKey);
        var (responsePacket, serverSendingKey, serverReceivingKey) =
            ServerHandshakeHelper.BuildResponse(pending.Packet, serverPrivateKey, serverPublicKey);

        WireGuardClient.Protocol.TryCompleteHandshake(responsePacket, clientPrivateKey, pending, out var clientSession, out _);
        Assert.NotNull(clientSession);

        // Server encrypt session: sends with key2, and the receiver index in the
        // packet must be the client's LocalIndex so the client can accept it.
        var serverEncryptSession = new WireGuardClient.SessionState(
            LocalIndex: clientSession!.RemoteIndex,
            RemoteIndex: clientSession.LocalIndex,   // written into packet as receiver for client
            SendingKey: serverSendingKey,
            ReceivingKey: serverReceivingKey,
            SendingCounter: 0,
            ReceivingCounter: 0,
            ExpiresAt: DateTime.UtcNow.AddHours(1));

        var payload = "server→client"u8.ToArray();
        var packet = WireGuardClient.Protocol.EncryptTransport(payload, serverEncryptSession, out _);

        var decryptOk = WireGuardClient.Protocol.TryDecryptTransport(packet, clientSession, out _, out var decrypted);

        Assert.True(decryptOk, "Client could not decrypt server transport packet.");
        Assert.Equal(payload, decrypted);
    }

    [Fact]
    public void Handshake_WrongServerKey_CannotProcessInitiation()
    {
        // Use a different server key for the initiation vs. the response processing.
        var realServerPrivateKey = GeneratePrivateKey();
        var realServerPublicKey = WireGuardClient.Protocol.DerivePublicKey(realServerPrivateKey);
        var wrongServerPrivateKey = GeneratePrivateKey();
        var wrongServerPublicKey = WireGuardClient.Protocol.DerivePublicKey(wrongServerPrivateKey);

        var clientPrivateKey = GeneratePrivateKey();
        var clientPublicKey = WireGuardClient.Protocol.DerivePublicKey(clientPrivateKey);

        // Client initiates toward the real server key.
        var pending = WireGuardClient.Protocol.CreateHandshakeInitiation(clientPrivateKey, clientPublicKey, realServerPublicKey);

        // A server with the wrong private key should fail to process the initiation
        // because it cannot derive the correct DH shared secret to decrypt the client's
        // encrypted static key. BuildResponse is expected to throw here.
        Assert.Throws<InvalidOperationException>(() =>
            ServerHandshakeHelper.BuildResponse(pending.Packet, wrongServerPrivateKey, wrongServerPublicKey));
    }

    private static byte[] GeneratePrivateKey()
    {
        using var key = Key.Create(KeyAgreementAlgorithm.X25519, new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        });
        return key.Export(KeyBlobFormat.RawPrivateKey);
    }
}

/// <summary>
/// Implements the server side of the WireGuard Noise_IKpsk2 handshake entirely in
/// memory, using the same primitives (NSec + Blake2Fast) as the client Protocol class.
/// Parses a HandshakeInitiation packet, performs the server-side Noise derivation,
/// and returns a valid HandshakeResponse packet along with the server's symmetric keys.
/// </summary>
internal static class ServerHandshakeHelper
{
    private static readonly KeyAgreementAlgorithm X25519 = KeyAgreementAlgorithm.X25519;
    private static readonly AeadAlgorithm ChaCha20Poly1305 = AeadAlgorithm.ChaCha20Poly1305;
    private static readonly byte[] Construction = Encoding.UTF8.GetBytes("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");
    private static readonly byte[] Identifier = Encoding.UTF8.GetBytes("WireGuard v1 zx2c4 Jason@zx2c4.com");
    private static readonly byte[] LabelMac1 = Encoding.UTF8.GetBytes("mac1----");

    // Packet field offsets (mirror of Protocol private constants).
    private const int CommonHeaderSize = 4;
    private const int SenderIndexOffset = CommonHeaderSize;
    private const int SenderIndexSize = 4;
    private const int ReceiverIndexOffset = SenderIndexOffset + SenderIndexSize;
    private const int ReceiverIndexSize = 4;
    private const int EphemeralOffset = SenderIndexOffset + SenderIndexSize; // offset 8
    private const int EphemeralSize = 32;
    private const int EncryptedStaticOffset = EphemeralOffset + EphemeralSize; // offset 40
    private const int EncryptedStaticSize = 48;
    private const int EncryptedTimestampOffset = EncryptedStaticOffset + EncryptedStaticSize; // offset 88
    private const int EncryptedTimestampSize = 28;
    private const int Mac1Offset = EncryptedTimestampOffset + EncryptedTimestampSize; // offset 116
    private const int MacSize = 16;
    private const int HandshakeInitiationSize = 148;
    // Response layout: type(1) + reserved(3) + senderIndex(4) + receiverIndex(4) + ephemeral(32) + encryptedEmpty(16) + mac1(16) + mac2(16) = 92
    private const int HandshakeResponseSize = 92;
    private const int ResponseSenderIndexOffset = CommonHeaderSize;          // 4
    private const int ResponseReceiverIndexOffset = ResponseSenderIndexOffset + SenderIndexSize; // 8
    private const int ResponseEphemeralOffset = ResponseReceiverIndexOffset + ReceiverIndexSize; // 12
    private const int ResponseEncryptedEmptyOffset = ResponseEphemeralOffset + EphemeralSize;    // 44
    private const int ResponseEncryptedEmptySize = 16;
    private const int ResponseMac1Offset = ResponseEncryptedEmptyOffset + ResponseEncryptedEmptySize; // 60
    private const int KeySize = 32;

    /// <summary>
    /// Processes a HandshakeInitiation packet (from the client) as a WireGuard server,
    /// and returns the HandshakeResponse packet along with the server's symmetric keys.
    /// </summary>
    /// <returns>
    /// (responsePacket, serverSendingKey, serverReceivingKey) where serverSendingKey is
    /// the key the server uses to encrypt outgoing transport packets, and serverReceivingKey
    /// is the key used to decrypt incoming transport packets from the client.
    /// </returns>
    public static (byte[] ResponsePacket, byte[] ServerSendingKey, byte[] ServerReceivingKey)
        BuildResponse(byte[] initiationPacket, byte[] serverPrivateKey, byte[] serverPublicKey)
    {
        // ── Parse initiation ────────────────────────────────────────────────
        var initiatorIndex = BinaryPrimitives.ReadUInt32LittleEndian(
            initiationPacket.AsSpan(SenderIndexOffset, SenderIndexSize));
        var clientEphemeralPublic = initiationPacket.AsSpan(EphemeralOffset, EphemeralSize).ToArray();
        var encryptedStatic = initiationPacket.AsSpan(EncryptedStaticOffset, EncryptedStaticSize).ToArray();
        var encryptedTimestamp = initiationPacket.AsSpan(EncryptedTimestampOffset, EncryptedTimestampSize).ToArray();

        // ── Reproduce the initiator's hash/chainKey state ───────────────────
        var constructionHash = Hash(Construction);
        var hash = Hash(Concat(Hash(Concat(constructionHash, Identifier)), serverPublicKey));

        // Mix in client ephemeral.
        hash = Hash(Concat(hash, clientEphemeralPublic));
        var chainKey = Kdf1(constructionHash, clientEphemeralPublic);

        // DH(serverStatic, clientEphemeral) → decrypt client static key.
        using var serverStaticKey = Key.Import(X25519, serverPrivateKey, KeyBlobFormat.RawPrivateKey,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var clientEphemeralKey = PublicKey.Import(X25519, clientEphemeralPublic, KeyBlobFormat.RawPublicKey);
        var dhEphemeralStatic = X25519.Agree(serverStaticKey, clientEphemeralKey,
            new SharedSecretCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        (chainKey, var staticDecryptionKey) = Kdf2(chainKey, dhEphemeralStatic!.Export(SharedSecretBlobFormat.RawSharedSecret));

        var clientPublicKey = AeadDecrypt(staticDecryptionKey, encryptedStatic, hash)
            ?? throw new InvalidOperationException("Server: failed to decrypt client public key.");
        hash = Hash(Concat(hash, encryptedStatic));

        // DH(serverStatic, clientStatic) → decrypt timestamp (just validate it decrypts).
        var clientStaticKey = PublicKey.Import(X25519, clientPublicKey, KeyBlobFormat.RawPublicKey);
        var dhStaticStatic = X25519.Agree(serverStaticKey, clientStaticKey,
            new SharedSecretCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        (chainKey, var timestampDecryptionKey) = Kdf2(chainKey, dhStaticStatic!.Export(SharedSecretBlobFormat.RawSharedSecret));

        var _ = AeadDecrypt(timestampDecryptionKey, encryptedTimestamp, hash)
            ?? throw new InvalidOperationException("Server: failed to decrypt timestamp.");
        hash = Hash(Concat(hash, encryptedTimestamp));

        // ── Server generates its own ephemeral key pair ──────────────────────
        using var serverEphemeralKey = Key.Create(X25519, new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        });
        var serverEphemeralPublic = serverEphemeralKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var serverLocalIndex = GenerateLocalIndex();

        // Mix server ephemeral into hash/chainKey.
        hash = Hash(Concat(hash, serverEphemeralPublic));
        chainKey = Kdf1(chainKey, serverEphemeralPublic);

        // DH(serverEphemeral, clientEphemeral).
        var dhEphemeralEphemeral = X25519.Agree(serverEphemeralKey, clientEphemeralKey,
            new SharedSecretCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        chainKey = Kdf1(chainKey, dhEphemeralEphemeral!.Export(SharedSecretBlobFormat.RawSharedSecret));

        // DH(serverEphemeral, clientStatic).
        var dhEphemeralClientStatic = X25519.Agree(serverEphemeralKey, clientStaticKey,
            new SharedSecretCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        chainKey = Kdf1(chainKey, dhEphemeralClientStatic!.Export(SharedSecretBlobFormat.RawSharedSecret));

        // Kdf3 for PSK (zero PSK in IKpsk2 without a pre-shared key).
        (chainKey, var tempHash, var emptyKey) = Kdf3(chainKey, new byte[KeySize]);
        hash = Hash(Concat(hash, tempHash));

        // Encrypt empty payload with emptyKey and current hash.
        var encryptedEmpty = AeadEncrypt(emptyKey, [], hash)
            ?? throw new InvalidOperationException("Server: failed to encrypt empty payload.");
        hash = Hash(Concat(hash, encryptedEmpty));

        // Derive final transport keys: key1 = client→server, key2 = server→client.
        var (key1, key2) = Kdf2(chainKey, []);

        // ── Assemble response packet ─────────────────────────────────────────
        var response = new byte[HandshakeResponseSize];
        response[0] = 2; // MessageType.HandshakeResponse
        BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(ResponseSenderIndexOffset, SenderIndexSize), serverLocalIndex);
        BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(ResponseReceiverIndexOffset, ReceiverIndexSize), initiatorIndex);
        serverEphemeralPublic.CopyTo(response.AsSpan(ResponseEphemeralOffset, EphemeralSize));
        encryptedEmpty.CopyTo(response.AsSpan(ResponseEncryptedEmptyOffset, ResponseEncryptedEmptySize));

        var mac1Key = Hash(Concat(LabelMac1, serverPublicKey));
        var mac1 = Mac(mac1Key, response.AsSpan(0, ResponseMac1Offset));
        mac1.CopyTo(response.AsSpan(ResponseMac1Offset, MacSize));

        // Server sends with key2, receives with key1.
        return (response, key2, key1);
    }

    private static uint GenerateLocalIndex()
    {
        Span<byte> bytes = stackalloc byte[4];
        RandomNumberGenerator.Fill(bytes);
        return BinaryPrimitives.ReadUInt32LittleEndian(bytes);
    }

    private static byte[]? AeadDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> ad)
    {
        try
        {
            using var k = Key.Import(ChaCha20Poly1305, key, KeyBlobFormat.RawSymmetricKey);
            return ChaCha20Poly1305.Decrypt(k, new byte[12], ad, ciphertext);
        }
        catch { return null; }
    }

    private static byte[]? AeadEncrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> ad)
    {
        try
        {
            using var k = Key.Import(ChaCha20Poly1305, key, KeyBlobFormat.RawSymmetricKey);
            return ChaCha20Poly1305.Encrypt(k, new byte[12], ad, plaintext);
        }
        catch { return null; }
    }

    private static byte[] Concat(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        var result = new byte[left.Length + right.Length];
        left.CopyTo(result);
        right.CopyTo(result.AsSpan(left.Length));
        return result;
    }

    private static byte[] Hash(ReadOnlySpan<byte> input) => Blake2s.ComputeHash(KeySize, input);

    private static byte[] Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input)
    {
        const int blockSize = 64;
        Span<byte> paddedKey = stackalloc byte[blockSize];
        key.CopyTo(paddedKey);
        Span<byte> outerPad = stackalloc byte[blockSize];
        Span<byte> innerPad = stackalloc byte[blockSize];
        for (var i = 0; i < blockSize; i++)
        {
            outerPad[i] = (byte)(paddedKey[i] ^ 0x5c);
            innerPad[i] = (byte)(paddedKey[i] ^ 0x36);
        }
        var innerHash = Blake2s.ComputeHash(KeySize, Concat(innerPad, input));
        return Blake2s.ComputeHash(KeySize, Concat(outerPad, innerHash));
    }

    private static byte[] Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input)
        => Blake2s.ComputeHash(16, key, input);

    private static byte[] Kdf1(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input) => Kdf(key, input, 1)[0];

    private static (byte[] key1, byte[] key2) Kdf2(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input)
    {
        var o = Kdf(key, input, 2);
        return (o[0], o[1]);
    }

    private static (byte[] key1, byte[] key2, byte[] key3) Kdf3(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input)
    {
        var o = Kdf(key, input, 3);
        return (o[0], o[1], o[2]);
    }

    private static byte[][] Kdf(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, int count)
    {
        var prk = Hmac(key, input);
        var output = new byte[count][];
        var prev = Array.Empty<byte>();
        for (var i = 0; i < count; i++)
        {
            var material = new byte[prev.Length + 1];
            prev.CopyTo(material, 0);
            material[^1] = (byte)(i + 1);
            prev = Hmac(prk, material);
            output[i] = prev;
        }
        return output;
    }
}
