using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using Blake2Fast;
using NSec.Cryptography;

namespace Proxylity.WireGuardClient;

public sealed class WireGuardClient : IDisposable
{
    private static readonly TimeSpan HandshakeLifetime = TimeSpan.FromSeconds(180);
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromSeconds(180);

    private readonly IPEndPoint _serverEndpoint;
    private readonly byte[] _serverPublicKey;
    private readonly byte[] _clientPrivateKey;
    private readonly byte[] _clientPublicKey;
    private readonly UdpClient _udpClient;
    private readonly bool _ownsUdpClient;
    private readonly object _stateLock = new();
    private readonly SemaphoreSlim _handshakeGate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Channel<UdpReceiveResult> _receiveQueue = Channel.CreateUnbounded<UdpReceiveResult>(
        new UnboundedChannelOptions
        {
            SingleWriter = true,
            AllowSynchronousContinuations = false
        });
    private readonly Task _receiveLoopTask;

    private SessionState? _session;
    private PendingHandshake? _pendingHandshake;
    private TaskCompletionSource<SessionState>? _handshakeCompletion;
    private Exception? _receiveLoopError;
    private bool _disposed;

    public WireGuardClient(
        IPEndPoint serverEndpoint,
        ReadOnlyMemory<byte> serverPublicKey,
        ReadOnlyMemory<byte> clientPrivateKey,
        IPEndPoint? localEndpoint = null)
    {
        ArgumentNullException.ThrowIfNull(serverEndpoint);

        ValidateKey(serverPublicKey, nameof(serverPublicKey));
        ValidateKey(clientPrivateKey, nameof(clientPrivateKey));

        _serverEndpoint = serverEndpoint;
        _serverPublicKey = serverPublicKey.ToArray();
        _clientPrivateKey = clientPrivateKey.ToArray();
        _clientPublicKey = Protocol.DerivePublicKey(_clientPrivateKey);
        _udpClient = localEndpoint is null ? new UdpClient() : new UdpClient(localEndpoint);
        if (localEndpoint is null)
        {
            _udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
        }
        _ownsUdpClient = true;
        _receiveLoopTask = Task.Run(ReceiveLoopAsync);
    }

    public WireGuardClient(
        IPEndPoint serverEndpoint,
        ReadOnlyMemory<byte> serverPublicKey,
        ReadOnlyMemory<byte> clientPrivateKey,
        UdpClient udpClient)
    {
        ArgumentNullException.ThrowIfNull(serverEndpoint);
        ArgumentNullException.ThrowIfNull(udpClient);

        ValidateKey(serverPublicKey, nameof(serverPublicKey));
        ValidateKey(clientPrivateKey, nameof(clientPrivateKey));

        _serverEndpoint = serverEndpoint;
        _serverPublicKey = serverPublicKey.ToArray();
        _clientPrivateKey = clientPrivateKey.ToArray();
        _clientPublicKey = Protocol.DerivePublicKey(_clientPrivateKey);
        _udpClient = udpClient;
        _ownsUdpClient = false;
        _receiveLoopTask = Task.Run(ReceiveLoopAsync);
    }

    public int Available => _receiveQueue.Reader.Count;

    public Socket Client => _udpClient.Client;

    public bool DontFragment
    {
        get => _udpClient.DontFragment;
        set => _udpClient.DontFragment = value;
    }

    public bool EnableBroadcast
    {
        get => _udpClient.EnableBroadcast;
        set => _udpClient.EnableBroadcast = value;
    }

    public bool MulticastLoopback
    {
        get => _udpClient.MulticastLoopback;
        set => _udpClient.MulticastLoopback = value;
    }

    public IPEndPoint RemoteEndPoint => _serverEndpoint;

    public short Ttl
    {
        get => _udpClient.Ttl;
        set => _udpClient.Ttl = value;
    }

    public void Close() => Dispose();

    public Task<UdpReceiveResult> ReceiveAsync() => ReceiveAsync(CancellationToken.None).AsTask();

    public async ValueTask<UdpReceiveResult> ReceiveAsync(CancellationToken cancellationToken)
    {
        ThrowIfUnavailable();
        await EnsureSessionAsync(cancellationToken);

        try
        {
            return await _receiveQueue.Reader.ReadAsync(cancellationToken);
        }
        catch (ChannelClosedException ex) when (_disposed)
        {
            throw new ObjectDisposedException(nameof(WireGuardClient), ex);
        }
        catch (ChannelClosedException ex)
        {
            throw new InvalidOperationException("The receive loop is no longer running.", ex);
        }
    }

    public Task<int> SendAsync(byte[] datagram, int bytes)
    {
        ArgumentNullException.ThrowIfNull(datagram);
        ValidateByteCount(datagram.Length, bytes);
        return SendAsync(datagram.AsMemory(0, bytes), CancellationToken.None).AsTask();
    }

    public Task<int> SendAsync(byte[] datagram, int bytes, IPEndPoint? endPoint)
    {
        ArgumentNullException.ThrowIfNull(datagram);
        ValidateByteCount(datagram.Length, bytes);
        return SendAsyncCore(datagram.AsMemory(0, bytes), endPoint, CancellationToken.None).AsTask();
    }

    public ValueTask<int> SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
        => SendAsyncCore(datagram, null, cancellationToken);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _lifetime.Cancel();

        TaskCompletionSource<SessionState>? handshakeCompletion;
        lock (_stateLock)
        {
            _session = null;
            _pendingHandshake = null;
            handshakeCompletion = _handshakeCompletion;
            _handshakeCompletion = null;
        }

        handshakeCompletion?.TrySetCanceled();
        _receiveQueue.Writer.TryComplete();

        if (_ownsUdpClient)
        {
            _udpClient.Dispose();
        }

        _handshakeGate.Dispose();
        _lifetime.Dispose();
        GC.SuppressFinalize(this);
    }

    private async ValueTask<int> SendAsyncCore(
        ReadOnlyMemory<byte> datagram,
        IPEndPoint? endPoint,
        CancellationToken cancellationToken)
    {
        ThrowIfUnavailable();

        if (endPoint is not null && !Protocol.EndpointsMatch(endPoint, _serverEndpoint))
        {
            throw new InvalidOperationException("WireGuardClient is bound to a single remote endpoint.");
        }

        var session = await EnsureSessionAsync(cancellationToken);
        byte[] encryptedPacket;

        lock (_stateLock)
        {
            var activeSession = GetActiveSessionLocked() ?? session;
            encryptedPacket = Protocol.EncryptTransport(datagram.Span, activeSession, out var updatedSession);
            _session = updatedSession;
        }

        await _udpClient.SendAsync(encryptedPacket, _serverEndpoint, cancellationToken);
        return datagram.Length;
    }

    private async Task<SessionState> EnsureSessionAsync(CancellationToken cancellationToken)
    {
        var activeSession = GetActiveSession();
        if (activeSession is not null)
        {
            return activeSession;
        }

        byte[]? initiationPacket = null;
        Task<SessionState>? handshakeTask;

        await _handshakeGate.WaitAsync(cancellationToken);
        try
        {
            ThrowIfUnavailable();

            activeSession = GetActiveSessionLocked();
            if (activeSession is not null)
            {
                return activeSession;
            }

            if (_pendingHandshake is null ||
                DateTime.UtcNow - _pendingHandshake.CreatedAt > HandshakeLifetime ||
                _handshakeCompletion is null ||
                _handshakeCompletion.Task.IsCompleted)
            {
                _pendingHandshake = Protocol.CreateHandshakeInitiation(
                    _clientPrivateKey,
                    _clientPublicKey,
                    _serverPublicKey);
                _handshakeCompletion = new TaskCompletionSource<SessionState>(TaskCreationOptions.RunContinuationsAsynchronously);
                initiationPacket = _pendingHandshake.Packet;
            }

            handshakeTask = _handshakeCompletion!.Task;
        }
        finally
        {
            _handshakeGate.Release();
        }

        if (initiationPacket is not null)
        {
            try
            {
                await _udpClient.SendAsync(initiationPacket, _serverEndpoint, cancellationToken);
            }
            catch (Exception ex)
            {
                FailPendingHandshake(new InvalidOperationException("Failed to send the handshake initiation packet.", ex));
                throw;
            }
        }

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        timeoutCts.CancelAfter(HandshakeTimeout);

        try
        {
            return await handshakeTask.WaitAsync(timeoutCts.Token);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
            throw new ObjectDisposedException(nameof(WireGuardClient));
        }
        catch (OperationCanceledException ex)
        {
            var timeout = new TimeoutException("Timed out waiting for a WireGuard handshake response.", ex);
            FailPendingHandshake(timeout);
            throw timeout;
        }
    }

    private SessionState? GetActiveSession()
    {
        lock (_stateLock)
        {
            return GetActiveSessionLocked();
        }
    }

    private SessionState? GetActiveSessionLocked()
    {
        if (_session is null)
        {
            return null;
        }

        if (_session.ExpiresAt <= DateTime.UtcNow)
        {
            _session = null;
            return null;
        }

        return _session;
    }

    private async Task ReceiveLoopAsync()
    {
        try
        {
            while (!_lifetime.IsCancellationRequested)
            {
                UdpReceiveResult received;
                try
                {
                    received = await _udpClient.ReceiveAsync(_lifetime.Token);
                }
                catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
                {
                    break;
                }
                catch (ObjectDisposedException) when (_lifetime.IsCancellationRequested)
                {
                    break;
                }

                if (!Protocol.EndpointsMatch(received.RemoteEndPoint, _serverEndpoint) || received.Buffer.Length == 0)
                {
                    continue;
                }

                ProcessIncomingPacket(received.Buffer, received.RemoteEndPoint);
            }
        }
        catch (Exception ex)
        {
            _receiveLoopError = ex;
            _receiveQueue.Writer.TryComplete(ex);
            FailPendingHandshake(new InvalidOperationException("The receive loop failed.", ex));
            return;
        }

        _receiveQueue.Writer.TryComplete();
    }

    private void ProcessIncomingPacket(byte[] packet, IPEndPoint remoteEndPoint)
    {
        switch ((MessageType)packet[0])
        {
            case MessageType.HandshakeResponse:
                ProcessHandshakeResponse(packet);
                break;

            case MessageType.Transport:
                ProcessTransportPacket(packet, remoteEndPoint);
                break;

            case MessageType.CookieReply:
                FailPendingHandshake(new NotSupportedException(
                    "The server requested a WireGuard cookie reply, which this client does not support."));
                break;
        }
    }

    private void ProcessHandshakeResponse(ReadOnlySpan<byte> packet)
    {
        PendingHandshake? pendingHandshake;
        TaskCompletionSource<SessionState>? handshakeCompletion;

        lock (_stateLock)
        {
            pendingHandshake = _pendingHandshake;
            handshakeCompletion = _handshakeCompletion;
        }

        if (pendingHandshake is null || handshakeCompletion is null)
        {
            return;
        }

        if (!Protocol.TryCompleteHandshake(packet, _clientPrivateKey, pendingHandshake, out var session, out var errorMessage))
        {
            if (errorMessage is not null)
            {
                FailPendingHandshake(new InvalidOperationException(errorMessage));
            }
            return;
        }

        lock (_stateLock)
        {
            _session = session;
            _pendingHandshake = null;
            _handshakeCompletion = null;
        }

        handshakeCompletion.TrySetResult(session!);
    }

    private void ProcessTransportPacket(ReadOnlySpan<byte> packet, IPEndPoint remoteEndPoint)
    {
        SessionState? currentSession;
        lock (_stateLock)
        {
            currentSession = GetActiveSessionLocked();
        }

        if (currentSession is null)
        {
            return;
        }

        if (!Protocol.TryDecryptTransport(packet, currentSession, out var updatedSession, out var payload))
        {
            return;
        }

        lock (_stateLock)
        {
            _session = updatedSession;
        }

        _receiveQueue.Writer.TryWrite(new UdpReceiveResult(payload!, remoteEndPoint));
    }

    private void ThrowIfUnavailable()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(WireGuardClient));
        }

        if (_receiveLoopError is not null)
        {
            throw new InvalidOperationException("The receive loop is no longer running.", _receiveLoopError);
        }
    }

    private void FailPendingHandshake(Exception exception)
    {
        TaskCompletionSource<SessionState>? handshakeCompletion;
        lock (_stateLock)
        {
            handshakeCompletion = _handshakeCompletion;
            _pendingHandshake = null;
            _handshakeCompletion = null;
        }

        handshakeCompletion?.TrySetException(exception);
    }

    private static void ValidateByteCount(int length, int bytes)
    {
        if (bytes < 0 || bytes > length)
        {
            throw new ArgumentOutOfRangeException(nameof(bytes));
        }
    }

    private static void ValidateKey(ReadOnlyMemory<byte> key, string paramName)
    {
        if (key.Length != Protocol.KeySize)
        {
            throw new ArgumentException($"{paramName} must be exactly {Protocol.KeySize} bytes.", paramName);
        }
    }

    internal enum MessageType : byte
    {
        HandshakeInitiation = 1,
        HandshakeResponse = 2,
        CookieReply = 3,
        Transport = 4
    }

    internal sealed record PendingHandshake(
        byte[] ChainKey,
        byte[] Hash,
        byte[] EphemeralPrivate,
        byte[] EphemeralPublic,
        uint LocalIndex,
        DateTime CreatedAt,
        byte[] Packet);

    internal sealed record SessionState(
        uint LocalIndex,
        uint RemoteIndex,
        byte[] SendingKey,
        byte[] ReceivingKey,
        ulong SendingCounter,
        ulong ReceivingCounter,
        DateTime ExpiresAt);

    internal static class Protocol
    {
        private static readonly KeyAgreementAlgorithm X25519 = KeyAgreementAlgorithm.X25519;
        private static readonly AeadAlgorithm ChaCha20Poly1305 = AeadAlgorithm.ChaCha20Poly1305;
        private static readonly byte[] Construction = Encoding.UTF8.GetBytes("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");
        private static readonly byte[] Identifier = Encoding.UTF8.GetBytes("WireGuard v1 zx2c4 Jason@zx2c4.com");
        private static readonly byte[] LabelMac1 = Encoding.UTF8.GetBytes("mac1----");
        private const ulong TimestampEpochOffset = 0x4000000000000000UL;

        public const int KeySize = 32;
        private const int ReservedSize = 3;
        private const int CommonHeaderSize = 4;
        private const int SenderIndexOffset = CommonHeaderSize;
        private const int SenderIndexSize = 4;
        private const int ReceiverIndexOffset = SenderIndexOffset + SenderIndexSize;
        private const int ReceiverIndexSize = 4;
        private const int EphemeralOffset = SenderIndexOffset + SenderIndexSize;
        private const int EphemeralSize = 32;
        private const int EncryptedStaticOffset = EphemeralOffset + EphemeralSize;
        private const int EncryptedStaticSize = 48;
        private const int EncryptedTimestampOffset = EncryptedStaticOffset + EncryptedStaticSize;
        private const int EncryptedTimestampSize = 28;
        private const int Mac1Offset = EncryptedTimestampOffset + EncryptedTimestampSize;
        private const int MacSize = 16;
        private const int HandshakeInitiationSize = 148;
        private const int HandshakeResponseEphemeralOffset = ReceiverIndexOffset + ReceiverIndexSize;
        private const int HandshakeResponseEncryptedEmptyOffset = HandshakeResponseEphemeralOffset + EphemeralSize;
        private const int HandshakeResponseEncryptedEmptySize = 16;
        private const int HandshakeResponseSize = 92;
        private const int TransportReceiverIndexOffset = CommonHeaderSize;
        private const int CounterOffset = TransportReceiverIndexOffset + ReceiverIndexSize;
        private const int CounterSize = 8;
        private const int TransportPayloadOffset = CounterOffset + CounterSize;
        private const int TransportMinimumSize = 32;

        public static PendingHandshake CreateHandshakeInitiation(
            ReadOnlySpan<byte> clientPrivateKey,
            ReadOnlySpan<byte> clientPublicKey,
            ReadOnlySpan<byte> serverPublicKey)
        {
            var constructionHash = Hash(Construction);
            var hash = Hash(Concat(Hash(Concat(constructionHash, Identifier)), serverPublicKey));
            var localIndex = GenerateLocalIndex();

            using var ephemeralPrivate = Key.Create(X25519, new KeyCreationParameters
            {
                ExportPolicy = KeyExportPolicies.AllowPlaintextExport
            });
            var ephemeralPublic = ephemeralPrivate.PublicKey.Export(KeyBlobFormat.RawPublicKey);

            hash = Hash(Concat(hash, ephemeralPublic));
            var chainKey = Kdf1(constructionHash, ephemeralPublic);

            var remoteStatic = PublicKey.Import(X25519, serverPublicKey, KeyBlobFormat.RawPublicKey);
            var dhEphemeralStatic = X25519.Agree(ephemeralPrivate, remoteStatic, new SharedSecretCreationParameters
            {
                ExportPolicy = KeyExportPolicies.AllowPlaintextExport
            });
            (chainKey, var staticEncryptionKey) = Kdf2(chainKey, dhEphemeralStatic!.Export(SharedSecretBlobFormat.RawSharedSecret));

            var encryptedStatic = AeadEncrypt(staticEncryptionKey, clientPublicKey, hash)
                ?? throw new InvalidOperationException("Failed to encrypt the client static key.");
            hash = Hash(Concat(hash, encryptedStatic));

            using var staticPrivate = Key.Import(X25519, clientPrivateKey, KeyBlobFormat.RawPrivateKey, new KeyCreationParameters
            {
                ExportPolicy = KeyExportPolicies.AllowPlaintextExport
            });
            var dhStaticStatic = X25519.Agree(staticPrivate, remoteStatic, new SharedSecretCreationParameters
            {
                ExportPolicy = KeyExportPolicies.AllowPlaintextExport
            });
            (chainKey, var timestampEncryptionKey) = Kdf2(chainKey, dhStaticStatic!.Export(SharedSecretBlobFormat.RawSharedSecret));

            var encryptedTimestamp = AeadEncrypt(timestampEncryptionKey, EncodeTimestamp(), hash)
                ?? throw new InvalidOperationException("Failed to encrypt the WireGuard timestamp.");
            hash = Hash(Concat(hash, encryptedTimestamp));

            var packet = new byte[HandshakeInitiationSize];
            packet[0] = (byte)MessageType.HandshakeInitiation;

            BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(SenderIndexOffset, SenderIndexSize), localIndex);
            ephemeralPublic.CopyTo(packet.AsSpan(EphemeralOffset, EphemeralSize));
            encryptedStatic.CopyTo(packet.AsSpan(EncryptedStaticOffset, EncryptedStaticSize));
            encryptedTimestamp.CopyTo(packet.AsSpan(EncryptedTimestampOffset, EncryptedTimestampSize));

            var mac1Key = Hash(Concat(LabelMac1, serverPublicKey));
            var mac1 = Mac(mac1Key, packet.AsSpan(0, Mac1Offset));
            mac1.CopyTo(packet.AsSpan(Mac1Offset, MacSize));

            return new PendingHandshake(
                chainKey,
                hash,
                ephemeralPrivate.Export(KeyBlobFormat.RawPrivateKey),
                ephemeralPublic,
                localIndex,
                DateTime.UtcNow,
                packet);
        }

        public static byte[] DerivePublicKey(ReadOnlySpan<byte> privateKey)
        {
            using var key = Key.Import(X25519, privateKey, KeyBlobFormat.RawPrivateKey, new KeyCreationParameters
            {
                ExportPolicy = KeyExportPolicies.AllowPlaintextExport
            });
            return key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        }

        public static bool EndpointsMatch(IPEndPoint left, IPEndPoint right)
            => left.Port == right.Port && left.Address.Equals(right.Address);

        public static byte[] EncryptTransport(
            ReadOnlySpan<byte> payload,
            SessionState session,
            out SessionState updatedSession)
        {
            var encryptedPayload = EncryptTransportPayload(session.SendingKey, session.SendingCounter, payload)
                ?? throw new InvalidOperationException("Failed to encrypt the outgoing transport packet.");

            var packet = new byte[TransportPayloadOffset + encryptedPayload.Length];
            packet[0] = (byte)MessageType.Transport;
            BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(TransportReceiverIndexOffset, ReceiverIndexSize), session.RemoteIndex);
            BinaryPrimitives.WriteUInt64LittleEndian(packet.AsSpan(CounterOffset, CounterSize), session.SendingCounter);
            encryptedPayload.CopyTo(packet.AsSpan(TransportPayloadOffset));

            updatedSession = session with
            {
                SendingCounter = session.SendingCounter + 1,
                ExpiresAt = DateTime.UtcNow.Add(SessionLifetime)
            };

            return packet;
        }

        public static bool TryCompleteHandshake(
            ReadOnlySpan<byte> packet,
            ReadOnlySpan<byte> clientPrivateKey,
            PendingHandshake pendingHandshake,
            out SessionState? session,
            out string? errorMessage)
        {
            session = null;
            errorMessage = null;

            if (packet.Length != HandshakeResponseSize || packet[0] != (byte)MessageType.HandshakeResponse)
            {
                return false;
            }

            var receiverIndex = BinaryPrimitives.ReadUInt32LittleEndian(packet.Slice(ReceiverIndexOffset, ReceiverIndexSize));
            if (receiverIndex != pendingHandshake.LocalIndex)
            {
                return false;
            }

            try
            {
                var remoteIndex = BinaryPrimitives.ReadUInt32LittleEndian(packet.Slice(SenderIndexOffset, SenderIndexSize));
                var remoteEphemeral = packet.Slice(HandshakeResponseEphemeralOffset, EphemeralSize).ToArray();
                var encryptedEmpty = packet.Slice(HandshakeResponseEncryptedEmptyOffset, HandshakeResponseEncryptedEmptySize);

                var hash = Hash(Concat(pendingHandshake.Hash, remoteEphemeral));
                var chainKey = Kdf1(pendingHandshake.ChainKey, remoteEphemeral);

                using var localEphemeralPrivate = Key.Import(X25519, pendingHandshake.EphemeralPrivate, KeyBlobFormat.RawPrivateKey, new KeyCreationParameters
                {
                    ExportPolicy = KeyExportPolicies.AllowPlaintextExport
                });
                var remoteEphemeralKey = PublicKey.Import(X25519, remoteEphemeral, KeyBlobFormat.RawPublicKey);

                var dhEphemeralEphemeral = X25519.Agree(localEphemeralPrivate, remoteEphemeralKey, new SharedSecretCreationParameters
                {
                    ExportPolicy = KeyExportPolicies.AllowPlaintextExport
                });
                chainKey = Kdf1(chainKey, dhEphemeralEphemeral!.Export(SharedSecretBlobFormat.RawSharedSecret));

                using var localStaticPrivate = Key.Import(X25519, clientPrivateKey, KeyBlobFormat.RawPrivateKey, new KeyCreationParameters
                {
                    ExportPolicy = KeyExportPolicies.AllowPlaintextExport
                });
                var dhStaticEphemeral = X25519.Agree(localStaticPrivate, remoteEphemeralKey, new SharedSecretCreationParameters
                {
                    ExportPolicy = KeyExportPolicies.AllowPlaintextExport
                });
                chainKey = Kdf1(chainKey, dhStaticEphemeral!.Export(SharedSecretBlobFormat.RawSharedSecret));

                (chainKey, var tempHash, var emptyKey) = Kdf3(chainKey, new byte[KeySize]);
                hash = Hash(Concat(hash, tempHash));

                var decryptedEmpty = AeadDecrypt(emptyKey, encryptedEmpty, hash);
                if (decryptedEmpty is null || decryptedEmpty.Length != 0)
                {
                    errorMessage = "Failed to validate the WireGuard handshake response.";
                    return false;
                }

                var keyMaterial = Kdf2(chainKey, []);
                session = new SessionState(
                    pendingHandshake.LocalIndex,
                    remoteIndex,
                    keyMaterial.key1,
                    keyMaterial.key2,
                    0,
                    0,
                    DateTime.UtcNow.Add(SessionLifetime));
                return true;
            }
            catch (Exception ex)
            {
                errorMessage = $"Failed to complete the WireGuard handshake: {ex.Message}";
                return false;
            }
        }

        public static bool TryDecryptTransport(
            ReadOnlySpan<byte> packet,
            SessionState session,
            out SessionState? updatedSession,
            out byte[]? payload)
        {
            updatedSession = null;
            payload = null;

            if (packet.Length < TransportMinimumSize || packet[0] != (byte)MessageType.Transport)
            {
                return false;
            }

            var receiverIndex = BinaryPrimitives.ReadUInt32LittleEndian(packet.Slice(TransportReceiverIndexOffset, ReceiverIndexSize));
            if (receiverIndex != session.LocalIndex)
            {
                return false;
            }

            var counter = BinaryPrimitives.ReadUInt64LittleEndian(packet.Slice(CounterOffset, CounterSize));
            if (session.ReceivingCounter > 0 && counter <= session.ReceivingCounter)
            {
                return false;
            }

            payload = DecryptTransportPayload(session.ReceivingKey, counter, packet.Slice(TransportPayloadOffset));
            if (payload is null)
            {
                return false;
            }

            updatedSession = session with
            {
                ReceivingCounter = counter,
                ExpiresAt = DateTime.UtcNow.Add(SessionLifetime)
            };
            return true;
        }

        private static byte[] EncodeTimestamp()
        {
            var timestamp = new byte[12];
            BinaryPrimitives.WriteUInt64BigEndian(timestamp.AsSpan(0, 8), TimestampEpochOffset + (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            return timestamp;
        }

        private static uint GenerateLocalIndex()
        {
            Span<byte> bytes = stackalloc byte[4];
            RandomNumberGenerator.Fill(bytes);
            return BinaryPrimitives.ReadUInt32LittleEndian(bytes);
        }

        private static byte[]? AeadDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData)
        {
            try
            {
                using var keyObject = Key.Import(ChaCha20Poly1305, key, KeyBlobFormat.RawSymmetricKey);
                return ChaCha20Poly1305.Decrypt(keyObject, new byte[12], associatedData, ciphertext);
            }
            catch
            {
                return null;
            }
        }

        private static byte[]? AeadEncrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData)
        {
            try
            {
                using var keyObject = Key.Import(ChaCha20Poly1305, key, KeyBlobFormat.RawSymmetricKey);
                return ChaCha20Poly1305.Encrypt(keyObject, new byte[12], associatedData, plaintext);
            }
            catch
            {
                return null;
            }
        }

        private static byte[] Concat(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            var combined = new byte[left.Length + right.Length];
            left.CopyTo(combined);
            right.CopyTo(combined.AsSpan(left.Length));
            return combined;
        }

        private static byte[]? DecryptTransportPayload(ReadOnlySpan<byte> key, ulong counter, ReadOnlySpan<byte> encryptedPayload)
        {
            try
            {
                using var keyObject = Key.Import(ChaCha20Poly1305, key, KeyBlobFormat.RawSymmetricKey);
                Span<byte> nonce = stackalloc byte[12];
                BinaryPrimitives.WriteUInt64LittleEndian(nonce[4..], counter);
                return ChaCha20Poly1305.Decrypt(keyObject, nonce, [], encryptedPayload);
            }
            catch
            {
                return null;
            }
        }

        private static byte[]? EncryptTransportPayload(ReadOnlySpan<byte> key, ulong counter, ReadOnlySpan<byte> payload)
        {
            try
            {
                using var keyObject = Key.Import(ChaCha20Poly1305, key, KeyBlobFormat.RawSymmetricKey);
                Span<byte> nonce = stackalloc byte[12];
                BinaryPrimitives.WriteUInt64LittleEndian(nonce[4..], counter);
                return ChaCha20Poly1305.Encrypt(keyObject, nonce, [], payload);
            }
            catch
            {
                return null;
            }
        }

        private static byte[] Hash(ReadOnlySpan<byte> input) => Blake2s.ComputeHash(KeySize, input);

        private static byte[] Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input)
        {
            const int blockSize = 64;

            Span<byte> paddedKey = stackalloc byte[blockSize];
            key.CopyTo(paddedKey);

            Span<byte> outerPad = stackalloc byte[blockSize];
            Span<byte> innerPad = stackalloc byte[blockSize];

            for (var index = 0; index < blockSize; index++)
            {
                outerPad[index] = (byte)(paddedKey[index] ^ 0x5c);
                innerPad[index] = (byte)(paddedKey[index] ^ 0x36);
            }

            var innerHash = Blake2s.ComputeHash(KeySize, Concat(innerPad, input));
            return Blake2s.ComputeHash(KeySize, Concat(outerPad, innerHash));
        }

        private static byte[] Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input)
            => Blake2s.ComputeHash(16, key, input);

        private static byte[] Kdf1(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input)
            => Kdf(key, input, 1)[0];

        private static (byte[] key1, byte[] key2) Kdf2(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input)
        {
            var outputs = Kdf(key, input, 2);
            return (outputs[0], outputs[1]);
        }

        private static (byte[] key1, byte[] key2, byte[] key3) Kdf3(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input)
        {
            var outputs = Kdf(key, input, 3);
            return (outputs[0], outputs[1], outputs[2]);
        }

        private static byte[][] Kdf(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, int count)
        {
            var pseudorandomKey = Hmac(key, input);
            var output = new byte[count][];
            var previous = Array.Empty<byte>();

            for (var index = 0; index < count; index++)
            {
                var material = new byte[previous.Length + 1];
                previous.CopyTo(material, 0);
                material[^1] = (byte)(index + 1);
                previous = Hmac(pseudorandomKey, material);
                output[index] = previous;
            }

            return output;
        }
    }
}