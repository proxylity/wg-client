# Proxylity.WireGuardClient

[![CI](https://github.com/proxylity/wg-client/actions/workflows/ci.yml/badge.svg)](https://github.com/proxylity/wg-client/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/Proxylity.WireGuardClient.svg)](https://www.nuget.org/packages/Proxylity.WireGuardClient)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A standalone, `UdpClient`-compatible WireGuard client library for .NET. It implements the full **Noise\_IKpsk2\_25519\_ChaChaPoly\_BLAKE2s** handshake and **ChaCha20-Poly1305** transport encryption — no kernel modules, no platform binaries, pure managed code.

## Features

- Drop-in `UdpClient` facade — same `SendAsync` / `ReceiveAsync` API
- Full WireGuard handshake (Noise IKpsk2) and transport encryption
- Automatic session re-keying on expiry
- Thread-safe; background receive loop with back-pressure via `Channel<T>`
- Zero unmanaged dependencies at the .NET level (NSec wraps libsodium)

## Installation

```
dotnet add package Proxylity.WireGuardClient
```

Or via the NuGet Package Manager:

```xml
<PackageReference Include="Proxylity.WireGuardClient" Version="0.1.0" />
```

## Quick Start

```csharp
using System.Net;
using Proxylity.WireGuardClient;

// Keys are 32-byte raw X25519 values, typically base64-encoded
var serverEndpoint = IPEndPoint.Parse("203.0.113.1:51820");
var serverPublicKey  = Convert.FromBase64String("<server public key base64>");
var clientPrivateKey = Convert.FromBase64String("<client private key base64>");

await using var wg = new WireGuardClient(serverEndpoint, serverPublicKey, clientPrivateKey);

await wg.SendAsync(Encoding.UTF8.GetBytes("hello"), CancellationToken.None);

var result = await wg.ReceiveAsync(CancellationToken.None);
Console.WriteLine(Encoding.UTF8.GetString(result.Buffer));
```

## API

### `WireGuardClient(IPEndPoint serverEndpoint, byte[] serverPublicKey, byte[] clientPrivateKey)`

Creates a new client. The client opens an ephemeral local UDP socket.

| Parameter | Description |
|-----------|-------------|
| `serverEndpoint` | IP + port of the WireGuard peer |
| `serverPublicKey` | 32-byte X25519 server public key |
| `clientPrivateKey` | 32-byte X25519 client private key |

An overload accepting an existing `UdpClient` is also available for socket re-use or testing.

### `SendAsync(byte[] datagram, CancellationToken ct)`

Performs the Noise handshake on first call (or after session expiry), then encrypts and sends the datagram.

### `ReceiveAsync(CancellationToken ct)`

Returns the next decrypted datagram as `UdpReceiveResult`.

### `Close()` / `Dispose()`

Closes the underlying UDP socket and releases all resources.

## Key Generation

WireGuard uses **X25519** (Curve25519 ECDH) key pairs. You can generate a key pair with:

**Using the `wg` tool (recommended, requires WireGuard installed):**

```sh
# Generate private key
wg genkey | tee client_private.key

# Derive the matching public key (needed as a parameter when deploying the stack)
wg pubkey < client_private.key | tee client_public.key
```

**Using the library itself** (in a small .NET script):

```csharp
// Derive public key from a randomly generated private key
byte[] privateKey = new byte[32];
System.Security.Cryptography.RandomNumberGenerator.Fill(privateKey);
byte[] publicKey = Proxylity.WireGuardClient.Protocol.DerivePublicKey(privateKey);

Console.WriteLine("Private: " + Convert.ToBase64String(privateKey));
Console.WriteLine("Public:  " + Convert.ToBase64String(publicKey));
```

> **Important:** Generate your client key pair *before* deploying the integration test stack — the public key is a required CloudFormation parameter.

## Testing

### Unit and Protocol Tests (no setup required)

```sh
dotnet test --filter "Category!=Integration"
```

These tests are fully in-memory and have no external dependencies.

### Integration Tests (requires AWS deployment)

The integration test (`WireGuardClientTests`) exercises a live WireGuard echo endpoint backed by an AWS Lambda function. It requires:

1. **AWS CLI and SAM CLI** installed and configured with appropriate credentials
2. **A client key pair** generated before deployment (see [Key Generation](#key-generation))

#### Deploy the backend stack

```sh
cd tests
sam deploy --guided
```

During the guided deployment you will be prompted for:

| Parameter | Value |
|-----------|-------|
| `ClientPublicKey` | The base64 public key you generated (contents of `client_public.key`) |
| `ClientCidr` | IP CIDR allowed to connect — use `0.0.0.0/0` for testing |

`sam deploy --guided` creates a `samconfig.toml` file in the `tests/` directory with your choices so you can redeploy with just `sam deploy` later. **Do not commit `samconfig.toml`** — it contains account-specific configuration.

#### Collect stack outputs

After a successful deploy, the SAM CLI prints the stack outputs. Capture these two values:

| Output key | Description |
|------------|-------------|
| `Endpoint` | `host:port` of the WireGuard gateway |
| `ServerPublicKey` | Base64 server public key |

#### Set environment variables and run

```sh
# Windows (PowerShell)
$env:WG_SERVER_ENDPOINT   = "host:port from stack output"
$env:WG_SERVER_KEY        = "base64 server public key from stack output"
$env:WG_CLIENT_PRIVATE_KEY = "base64 private key you generated"

dotnet test --filter "Category=Integration"
```

```sh
# Linux / macOS
export WG_SERVER_ENDPOINT="host:port from stack output"
export WG_SERVER_KEY="base64 server public key from stack output"
export WG_CLIENT_PRIVATE_KEY="base64 private key you generated"

dotnet test --filter "Category=Integration"
```

If the environment variables are not set the test is **skipped** automatically — it will never fail CI due to missing infrastructure.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) for our responsible-disclosure policy.

## License

[MIT](LICENSE) © 2026 Proxylity LLC
