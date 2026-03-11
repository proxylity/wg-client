using System.Net;
using Proxylity.WireGuardClient;

/// <summary>
/// Integration tests that require a live WireGuard echo backend deployed via the AWS SAM
/// stack in tests/. See README.md §Testing for deployment and setup instructions.
///
/// Required environment variables (set from SAM stack Outputs):
///   WG_SERVER_ENDPOINT  – host:port of the running WireGuard gateway  (e.g. "1.2.3.4:2059")
///   WG_SERVER_KEY       – base64 server public key                     (e.g. "AdqJXb...")
///   WG_CLIENT_PRIVATE_KEY – base64 client private key you generated before deploying
/// </summary>
[Trait("Category", "Integration")]
public class WireGuardClientTests
{
    [SkippableFact]
    public async Task TestWireGuardClientInitialization()
    {
        var serverEndpointRaw = Environment.GetEnvironmentVariable("WG_SERVER_ENDPOINT");
        var serverKeyRaw      = Environment.GetEnvironmentVariable("WG_SERVER_KEY");
        var clientKeyRaw      = Environment.GetEnvironmentVariable("WG_CLIENT_PRIVATE_KEY");

        Skip.If(
            string.IsNullOrWhiteSpace(serverEndpointRaw) ||
            string.IsNullOrWhiteSpace(serverKeyRaw)      ||
            string.IsNullOrWhiteSpace(clientKeyRaw),
            "Integration test skipped: WG_SERVER_ENDPOINT, WG_SERVER_KEY, and WG_CLIENT_PRIVATE_KEY " +
            "must all be set. See README.md §Testing for setup instructions.");

        var serverEndpoint = IPEndPoint.Parse(serverEndpointRaw!);
        var serverKey      = Convert.FromBase64String(serverKeyRaw!);
        var clientKey      = Convert.FromBase64String(clientKeyRaw!);
        var request        = System.Text.Encoding.UTF8.GetBytes("Hello, WireGuard!");

        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var wg  = new WireGuardClient(serverEndpoint, serverKey, clientKey);

        await wg.SendAsync(request, cts.Token);
        var received = await wg.ReceiveAsync(cts.Token);

        Assert.NotNull(received.Buffer);
        Assert.NotEmpty(received.Buffer);

        var response = System.Text.Encoding.UTF8.GetString(received.Buffer);
        Assert.Contains("Hello, WireGuard!", response);
    }
}
