using System.Net;
using System.Text;
using System.Text.Json;
using AvantimeConnect.Core.Enrollment;
using AvantimeConnect.Core.WireGuard;

int passed = 0;
void Check(bool value, string name)
{
    if (!value) throw new Exception("FAIL: " + name);
    Console.WriteLine("PASS: " + name);
    passed++;
}
async Task Reject(Func<Task> action, string name)
{
    try { await action(); }
    catch (ClientException) { Check(true, name); return; }
    throw new Exception("FAIL: " + name);
}
var store = new MemoryStore();
var keys = new FakeKeys();
var requests = new List<string>();
var transport = new FakeTransport(async request =>
{
    Check(store.Data is not null, "identity persisted before HTTP");
    requests.Add(await request.Content!.ReadAsStringAsync());
    return requests.Count == 1 ? new HttpResponseMessage(HttpStatusCode.BadGateway)
        : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(Profile())) };
});
using var http = new HttpClient(transport);
var service = new EnrollmentService(http, store, keys);
await Reject(() => service.EnrollAsync("https://vpn.example", "test-invitation", "TEST-PC"), "502 retains identity");
// New service simulates a process restart; the storage fake serializes, just like the real store.
service = new EnrollmentService(http, store, keys);
var result = await service.EnrollAsync("https://vpn.example/", "test-invitation", "TEST-PC");
Check(requests.Count == 2 && requests[0] == requests[1] && keys.Calls == 1, "retry sends identical identity after restart");
Check(result.Profile?.VpnIp == "10.30.0.241" && store.Load()?.Profile is not null, "validated profile persisted");
var body = JsonDocument.Parse(requests[0]).RootElement;
Check(body.EnumerateObject().Count() == 3 && !requests[0].Contains(result.PrivateKey), "request has no private key");
await service.EnrollAsync("https://vpn.example", "test-invitation", "TEST-PC");
Check(requests.Count == 2, "saved profile causes no extra enrollment");
await Reject(() => service.EnrollAsync("https://vpn.example", "another-token", "TEST-PC"), "different invite rejected");
await Reject(() => service.EnrollAsync("https://other.example", "test-invitation", "TEST-PC"), "different server rejected");
await Reject(() => service.EnrollAsync("https://vpn.example", "test-invitation", "OTHER-PC"), "different device rejected");
Check(keys.Calls == 1 && requests.Count == 2, "rejected changes cause no new key or request");

foreach (string badOrigin in new[] { "http://vpn.example", "https://user:pass@vpn.example", "https://vpn.example/path", "https://vpn.example/?token=x" })
    await Reject(() => Task.FromResult(EnrollmentService.ValidateOrigin(badOrigin)), "unsafe origin rejected");
Check(EnrollmentService.ValidateOrigin("http://127.0.0.1:15173") == "http://127.0.0.1:15173", "explicit loopback tunnel permitted");

foreach (var mutate in new Action<EnrollmentProfile>[]
{
    p => p.AllowedIps = "0.0.0.0/0", p => p.AllowedIps = "10.40.0.0/24\nPostUp=bad",
    p => p.Endpoint = "vpn.example:51820\nBad=1", p => p.ServerPublicKey = "invalid",
    p => p.VpnIp = "127.0.0.1", p => p.RdpHost = "host\nBad=1", p => p.Keepalive = -1
})
{
    var profile = Profile(); mutate(profile);
    await Reject(() => { WireGuardManager.ValidateProfile(profile); return Task.CompletedTask; }, "invalid profile rejected");
}
foreach (int code in new[] { 301, 302, 307, 404, 409, 410, 503 })
{
    var s = new MemoryStore();
    using var client = new HttpClient(new FakeTransport(_ => Task.FromResult(new HttpResponseMessage((HttpStatusCode)code)
    { Content = new StringContent("secret-server-diagnostic") })));
    var enroll = new EnrollmentService(client, s, new FakeKeys());
    try { await enroll.EnrollAsync("https://vpn.example", "invite", "PC"); throw new Exception("unexpected success"); }
    catch (ClientException ex) { Check(!ex.Message.Contains("secret-server-diagnostic") && s.Load()?.Profile is null, "HTTP failure retains pending identity, hides body: " + code); }
}
var failingStore = new MemoryStore { FailWrites = true };
var sent = false;
using (var client = new HttpClient(new FakeTransport(_ => { sent = true; throw new Exception("must not send"); })))
{
    try { await new EnrollmentService(client, failingStore, new FakeKeys()).EnrollAsync("https://vpn.example", "invite", "PC"); }
    catch (IOException) { }
    Check(!sent, "storage failure blocks HTTP");
}
var pending = new MemoryStore();
using (var client = new HttpClient(new FakeTransport(_ => throw new HttpRequestException("raw-secret"))))
{
    await Reject(() => new EnrollmentService(client, pending, new FakeKeys()).EnrollAsync("https://vpn.example", "invite", "PC"), "network failure handled");
    Check(pending.Load()?.PublicKey is not null, "network failure retains key");
}
if (OperatingSystem.IsWindows())
{
    var path = Path.Combine(Path.GetTempPath(), "avantime-check-" + Guid.NewGuid().ToString("N"), "state.dpapi");
    try
    {
        var protectedStore = new ProtectedEnrollmentStore(path);
        protectedStore.Save(result);
        Check(protectedStore.Load()!.PrivateKey == result.PrivateKey, "DPAPI round trip");
        Check(!Encoding.UTF8.GetString(File.ReadAllBytes(path)).Contains(result.Token), "invitation absent from disk plaintext");
        var damaged = File.ReadAllBytes(path); damaged[damaged.Length / 2] ^= 1; File.WriteAllBytes(path, damaged);
        try { protectedStore.Load(); throw new Exception("corrupt data accepted"); }
        catch (System.Security.Cryptography.CryptographicException) { Check(true, "damaged DPAPI state fails closed"); }
    }
    finally { Directory.Delete(Path.GetDirectoryName(path)!, true); }
    if (File.Exists(WireGuardManager.WgPath))
    {
        var pair = await new WireGuardManager().GenerateAsync(CancellationToken.None);
        Check(pair.PrivateKey != pair.PublicKey, "installed wg.exe key generation (no tunnel changes)");
    }
    else Console.WriteLine("SKIP: installed WireGuard check");
}
else Console.WriteLine("SKIP: Windows DPAPI and installed wg.exe checks (requires Windows)");
Console.WriteLine($"PASS: {passed} checks; no real API requests or tunnel changes.");

static EnrollmentProfile Profile() => new()
{
    VpnIp = "10.30.0.241", ServerPublicKey = Convert.ToBase64String(Enumerable.Repeat((byte)3, 32).ToArray()),
    Endpoint = "vpn.example:51820", AllowedIps = "10.40.0.0/24", Keepalive = 25, AppType = "desktop", RdpHost = "10.40.0.20"
};
sealed class MemoryStore : IEnrollmentStore
{
    public string? Data;
    public bool FailWrites;
    public EnrollmentState? Load() => Data is null ? null : JsonSerializer.Deserialize<EnrollmentState>(Data);
    public void Save(EnrollmentState state)
    {
        if (FailWrites) throw new IOException("simulated disk error");
        Data = JsonSerializer.Serialize(state);
    }
}
sealed class FakeKeys : IKeyGenerator
{
    public int Calls;
    public Task<(string PrivateKey, string PublicKey)> GenerateAsync(CancellationToken cancellationToken)
    {
        Calls++;
        return Task.FromResult((Convert.ToBase64String(Enumerable.Repeat((byte)1, 32).ToArray()),
                               Convert.ToBase64String(Enumerable.Repeat((byte)2, 32).ToArray())));
    }
}
sealed class FakeTransport(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => respond(request);
}
