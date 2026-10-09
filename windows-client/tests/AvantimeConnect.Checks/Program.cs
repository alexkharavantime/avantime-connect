using System.Net;
using System.Text;
using System.Text.Json;
using AvantimeConnect.Core.Enrollment;
using AvantimeConnect.Core.WireGuard;

if (args.Length == 3 && args[0] == "--broker-smoke")
{
    await BrokerSmoke.RunAsync(args[1], args[2]);
    return;
}
if (args.Length != 0)
{
    if (args.Length != 1 || args[0] != "--tunnel-smoke") throw new ArgumentException("Unknown check mode.");
    await TunnelSmoke.RunAsync();
    return;
}

await RemoteAppChecks.RunAsync();

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
var tunnelState = new EnrollmentState
{
    PrivateKey = result.PrivateKey, PublicKey = result.PublicKey, Profile = Profile()
};
tunnelState.Profile.VpnIp = "10.30.0.12";
var tunnel = new TunnelDefinition(tunnelState);
Check(tunnel.Configuration.Contains("Address = 10.30.0.12/32\n")
    && !tunnel.Configuration.Contains("DNS") && !tunnel.Configuration.Contains("PostUp")
    && tunnel.Configuration.Contains("AllowedIPs = 10.40.0.0/24\n"), "tunnel uses host address and only the approved split route");
Check(tunnel.Name == new TunnelDefinition(tunnelState).Name && tunnel.Name.Length <= 32, "tunnel identity survives restart");
foreach (string routes in new[] { "0.0.0.0/1,128.0.0.0/1", "10.20.0.0/24", "10.40.0.0/24,10.20.0.0/24", "::/1,8000::/1" })
{
    tunnelState.Profile.AllowedIps = routes;
    await Reject(() => Task.FromResult(new TunnelDefinition(tunnelState)), "unapproved route set cannot be installed");
}
tunnelState.Profile.AllowedIps = "10.40.0.0/24";
foreach (string ip in new[] { "10.30.0.240", "10.30.0.241", "10.30.0.242", "10.20.0.30", "10.30.0.1" })
{
    tunnelState.Profile.VpnIp = ip;
    await Reject(() => Task.FromResult(new TunnelDefinition(tunnelState)), "reserved or foreign interface address rejected");
}
tunnelState.Profile.VpnIp = "10.30.0.12";
// Access refresh preserves device identity and rejects unexpected server changes.
var refreshStore = new MemoryStore();
tunnelState.ApiOrigin = "https://vpn.example";
tunnelState.Token = "refresh-test-token";
tunnelState.DeviceName = "REFRESH-PC";
refreshStore.Save(tunnelState);
foreach (var envs in new[] { new[] { "dev", "prod" }, new[] { "dev" }, new[] { "prod" } })
{
    var fresh = refreshStore.Load()!.Profile!;
    fresh.Environments = envs;
    fresh.AccessRevision++;
    fresh.AllowedIps = string.Join(", ", envs.Select(e => e == "dev" ? "10.20.0.20/32" : "10.40.0.0/24"));
    fresh.RdpHost = envs.Contains("prod") ? "10.40.0.20" : "10.20.0.20";
    using var refreshHttp = new HttpClient(new FakeTransport(async request =>
    {
        var json = await request.Content!.ReadAsStringAsync();
        Check(request.RequestUri!.AbsolutePath == "/api/enroll/profile" && !json.Contains(tunnelState.PrivateKey), "refresh uses bound public identity without private key");
        return new HttpResponseMessage(HttpStatusCode.OK) {Content = new StringContent(JsonSerializer.Serialize(fresh))};
    }));
    await new EnrollmentService(refreshHttp, refreshStore, keys).RefreshAccessAsync();
    var refreshed = refreshStore.Load()!;
    Check(new TunnelDefinition(refreshed).Name == tunnel.Name && refreshed.PrivateKey == tunnelState.PrivateKey
        && refreshed.Profile!.VpnIp == tunnelState.Profile.VpnIp, "policy update preserves key, address and tunnel identity");
    Check(TunnelDefinition.Environments(refreshed.Profile!).SequenceEqual(envs), "DEV/PROD routes match assigned environments");
}
foreach (var change in new Action<EnrollmentProfile>[] {
    p => p.AccessRevision = 0, p => p.VpnIp = "10.30.0.99", p => p.Endpoint = "other.example:51820",
    p => p.AllowedIps = "10.20.0.0/24", p => p.Environments = ["dev"], p => p.Environments = ["dev", "dev"] })
{
    var before = refreshStore.Data;
    var fresh = refreshStore.Load()!.Profile!;
    change(fresh);
    using var refreshHttp = new HttpClient(new FakeTransport(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {Content = new StringContent(JsonSerializer.Serialize(fresh))})));
    await Reject(() => new EnrollmentService(refreshHttp, refreshStore, keys).RefreshAccessAsync(), "invalid or older access response rejected");
    Check(refreshStore.Data == before, "failed refresh preserves stored profile");
}
foreach (var routes in new[] { "10.20.0.20/32", "10.20.0.20/32, 10.40.0.10/32" })
{
    var devProfile = Profile();
    devProfile.VpnIp = "10.30.0.15"; devProfile.Environments = ["dev"];
    devProfile.RdpHost = "10.20.0.20"; devProfile.AllowedIps = routes;
    var devState = new EnrollmentState { PrivateKey = result.PrivateKey, PublicKey = result.PublicKey, Profile = devProfile };
    var devTunnel = new TunnelDefinition(devState);
    Check(devTunnel.AllowedIps == "10.20.0.20/32, 10.40.0.10/32" && devProfile.AllowedIps == routes, "legacy and new DEV profiles add only DNS host without changing saved profile");
}
var now = DateTimeOffset.FromUnixTimeSeconds(2000);
Check(TunnelDefinition.HasRecentHandshake(tunnel.ServerPublicKey + "\t1999", tunnel.ServerPublicKey, now), "fresh expected peer handshake accepted");
foreach (string output in new[] { tunnel.ServerPublicKey + "\t0", tunnel.ServerPublicKey + "\t1819",
    tunnel.ServerPublicKey + "\t2001", "other-peer\t1999", tunnel.ServerPublicKey + "\t1999\nother\t1999", "malformed" })
    Check(!TunnelDefinition.HasRecentHandshake(output, tunnel.ServerPublicKey, now), "missing/stale/future/foreign handshake never reports connected");

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
    var plain = Encoding.UTF8.GetBytes(tunnel.Configuration);
    var encrypted = TunnelDpapi.Protect(plain, tunnel.Name);
    Check(!Encoding.UTF8.GetString(encrypted).Contains(tunnelState.PrivateKey), "service configuration encrypted before disk write");
    Check(TunnelDpapi.Unprotect(encrypted, tunnel.Name).SequenceEqual(plain), "WireGuard DPAPI description format round trip");
    try { TunnelDpapi.Unprotect(encrypted, "wrong-name"); throw new Exception("name mismatch accepted"); }
    catch (System.Security.Cryptography.CryptographicException) { Check(true, "DPAPI service configuration bound to tunnel name"); }
    var exe = @"C:\Program Files\WireGuard\wireguard.exe";
    var conf = @"C:\Program Files\AvantimeConnect.Tunnels\avt-test.conf.dpapi";
    var command = $"\"{exe}\" /tunnelservice \"{conf}\"";
    Check(WindowsTunnelController.IsExpectedCommand(command, exe, conf), "expected service executable and configuration accepted");
    foreach (var bad in new[] { command + " extra", command.Replace("/tunnelservice", "/managerservice"),
        command.Replace("wireguard.exe", "other.exe"), command.Replace("avt-test", "foreign"), "cmd.exe /c " + command })
        Check(!WindowsTunnelController.IsExpectedCommand(bad, exe, conf), "foreign service command rejected");
    using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
    if (new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
    {
        var aclPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "AvantimeConnect.Checks-" + Guid.NewGuid().ToString("N"));
        try
        {
            ProtectedTunnelFiles.EnsureDirectory(aclPath);
            var configPath = Path.Combine(aclPath, tunnel.Name + ".conf.dpapi");
            ProtectedTunnelFiles.Create(configPath, tunnel);
            ProtectedTunnelFiles.Verify(configPath, tunnel);
            Check(true, "protected configuration ACL and identity verified");
            var file = new FileInfo(configPath);
            var acl = System.IO.FileSystemAclExtensions.GetAccessControl(file);
            acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.WorldSid, null),
                System.Security.AccessControl.FileSystemRights.Read, System.Security.AccessControl.AccessControlType.Allow));
            System.IO.FileSystemAclExtensions.SetAccessControl(file, acl);
            try { ProtectedTunnelFiles.Verify(configPath, tunnel); throw new Exception("weak ACL accepted"); }
            catch (InvalidDataException) { Check(true, "readable-by-everyone configuration fails closed"); }
        }
        finally { if (Directory.Exists(aclPath)) Directory.Delete(aclPath, true); }
    }
    else Console.WriteLine("SKIP: restricted service-file ACL check requires administrator");
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
