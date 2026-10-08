using System.Security.Principal;
using System.Security.Cryptography;
using AvantimeConnect.Core.Broker;
using AvantimeConnect.Core.Enrollment;
using AvantimeConnect.Core.WireGuard;

internal static class BrokerSmoke
{
    internal static async Task RunAsync(string phase, string directory)
    {
        if (Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true"
            || Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted") throw new Exception("CI only");
        using var identity = WindowsIdentity.GetCurrent();
        if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator) || identity.IsSystem)
            throw new Exception("Expected a real standard user");
        void Check(bool value, string label)
        {
            if (!value) throw new Exception("FAIL: " + label);
            Console.WriteLine("PASS: " + label);
        }
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AvantimeConnect", "enrollment.dpapi");
        var store = new ProtectedEnrollmentStore(path);
        if (phase == "foreign")
        {
            Check(store.Load() is null, "second user has no enrollment");
            Check(await BrokerClient.ExecuteAsync("disconnect", File.ReadAllText(Path.Combine(directory, "name"))) == TunnelResult.InvalidProfile,
                "second standard user cannot stop first user's tunnel");
            return;
        }
        if (phase == "connect")
        {
            Check(store.Load() is null, "clean standard user profile");
            var pair = await new WireGuardManager().GenerateAsync(default);
            var peer = await new WireGuardManager().GenerateAsync(default);
            store.Save(new EnrollmentState
            {
                ApiOrigin = "https://connect.avantime.lv", DeviceName = "CI-ONLY",
                PrivateKey = pair.PrivateKey, PublicKey = pair.PublicKey,
                Profile = new EnrollmentProfile { VpnIp = "10.30.0.239", ServerPublicKey = peer.PublicKey,
                    Endpoint = "127.0.0.1:9", AllowedIps = "10.40.0.0/24", Keepalive = 25, AppType = "desktop", RdpHost = "10.40.0.20" }
            });
        }
        var state = store.Load()!;
        var name = new TunnelDefinition(state).Name;
        if (phase == "connect")
        {
            File.WriteAllText(Path.Combine(directory, "name"), name);
            File.WriteAllText(Path.Combine(directory, "profileHash"), Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))));
            Check(await BrokerClient.ExecuteAsync("check", "avt-000000000000000000000000") == TunnelResult.InvalidProfile, "wrong tunnel rejected");
            Check(await BrokerClient.ExecuteAsync("connect", name) == TunnelResult.WaitingForHandshake,
                "standard user starts encrypted LocalSystem tunnel via broker without UAC");
            try { File.ReadAllBytes(Path.Combine(ProtectedTunnelFiles.DirectoryPath, name + ".conf.dpapi")); throw new Exception("User can read machine tunnel"); }
            catch (UnauthorizedAccessException) { Console.WriteLine("PASS: standard user cannot read protected machine configuration"); }
        }
        else if (phase == "after-upgrade")
        {
            Check(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))) == File.ReadAllText(Path.Combine(directory, "profileHash")), "upgrade preserves exact CurrentUser DPAPI profile");
            Check(await BrokerClient.ExecuteAsync("check", name) == TunnelResult.WaitingForHandshake, "broker upgrade preserves active tunnel and caller binding");
            Check(await BrokerClient.ExecuteAsync("disconnect", name) == TunnelResult.Stopped, "standard user disconnects without UAC");
            Check(await BrokerClient.ExecuteAsync("check", name) == TunnelResult.Stopped, "standard user checks stopped state without UAC");
        }
        else throw new ArgumentException();
    }
}
