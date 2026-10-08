using System.Diagnostics;
using System.ServiceProcess;
using AvantimeConnect.Core.Enrollment;
using AvantimeConnect.Core.WireGuard;

internal static class TunnelSmoke
{
    // Opt-in, GitHub-hosted disposable Windows runner ONLY. No backend calls,
    // invitation, production keys or public endpoints are involved.
    internal static async Task RunAsync()
    {
        if (!OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true"
            || Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted")
            throw new InvalidOperationException("Tunnel smoke test is restricted to GitHub-hosted Windows runners.");
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        var pair = await new WireGuardManager().GenerateAsync(timeout.Token);
        var peer = await new WireGuardManager().GenerateAsync(timeout.Token);
        var state = new EnrollmentState
        {
            PrivateKey = pair.PrivateKey, PublicKey = pair.PublicKey,
            Profile = new EnrollmentProfile
            {
                VpnIp = "10.30.0.12", ServerPublicKey = peer.PublicKey, Endpoint = "127.0.0.1:9",
                AllowedIps = "10.40.0.0/24", Keepalive = 25, AppType = "desktop", RdpHost = "10.40.0.20"
            }
        };
        var definition = new TunnelDefinition(state);
        var path = Path.Combine(ProtectedTunnelFiles.DirectoryPath, definition.Name + ".conf.dpapi");
        var controller = new WindowsTunnelController();
        void Check(bool value, string name)
        {
            if (!value) throw new Exception("FAIL: " + name);
            Console.WriteLine("PASS: " + name);
        }
        try
        {
            Check(await controller.ExecuteAsync("check", state, timeout.Token) == TunnelResult.NotInstalled, "fresh identity has no tunnel service");
            Check(await controller.ExecuteAsync("connect", state, timeout.Token) == TunnelResult.WaitingForHandshake,
                "LocalSystem WireGuard reads encrypted profile and starts; absent peer never appears connected");
            var original = File.ReadAllBytes(path);
            using (var service = new ServiceController(definition.ServiceName))
                Check(service.StartType == ServiceStartMode.Manual, "service is manual-start");
            Check(await controller.ExecuteAsync("check", state, timeout.Token) == TunnelResult.WaitingForHandshake, "runtime identity and route checks pass");
            Check(await controller.ExecuteAsync("disconnect", state, timeout.Token) == TunnelResult.Stopped, "only own tunnel stopped");
            Check(await controller.ExecuteAsync("check", state, timeout.Token) == TunnelResult.Stopped, "stopped tunnel correctly reported");
            Check(await controller.ExecuteAsync("connect", state, timeout.Token) == TunnelResult.WaitingForHandshake, "existing protected tunnel restarts without enrollment");
            Check(File.ReadAllBytes(path).SequenceEqual(original), "reconnect preserves encrypted profile bytes");
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(40));
            var stopped = await controller.ExecuteAsync("disconnect", state, cleanup.Token);
            if (stopped == TunnelResult.Stopped)
            {
                ProtectedTunnelFiles.Verify(path, definition);
                var start = new ProcessStartInfo(WindowsTunnelController.WireGuardPath) { UseShellExecute = false, CreateNoWindow = true };
                start.ArgumentList.Add("/uninstalltunnelservice");
                start.ArgumentList.Add(definition.Name);
                using var uninstall = Process.Start(start)!;
                await uninstall.WaitForExitAsync(cleanup.Token);
                if (uninstall.ExitCode != 0) throw new Exception("Smoke tunnel cleanup failed.");
                File.Delete(path);
                Console.WriteLine("PASS: disposable CI tunnel removed");
            }
        }
    }
}
