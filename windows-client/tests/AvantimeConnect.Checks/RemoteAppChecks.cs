using System.Net;
using System.Net.Sockets;
using System.Text;
using AvantimeConnect.Core.Enrollment;
using AvantimeConnect.Core.Rdp;

internal static class RemoteAppChecks
{
    public static async Task RunAsync()
    {
        const string valid = "full address:s:WIN-APP-PROD.AD.AVANTIME.LV\r\nremoteapplicationmode:i:1\r\nremoteapplicationprogram:s:||1C\r\nauthentication level:i:2\r\nsignature:s:unchanged\r\n";
        void Accept(byte[] content)
        {
            var original = content.ToArray();
            RemoteAppPreflight.ValidateFile(content);
            if (!original.SequenceEqual(content)) throw new Exception("RDP bytes changed");
        }
        foreach (var appType in new[] { "desktop", "remoteapp32", "remoteapp64" })
        {
            if (!RemoteAppPreflight.IsAvailable(appType, new[] { "prod" }) ||
                RemoteAppPreflight.IsAvailable(appType, new[] { "dev" }))
                throw new Exception("RemoteApp access gate incorrect");
        }
        if (RemoteAppPreflight.IsAvailable("unknown", new[] { "prod" }))
            throw new Exception("Unsupported app type enabled");
        Accept(Encoding.UTF8.GetBytes(valid));
        Accept(Encoding.UTF8.GetBytes(valid + "gatewayusagemethod:i:0\n"));
        Accept(Encoding.UTF8.GetBytes(valid + "gatewayusagemethod:i:4\n"));
        Accept(Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes(valid)).ToArray());
        foreach (var bad in new[] {
            valid + "full address:s:evil.example\n",
            valid.Replace("WIN-APP-PROD.AD.AVANTIME.LV", "10.40.0.20"),
            valid.Replace("mode:i:1", "mode:i:0"),
            valid.Replace("authentication level:i:2", "authentication level:i:0"),
            valid + "alternate full address:s:evil.example\n",
            valid + "gatewayhostname:s:gateway.example\n",
            valid + "gatewayusagemethod:i:1\n",
            valid + "gatewayusagemethod:i:2\n",
            valid + "gatewayusagemethod:i:3\n",
            valid + "loadbalanceinfo:s:redirect\n",
            valid + "server port:i:3390\n",
            valid + "enablecredsspsupport:i:0\n" })
        {
            try { RemoteAppPreflight.ValidateFile(Encoding.UTF8.GetBytes(bad)); }
            catch (ClientException) { continue; }
            throw new Exception("Unsafe RDP accepted");
        }
        var connected = false;
        await RemoteAppPreflight.CheckAsync("10.30.0.15", CancellationToken.None,
            (host, _) => host == RemoteAppPreflight.Host
                ? Task.FromResult(new[] { IPAddress.Parse(RemoteAppPreflight.Address) })
                : throw new Exception("Wrong DNS hostname"),
            (source, target, _) => {
                if (source.ToString() != "10.30.0.15" || target.ToString() != "10.40.0.20")
                    throw new Exception("Wrong RDP route");
                connected = true;
                return Task.CompletedTask;
            });
        if (!connected) throw new Exception("RDP preflight skipped");
        async Task ExpectError(string prefix, Func<string, CancellationToken, Task<IPAddress[]>> resolve,
            Func<IPAddress, IPAddress, CancellationToken, Task>? connect = null)
        {
            try { await RemoteAppPreflight.CheckAsync("10.30.0.15", CancellationToken.None, resolve,
                connect ?? ((_, _, _) => throw new Exception("Unexpected TCP probe"))); }
            catch (ClientException ex) when (ex.Message.StartsWith(prefix, StringComparison.Ordinal)) { return; }
            throw new Exception("Missing " + prefix + " error");
        }
        await ExpectError("DNS:", (_, _) => throw new SocketException());
        await ExpectError("DNS:", (_, _) => Task.FromResult(Array.Empty<IPAddress>()));
        await ExpectError("DNS:", (_, _) => Task.FromResult(new[] { IPAddress.Loopback }));
        await ExpectError("DNS:", (_, _) => Task.FromResult(new[] { IPAddress.Parse(RemoteAppPreflight.Address), IPAddress.Loopback }));
        await ExpectError("RDP:", (_, _) => Task.FromResult(new[] { IPAddress.Parse(RemoteAppPreflight.Address) }),
            (_, _, _) => throw new SocketException());
        Console.WriteLine("PASS: RemoteApp encoding, immutable bytes, destination/auth validation and distinct DNS/RDP preflight checks");
    }
}
