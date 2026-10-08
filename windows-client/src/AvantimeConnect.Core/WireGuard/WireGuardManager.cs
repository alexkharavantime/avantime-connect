using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using AvantimeConnect.Core.Enrollment;

namespace AvantimeConnect.Core.WireGuard;

public sealed class WireGuardManager : IKeyGenerator
{
    public static string WgPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WireGuard", "wg.exe");
    public async Task<(string PrivateKey, string PublicKey)> GenerateAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(WgPath)) throw new ClientException("Установите WireGuard для Windows перед регистрацией.");
        var secret = await RunAsync("genkey", null, cancellationToken);
        ValidateKey(secret);
        var publicKey = await RunAsync("pubkey", secret, cancellationToken);
        ValidateKey(publicKey);
        return (secret, publicKey);
    }

    private static async Task<string> RunAsync(string command, string? input, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        using var process = new Process { StartInfo = new ProcessStartInfo(WgPath, command)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        }};
        process.Start();
        try
        {
            var output = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var error = process.StandardError.ReadToEndAsync(timeout.Token);
            if (input is not null) await process.StandardInput.WriteLineAsync(input.AsMemory(), timeout.Token);
            process.StandardInput.Close();
            await process.WaitForExitAsync(timeout.Token);
            await error; // Never expose process stderr or key output in diagnostics.
            var result = await output;
            if (process.ExitCode != 0) throw new ClientException("WireGuard не смог создать ключи.");
            return result.Trim();
        }
        finally { if (!process.HasExited) process.Kill(entireProcessTree: true); }
    }

    public static void ValidateKey(string value)
    {
        if (value is null || value.Length != 44) throw new ClientException("Некорректный ключ WireGuard.");
        try
        {
            var bytes = Convert.FromBase64String(value);
            if (bytes.Length != 32 || bytes.All(b => b == 0) || Convert.ToBase64String(bytes) != value)
                throw new ClientException("Некорректный ключ WireGuard.");
        }
        catch (FormatException) { throw new ClientException("Некорректный ключ WireGuard."); }
    }

    public static void ValidateProfile(EnrollmentProfile profile)
    {
        ValidateKey(profile.ServerPublicKey);
        if (!IPAddress.TryParse(profile.VpnIp, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork
            || ip.ToString() != profile.VpnIp || ip.Equals(IPAddress.Any) || IPAddress.IsLoopback(ip))
            throw new ClientException("Сервер вернул некорректный VPN-адрес.");
        if (profile.Keepalive is < 0 or > 65535
            || profile.AppType is not ("desktop" or "remoteapp32" or "remoteapp64")
            || string.IsNullOrEmpty(profile.RdpHost) || Uri.CheckHostName(profile.RdpHost) == UriHostNameType.Unknown)
            throw new ClientException("Сервер вернул некорректные параметры профиля.");
        if (string.IsNullOrEmpty(profile.Endpoint) || profile.Endpoint.Any(char.IsWhiteSpace)
            || !Uri.TryCreate("udp://" + profile.Endpoint, UriKind.Absolute, out var endpoint)
            || endpoint.UserInfo.Length != 0 || endpoint.AbsolutePath != "/"
            || endpoint.Query.Length != 0 || endpoint.Fragment.Length != 0
            || endpoint.Port is < 1 or > 65535 || Uri.CheckHostName(endpoint.Host) == UriHostNameType.Unknown)
            throw new ClientException("Сервер вернул некорректный адрес WireGuard.");
        if (string.IsNullOrEmpty(profile.AllowedIps) || profile.AllowedIps.Any(char.IsControl))
            throw new ClientException("Сервер вернул некорректные VPN-маршруты.");
        foreach (var cidr in profile.AllowedIps.Split(','))
        {
            var parts = cidr.Trim().Split('/');
            if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var network)
                || network.ToString() != parts[0] || !int.TryParse(parts[1], out int prefix)
                || prefix <= 0 || prefix > (network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128))
                throw new ClientException("Ожидаются VPN-маршруты с явной маской, без маршрута по умолчанию.");
        }
    }
}
