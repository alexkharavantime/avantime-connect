using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using AvantimeConnect.Core.Enrollment;

namespace AvantimeConnect.Core.WireGuard;

// Contains a private key. Do not log, serialize for diagnostics, or make this a record.
public sealed class TunnelDefinition
{
    public string Name { get; }
    public string ServiceName => "WireGuardTunnel$" + Name;
    public string PublicKey { get; }
    public string ServerPublicKey { get; }
    public string Configuration { get; }
    public string AllowedIps { get; }
    public static readonly string[] SupportedRoutes = ["10.40.0.0/24", "10.20.0.20/32", "10.20.0.20/32, 10.40.0.10/32", "10.20.0.20/32, 10.40.0.0/24"];
    public static string[] Environments(EnrollmentProfile profile)
    {
        var envs = profile.Environments ?? ["prod"];
        if (envs.Length is < 1 or > 2 || envs.Distinct().Count() != envs.Length
            || envs.Any(e => e is not ("prod" or "dev"))) throw new ClientException("Некорректный список разрешённых серверов.");
        var expected = string.Join(", ", envs.OrderBy(e => e).Select(e => e == "dev" ? "10.20.0.20/32" : "10.40.0.0/24"));
        var routesMatch = profile.AllowedIps.Trim() == expected
            || (envs.Length == 1 && envs[0] == "dev" && profile.AllowedIps.Trim() == "10.20.0.20/32, 10.40.0.10/32");
        if (!routesMatch || profile.AccessRevision < 0
            || profile.RdpHost != (envs.Contains("prod") ? "10.40.0.20" : "10.20.0.20"))
            throw new ClientException("Маршруты не соответствуют разрешённым серверам.");
        return envs;
    }

    public TunnelDefinition(EnrollmentState state)
    {
        if (state.Version != 1 || state.Profile is null) throw new ClientException("Сначала завершите регистрацию.");
        WireGuardManager.ValidateKey(state.PrivateKey);
        WireGuardManager.ValidateKey(state.PublicKey);
        var profile = state.Profile;
        WireGuardManager.ValidateProfile(profile);
        var environments = Environments(profile);
        // Migrate legacy DEV routes in the protected tunnel without changing enrollment identity.
        AllowedIps = environments.Length == 1 && environments[0] == "dev"
            ? "10.20.0.20/32, 10.40.0.10/32" : profile.AllowedIps.Trim();
        var octets = profile.VpnIp.Split('.');
        if (octets[0] != "10" || octets[1] != "30" || octets[2] != "0"
            || int.Parse(octets[3], CultureInfo.InvariantCulture) is < 2 or >= 240
            || profile.Keepalive != 25)
            throw new ClientException("Профиль VPN не соответствует разрешённому диапазону адресов или keepalive 25.");
        PublicKey = state.PublicKey;
        ServerPublicKey = profile.ServerPublicKey;
        Name = "avt-" + Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(PublicKey)))[..24].ToLowerInvariant();
        Configuration = "[Interface]\nPrivateKey = " + state.PrivateKey
            + "\nAddress = " + profile.VpnIp + "/32\n\n[Peer]\nPublicKey = " + ServerPublicKey
            + "\nEndpoint = " + profile.Endpoint
            + "\nAllowedIPs = " + AllowedIps + "\nPersistentKeepalive = 25\n";
    }

    public static bool HasRecentHandshake(string output, string expectedPeer, DateTimeOffset now)
    {
        var fields = output.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        return fields.Length == 2 && fields[0] == expectedPeer
            && long.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
            && seconds > 0 && seconds <= now.ToUnixTimeSeconds()
            && now.ToUnixTimeSeconds() - seconds <= 180;
    }
}

// Helper process exit codes contain no secrets and no server-supplied messages.
public enum TunnelResult
{
    RecentHandshake = 10,
    WaitingForHandshake = 11,
    Stopped = 12,
    NotInstalled = 13,
    WrongAccount = 20,
    InvalidProfile = 21,
    WireGuardMissing = 22,
    OtherTunnelActive = 23,
    OwnershipMismatch = 24,
    Busy = 25,
    Failed = 26,
    DnsFailed = 27
}
