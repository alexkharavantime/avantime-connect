using System.Net;
using System.Net.Sockets;
using System.Text;
using AvantimeConnect.Core.Enrollment;

namespace AvantimeConnect.Core.Rdp;

/// <summary>Preflight for administrator-published PROD files; never rewrites signed RDP content.</summary>
public static class RemoteAppPreflight
{
    public const string Host = "WIN-APP-PROD.AD.AVANTIME.LV";
    public const string Address = "10.40.0.20";
    public const int MaximumFileBytes = 1024 * 1024;

    public static bool IsAvailable(string appType, IEnumerable<string> environments) =>
        appType is ("desktop" or "remoteapp32" or "remoteapp64") && environments.Contains("prod");

    public static void ValidateFile(byte[] bytes)
    {
        if (bytes.Length == 0 || bytes.Length > MaximumFileBytes)
            throw new ClientException("RemoteApp: файл пустой или слишком большой.");
        string text;
        try
        {
            var offset = 0;
            Encoding encoding = new UTF8Encoding(false, true);
            if (bytes.Length >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe)
            { encoding = new UnicodeEncoding(false, true, true); offset = 2; }
            else if (bytes.Length >= 2 && bytes[0] == 0xfe && bytes[1] == 0xff)
            { encoding = new UnicodeEncoding(true, true, true); offset = 2; }
            else if (bytes.Length >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf) offset = 3;
            text = encoding.GetString(bytes, offset, bytes.Length - offset);
        }
        catch (DecoderFallbackException)
        { throw new ClientException("RemoteApp: используйте опубликованный файл RDP в UTF-8 или UTF-16 с BOM."); }
        if (text.Contains('\0')) throw new ClientException("RemoteApp: некорректная кодировка файла.");
        var entries = new Dictionary<string, (string Type, string Value)>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0) continue;
            var parts = trimmed.Split(':', 3);
            if (parts.Length != 3 || !entries.TryAdd(parts[0].Trim(), (parts[1], parts[2].Trim())))
                throw new ClientException("RemoteApp: некорректные или повторяющиеся параметры RDP.");
        }
        string Get(string key, string type)
        {
            if (!entries.TryGetValue(key, out var entry)) return "";
            if (entry.Type != type) throw new ClientException("RemoteApp: неверный тип параметра RDP.");
            return entry.Value;
        }
        bool IsHost(string value) => value.Equals(Host, StringComparison.OrdinalIgnoreCase) ||
            value.Equals(Host + ":3389", StringComparison.OrdinalIgnoreCase);
        if (!IsHost(Get("full address", "s")) || Get("remoteapplicationmode", "i") != "1" ||
            string.IsNullOrWhiteSpace(Get("remoteapplicationprogram", "s")))
            throw new ClientException("RemoteApp: выберите опубликованный файл приложения для " + Host + ".");
        var alternate = Get("alternate full address", "s");
        var gatewayUsage = Get("gatewayusagemethod", "i");
        if (gatewayUsage is not ("" or "0" or "4"))
            throw new ClientException("RemoteApp: файл должен явно использовать прямое подключение без шлюза.");
        if ((alternate.Length > 0 && !IsHost(alternate)) || Get("gatewayhostname", "s").Length > 0 ||
            Get("loadbalanceinfo", "s").Length > 0 ||
            (Get("server port", "i") is var port && port.Length > 0 && port != "3389"))
            throw new ClientException("RemoteApp: этот файл использует другой сервер, шлюз или порт. Требуется прямое подключение к PROD:3389.");
        if (Get("authentication level", "i") == "0" || Get("enablecredsspsupport", "i") == "0")
            throw new ClientException("RemoteApp: файл отключает проверку подлинности сервера. Получите корректный файл у администратора.");
    }

    public static async Task CheckAsync(string vpnIp, CancellationToken cancellationToken,
        Func<string, CancellationToken, Task<IPAddress[]>>? resolve = null,
        Func<IPAddress, IPAddress, CancellationToken, Task>? connect = null)
    {
        IPAddress[] addresses;
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(8));
            try { addresses = await (resolve ?? ResolveAsync)(Host, timeout.Token); }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            { throw new ClientException("DNS: не удалось определить " + Host + ". Переподключите VPN или обратитесь к администратору."); }
        }
        var expected = IPAddress.Parse(Address);
        if (addresses.Length == 0 || addresses.Any(address => !address.Equals(expected)))
            throw new ClientException("DNS: имя PROD не разрешается в ожидаемый адрес " + Address + ". Обратитесь к администратору.");
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(8));
            try { await (connect ?? ConnectAsync)(IPAddress.Parse(vpnIp), expected, timeout.Token); }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            { throw new ClientException("RDP: имя определено, но PROD:3389 недоступен через VPN. Проверьте права доступа и доступность сервера."); }
        }
    }
    private static Task<IPAddress[]> ResolveAsync(string host, CancellationToken token) => Dns.GetHostAddressesAsync(host, token);
    private static async Task ConnectAsync(IPAddress source, IPAddress destination, CancellationToken token)
    {
        using var client = new TcpClient(new IPEndPoint(source, 0));
        await client.ConnectAsync(destination, 3389, token);
    }
}
