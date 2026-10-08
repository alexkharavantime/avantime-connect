using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using AvantimeConnect.Core.WireGuard;

namespace AvantimeConnect.Core.Enrollment;

// Do not add secret-bearing ToString() implementations to these classes.
public sealed class EnrollmentState
{
    public int Version { get; set; } = 1;
    public string ApiOrigin { get; set; } = "";
    public string Token { get; set; } = "";
    public string DeviceName { get; set; } = "";
    public string PrivateKey { get; set; } = "";
    public string PublicKey { get; set; } = "";
    public EnrollmentProfile? Profile { get; set; }
}

public sealed class EnrollmentProfile
{
    [JsonPropertyName("vpn_ip")] public string VpnIp { get; set; } = "";
    [JsonPropertyName("server_public_key")] public string ServerPublicKey { get; set; } = "";
    [JsonPropertyName("endpoint")] public string Endpoint { get; set; } = "";
    [JsonPropertyName("allowed_ips")] public string AllowedIps { get; set; } = "";
    [JsonPropertyName("keepalive")] public int Keepalive { get; set; }
    [JsonPropertyName("app_type")] public string AppType { get; set; } = "";
    [JsonPropertyName("rdp_host")] public string RdpHost { get; set; } = "";
}

public interface IEnrollmentStore
{
    EnrollmentState? Load();
    void Save(EnrollmentState state);
}

public interface IKeyGenerator
{
    Task<(string PrivateKey, string PublicKey)> GenerateAsync(CancellationToken cancellationToken);
}

public sealed class ClientException(string message) : Exception(message);

public sealed class EnrollmentService(HttpClient http, IEnrollmentStore store, IKeyGenerator keys)
{
    private readonly SemaphoreSlim gate = new(1, 1);

    public static HttpClient CreateHttpClient() => new(new HttpClientHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        UseProxy = false
    }) { Timeout = TimeSpan.FromSeconds(90) };

    public static string ValidateOrigin(string input)
    {
        if (!Uri.TryCreate(input.Trim(), UriKind.Absolute, out var uri)
            || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0
            || uri.AbsolutePath != "/"
            || (uri.Scheme != "https" && !(uri.Scheme == "http" &&
                 (uri.Host == "127.0.0.1" || uri.Host == "[::1]"))))
            throw new ClientException("Укажите HTTPS-адрес сервера без пути. HTTP допустим только для локального SSH-туннеля 127.0.0.1.");
        return uri.GetLeftPart(UriPartial.Authority);
    }

    public async Task<EnrollmentState> EnrollAsync(string origin, string token, string deviceName,
        CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            origin = ValidateOrigin(origin);
            token = token.Trim();
            deviceName = deviceName.Trim();
            if (token.Length is < 1 or > 4096 || token.Any(char.IsControl)
                || deviceName.Length is < 1 or > 128 || deviceName.Any(char.IsControl))
                throw new ClientException("Введите приглашение и имя устройства (до 128 символов).");
            var state = store.Load();
            if (state is not null)
            {
                if (state.Version != 1 || state.ApiOrigin != origin || state.Token != token || state.DeviceName != deviceName)
                    throw new ClientException("Уже сохранена регистрация с другими данными. Продолжите её; замену устройства должен согласовать администратор.");
                WireGuardManager.ValidateKey(state.PrivateKey);
                WireGuardManager.ValidateKey(state.PublicKey);
                if (state.Profile is not null)
                {
                    WireGuardManager.ValidateProfile(state.Profile);
                    return state;
                }
            }
            else
            {
                var pair = await keys.GenerateAsync(cancellationToken);
                WireGuardManager.ValidateKey(pair.PrivateKey);
                WireGuardManager.ValidateKey(pair.PublicKey);
                state = new EnrollmentState
                {
                    ApiOrigin = origin, Token = token, DeviceName = deviceName,
                    PrivateKey = pair.PrivateKey, PublicKey = pair.PublicKey
                };
                store.Save(state); // Must succeed BEFORE any network operation.
            }
            using var request = new HttpRequestMessage(HttpMethod.Post, origin + "/api/enroll/")
            {
                Content = JsonContent.Create(new { token = state.Token, public_key = state.PublicKey, device_name = state.DeviceName })
            };
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(90));
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if ((int)response.StatusCode != 200)
                throw new ClientException((int)response.StatusCode switch
                {
                    404 => "Приглашение не найдено. Проверьте его с администратором.",
                    409 => "Регистрация занята либо приглашение связано с устройством. Повторите позже или обратитесь к администратору. Ключи сохранены.",
                    410 => "Приглашение истекло или устройство отозвано. Обратитесь к администратору.",
                    502 or 503 => "Сервер не подтвердил регистрацию. Устройство могло быть создано. Повторите с сохранёнными ключами.",
                    401 or 403 => "Сервер отклонил запрос регистрации. Проверьте адрес с администратором.",
                    >= 300 and < 400 => "Сервер перенаправляет запрос. Укажите конечный адрес; приглашение не пересылалось.",
                    _ => $"Сервер вернул HTTP {(int)response.StatusCode}. Данные повторной попытки сохранены."
                });
            using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
            var bytes = new byte[16385];
            var count = 0;
            while (count < bytes.Length)
            {
                int read = await stream.ReadAsync(bytes.AsMemory(count), timeout.Token);
                if (read == 0) break;
                count += read;
            }
            if (count > 16384) throw new ClientException("Ответ сервера слишком велик. Обратитесь к администратору.");
            var profile = JsonSerializer.Deserialize<EnrollmentProfile>(bytes.AsSpan(0, count))
                ?? throw new ClientException("Сервер вернул пустой профиль.");
            WireGuardManager.ValidateProfile(profile);
            state.Profile = profile;
            store.Save(state);
            return state;
        }
        catch (HttpRequestException)
        {
            throw new ClientException("Нет подтверждения от сервера. Проверьте соединение или SSH-туннель и повторите. Сохранённые ключи будут использованы снова.");
        }
        catch (OperationCanceledException)
        {
            throw new ClientException("Ожидание прервано. Результат регистрации неизвестен; повторите с сохранёнными ключами.");
        }
        catch (JsonException)
        {
            throw new ClientException("Не удалось прочитать профиль сервера. Данные регистрации сохранены; обратитесь к администратору.");
        }
        finally { gate.Release(); }
    }
}
