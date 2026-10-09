using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using AvantimeConnect.Core.Enrollment;
using AvantimeConnect.Core.WireGuard;

namespace AvantimeConnect.App;

internal static class TunnelElevation
{
    internal static string EnrollmentPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "AvantimeConnect", "enrollment.dpapi");

    internal static Task<int> RunHelperAsync(string[] args) => Task.FromResult((int)TunnelResult.Failed);

    internal static async Task<TunnelResult> ExecuteAsync(string action, string tunnelName)
    {
        try { return await AvantimeConnect.Core.Broker.BrokerClient.ExecuteAsync(action, tunnelName); }
        catch (OperationCanceledException)
        { throw new ClientException("Нет подтверждения завершения. Нажмите «Проверить VPN» перед повтором."); }
        catch
        { throw new ClientException("Служба Avantime Connect недоступна. Обратитесь к администратору для восстановления установки. Повторная регистрация не требуется."); }
    }

    internal static string Describe(TunnelResult result) => result switch
    {
        TunnelResult.RecentHandshake => "Служба VPN работает. Есть handshake с сервером за последние 3 минуты. Доступ к рабочему столу проверяется отдельно.",
        TunnelResult.WaitingForHandshake => "Служба VPN работает, но свежего handshake нет. Соединение с сервером не подтверждено. Можно повторить проверку или отключить VPN.",
        TunnelResult.Stopped => "VPN отключён. Регистрация и сохранённый профиль сохранены.",
        TunnelResult.NotInstalled => "Туннель этого профиля ещё не установлен. Нажмите «Подключить VPN».",
        TunnelResult.WrongAccount => "Для этого этапа подтвердите повышение прав той же учётной записи Windows, в которой выполнена регистрация. Ввод другой учётной записи администратора не поддерживается.",
        TunnelResult.InvalidProfile => "Сохранённый профиль не прошёл проверку. Не регистрируйте устройство повторно; обратитесь к администратору.",
        TunnelResult.WireGuardMissing => "Не найден установленный WireGuard для Windows.",
        TunnelResult.OtherTunnelActive => "Уже работает другой туннель WireGuard. Он не изменён. Завершите его подключение, если это допустимо, и повторите.",
        TunnelResult.OwnershipMismatch => "Служба или защищённая конфигурация не совпадает с этим профилем. Дальнейшее управление остановлено. Обратитесь к администратору.",
        TunnelResult.DnsFailed => "Ошибка DNS: не удалось применить правило ad.avantime.lv → 10.40.0.10. Возможен конфликт с политикой DNS. Обратитесь к администратору; чужие правила не изменены.",
        TunnelResult.Busy => "Другая операция VPN ещё выполняется. Дождитесь её завершения и проверьте состояние.",
        _ => "Операция VPN не подтверждена. Туннель мог запуститься. Нажмите «Проверить VPN»; не удаляйте профиль и не регистрируйте компьютер заново."
    };
}
