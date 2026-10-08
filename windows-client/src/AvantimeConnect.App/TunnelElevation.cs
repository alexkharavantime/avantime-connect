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

    internal static async Task<int> RunHelperAsync(string[] args)
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (args.Length != 4 || args[0] != "--tunnel-helper"
                || args[1] is not ("connect" or "disconnect" or "check")) return (int)TunnelResult.Failed;
            // CurrentUser DPAPI must not be read under an alternate administrator's
            // account. No enrollment paths, tokens or keys are accepted as arguments.
            if (identity.User?.Value != args[2] || !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                return (int)TunnelResult.WrongAccount;
            var state = new ProtectedEnrollmentStore(EnrollmentPath).Load();
            if (state is null || new TunnelDefinition(state).Name != args[3]) return (int)TunnelResult.InvalidProfile;
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(80));
            return (int)await new WindowsTunnelController().ExecuteAsync(args[1], state, timeout.Token);
        }
        catch (ClientException) { return (int)TunnelResult.InvalidProfile; }
        catch { return (int)TunnelResult.Failed; }
    }

    internal static async Task<TunnelResult> ExecuteAsync(string action, string tunnelName)
    {
        var executable = Path.ChangeExtension(typeof(TunnelElevation).Assembly.Location, ".exe");
        if (!File.Exists(executable)) throw new ClientException("Не найден Windows apphost. Соберите приложение заново.");
        using var identity = WindowsIdentity.GetCurrent();
        var start = new ProcessStartInfo(executable) { UseShellExecute = true, Verb = "runas", WorkingDirectory = Path.GetDirectoryName(executable)! };
        foreach (var value in new[] { "--tunnel-helper", action, identity.User!.Value, tunnelName }) start.ArgumentList.Add(value);
        try
        {
            // ShellExecute/UAC may wait for the user. Keep the WPF dispatcher responsive.
            using var process = await Task.Run(() => Process.Start(start)) ?? throw new IOException();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(100));
            await process.WaitForExitAsync(timeout.Token);
            return Enum.IsDefined(typeof(TunnelResult), process.ExitCode) ? (TunnelResult)process.ExitCode : TunnelResult.Failed;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        { throw new ClientException("Запрос прав Windows отменён. Команда управления VPN не выполнялась."); }
        catch (OperationCanceledException)
        { throw new ClientException("Нет подтверждения завершения. VPN мог включиться. Нажмите «Проверить VPN» перед повтором."); }
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
        TunnelResult.Busy => "Другая операция VPN ещё выполняется. Дождитесь её завершения и проверьте состояние.",
        _ => "Операция VPN не подтверждена. Туннель мог запуститься. Нажмите «Проверить VPN»; не удаляйте профиль и не регистрируйте компьютер заново."
    };
}
