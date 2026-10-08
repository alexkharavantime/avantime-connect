using System.IO;
using System.Net.Http;
using System.Windows;
using AvantimeConnect.Core.Enrollment;
using AvantimeConnect.Core.WireGuard;

namespace AvantimeConnect.App;

public partial class MainWindow : Window
{
    private readonly HttpClient http = EnrollmentService.CreateHttpClient();
    private readonly CancellationTokenSource lifetime = new();
    private readonly ProtectedEnrollmentStore store;
    private readonly EnrollmentService service;
    private readonly string directory;
    private FileStream? writerLock;
    private bool busy;

    public MainWindow()
    {
        InitializeComponent();
        directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AvantimeConnect");
        store = new ProtectedEnrollmentStore(Path.Combine(directory, "enrollment.dpapi"));
        service = new EnrollmentService(http, store, new WireGuardManager());
        DeviceName.Text = Environment.MachineName;
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            Directory.CreateDirectory(directory);
            writerLock = new FileStream(Path.Combine(directory, "enrollment.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            RestoreState();
        }
        catch
        {
            Register.IsEnabled = false;
            Status.Text = "Не удалось открыть сохранённую регистрацию. Возможно, клиент уже запущен в другом сеансе или файл недоступен. Не удаляйте его; обратитесь к администратору.";
        }
    }

    private void RestoreState()
    {
        var saved = store.Load();
        if (saved is null) return;
        EnrollmentService.ValidateOrigin(saved.ApiOrigin);
        WireGuardManager.ValidateKey(saved.PrivateKey);
        WireGuardManager.ValidateKey(saved.PublicKey);
        ApiOrigin.Text = saved.ApiOrigin;
        DeviceName.Text = saved.DeviceName;
        Invitation.Password = saved.Token;
        ApiOrigin.IsEnabled = DeviceName.IsEnabled = Invitation.IsEnabled = false;
        if (saved.Profile is null)
        {
            Register.Content = "Повторить регистрацию";
            Status.Text = "Данные предыдущей попытки восстановлены. Повтор будет использовать прежние ключи и приглашение.";
        }
        else
        {
            WireGuardManager.ValidateProfile(saved.Profile);
            Register.IsEnabled = false;
            Invitation.Clear();
            Status.Text = $"Профиль сохранён для {saved.DeviceName}. VPN IP: {saved.Profile.VpnIp}. Туннель ещё не подключён. Текущий статус устройства на сервере этим не проверяется.";
        }
    }

    private async void Register_Click(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        busy = true;
        Register.IsEnabled = ApiOrigin.IsEnabled = DeviceName.IsEnabled = Invitation.IsEnabled = false;
        Status.Text = "Сохраняем ключи и ожидаем подтверждение сервера…";
        string? error = null;
        try { await service.EnrollAsync(ApiOrigin.Text, Invitation.Password, DeviceName.Text, lifetime.Token); }
        catch (ClientException ex) { error = ex.Message; }
        catch { error = "Не удалось завершить регистрацию или сохранить её результат. Не удаляйте локальные данные; обратитесь к администратору."; }
        finally { busy = false; }
        Register.IsEnabled = ApiOrigin.IsEnabled = DeviceName.IsEnabled = Invitation.IsEnabled = true;
        try
        {
            RestoreState();
            if (error is not null) Status.Text = error;
        }
        catch
        {
            Register.IsEnabled = false;
            Status.Text = "Сохранённые данные недоступны. Повтор остановлен, чтобы не создать другое устройство. Обратитесь к администратору.";
        }
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        if (busy)
        {
            e.Cancel = true;
            Status.Text = "Дождитесь завершения запроса (до 90 секунд). Повтор использует те же ключи.";
        }
        base.OnClosing(e);
    }
    protected override void OnClosed(EventArgs e)
    {
        lifetime.Cancel();
        lifetime.Dispose();
        http.Dispose();
        writerLock?.Dispose();
        base.OnClosed(e);
    }
}
