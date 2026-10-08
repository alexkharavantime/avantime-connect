using System.IO;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
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
    private string? tunnelName;
    private string? vpnIp;
    private bool prodAvailable;

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
            Status.Text = $"Профиль сохранён для {saved.DeviceName}. VPN IP: {saved.Profile.VpnIp}.";
            tunnelName = new TunnelDefinition(saved).Name;
            vpnIp = saved.Profile.VpnIp;
            prodAvailable = saved.Profile.AppType == "desktop" && saved.Profile.RdpHost == "10.40.0.20";
            OpenProd.IsEnabled = prodAvailable;
            RegistrationPanel.Visibility = Visibility.Collapsed;
            TunnelPanel.Visibility = Visibility.Visible;
            DesktopPanel.Visibility = Visibility.Visible;
            DesktopStatus.Text = prodAvailable
                ? "PROD: 10.40.0.20. Сначала подключите VPN, затем откройте рабочий стол."
                : "Открытие PROD доступно для профиля Desktop с сервером 10.40.0.20. Обратитесь к администратору.";
        }
    }

    private async void Tunnel_Click(object sender, RoutedEventArgs e)
    {
        if (busy || tunnelName is null || sender is not System.Windows.Controls.Button button || button.Tag is not string action) return;
        busy = true;
        ConnectVpn.IsEnabled = DisconnectVpn.IsEnabled = CheckVpn.IsEnabled = OpenProd.IsEnabled = false;
        VpnStatus.Text = "Подтвердите запрос прав Windows. Ожидаем результат (до 80 секунд)…";
        try
        {
            var result = await TunnelElevation.ExecuteAsync(action, tunnelName);
            VpnStatus.Text = $"Проверка {DateTime.Now:HH:mm:ss}: " + TunnelElevation.Describe(result);
        }
        catch (ClientException ex) { VpnStatus.Text = ex.Message; }
        catch { VpnStatus.Text = TunnelElevation.Describe(TunnelResult.Failed); }
        finally
        {
            busy = false;
            ConnectVpn.IsEnabled = DisconnectVpn.IsEnabled = CheckVpn.IsEnabled = true;
            OpenProd.IsEnabled = prodAvailable;
        }
    }

    private async void OpenProd_Click(object sender, RoutedEventArgs e)
    {
        if (busy || !prodAvailable || tunnelName is null || vpnIp is null) return;
        busy = true;
        ConnectVpn.IsEnabled = DisconnectVpn.IsEnabled = CheckVpn.IsEnabled = OpenProd.IsEnabled = false;
        DesktopStatus.Text = "Проверяем VPN перед открытием PROD. Подтвердите запрос Windows, если он появится…";
        try
        {
            var result = await TunnelElevation.ExecuteAsync("check", tunnelName);
            VpnStatus.Text = $"Проверка {DateTime.Now:HH:mm:ss}: " + TunnelElevation.Describe(result);
            if (result != TunnelResult.RecentHandshake)
            {
                DesktopStatus.Text = "Рабочий стол не запущен: сначала подключите VPN и дождитесь handshake.";
                return;
            }
            DesktopStatus.Text = "Проверяем доступ к PROD через VPN…";
            using (var probe = new TcpClient(new IPEndPoint(IPAddress.Parse(vpnIp), 0)))
            using (var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8)))
                await probe.ConnectAsync(IPAddress.Parse("10.40.0.20"), 3389, timeout.Token);
            var start = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "mstsc.exe"))
            { UseShellExecute = false };
            start.ArgumentList.Add("/v:10.40.0.20");
            using var process = Process.Start(start) ?? throw new IOException();
            DesktopStatus.Text = "Окно подключения к PROD открыто. Введите учётные данные Windows-сервера в окне удалённого рабочего стола.";
        }
        catch (ClientException ex) { DesktopStatus.Text = ex.Message; }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        { DesktopStatus.Text = "PROD:3389 не отвечает через сохранённый VPN-адрес. Проверьте VPN и повторите."; }
        catch { DesktopStatus.Text = "Не удалось открыть рабочий стол. Проверьте VPN и наличие клиента удалённого рабочего стола Windows."; }
        finally
        {
            busy = false;
            ConnectVpn.IsEnabled = DisconnectVpn.IsEnabled = CheckVpn.IsEnabled = true;
            OpenProd.IsEnabled = prodAvailable;
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
            Status.Text = "Дождитесь завершения текущей операции или закройте запрос прав Windows.";
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
