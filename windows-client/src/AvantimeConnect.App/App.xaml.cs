using System.Windows;

namespace AvantimeConnect.App;

public partial class App : Application
{
    private Mutex? instance;
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        if (e.Args.Length > 0)
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            Shutdown(await TunnelElevation.RunHelperAsync(e.Args));
            return;
        }
        // One writer per Windows user/session. A file lock also protects cross-session access.
        instance = new Mutex(true, @"Local\AvantimeConnect.Enrollment", out bool first);
        if (!first)
        {
            MessageBox.Show("Avantime Connect уже запущен.", "Avantime Connect");
            Shutdown();
            return;
        }
        new MainWindow().Show();
    }
    protected override void OnExit(ExitEventArgs e)
    {
        instance?.Dispose();
        base.OnExit(e);
    }
}
