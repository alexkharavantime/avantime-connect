using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Security.Cryptography;
using AvantimeConnect.Core.Broker;
using Microsoft.Win32;
using AvantimeConnect.Core.Enrollment;

namespace AvantimeConnect.Core.WireGuard;

public sealed class WindowsTunnelController
{
    public static string WireGuardPath => Path.Combine(Path.GetDirectoryName(WireGuardManager.WgPath)!, "wireguard.exe");

    // Called only by the short-lived elevated helper. No server calls, key rotation,
    // arbitrary file paths, shell commands, config hooks, or broad service operations.
    public async Task<TunnelResult> ExecuteAsync(string action, EnrollmentState state, CancellationToken cancellationToken)
    {
        if (action is not ("connect" or "disconnect" or "check")) return TunnelResult.Failed;
        var definition = new TunnelDefinition(state);
        if (!File.Exists(WireGuardPath) || !File.Exists(WireGuardManager.WgPath)) return TunnelResult.WireGuardMissing;
        if (await WireGuardManager.DerivePublicKeyAsync(state.PrivateKey, cancellationToken) != definition.PublicKey)
            return TunnelResult.InvalidProfile;

        var directory = ProtectedTunnelFiles.DirectoryPath;
        ProtectedTunnelFiles.EnsureDirectory(directory);
        FileStream? operationLock = null;
        var lockWait = Stopwatch.StartNew();
        // Briefly yield to the background DNS reconciliation rather than making a
        // normal button click fail immediately. Still bound competing operations.
        while (operationLock is null)
        {
            try { operationLock = new FileStream(Path.Combine(directory, "operation.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException)
            {
                if (lockWait.Elapsed >= TimeSpan.FromSeconds(3)) return TunnelResult.Busy;
                await Task.Delay(150, cancellationToken);
            }
        }
        using (operationLock)
        {
            var path = Path.Combine(directory, definition.Name + ".conf.dpapi");
            bool updateRoutes = false;
            bool installed = ServiceExists(definition.ServiceName);
            try
            {
                if (File.Exists(path))
                {
                    ProtectedTunnelFiles.VerifyIdentity(path, definition);
                    try { ProtectedTunnelFiles.Verify(path, definition); }
                    catch (InvalidDataException) { updateRoutes = true; }
                }
                else if (installed) return TunnelResult.OwnershipMismatch;
                if (installed) VerifyService(definition.ServiceName, path);
            }
            catch { return TunnelResult.OwnershipMismatch; }

            if (action != "connect" && !installed)
            {
                await ReconcileDnsCoreAsync(cancellationToken);
                return TunnelResult.NotInstalled;
            }
            try
            {
                if (action == "connect")
                {
                    if (OtherTunnelActive(definition.ServiceName)) return TunnelResult.OtherTunnelActive;
                    if (updateRoutes)
                    {
                        if (installed)
                        {
                            using var oldService = new ServiceController(definition.ServiceName);
                            if (oldService.Status != ServiceControllerStatus.Stopped)
                            {
                                oldService.Stop();
                                await WaitAsync(oldService, ServiceControllerStatus.Stopped, cancellationToken);
                            }
                        }
                        ProtectedTunnelFiles.Create(path, definition, replaceRoutes: true);
                    }
                    if (!File.Exists(path)) ProtectedTunnelFiles.Create(path, definition);
                    if (!installed)
                    {
                        // Only install when absent: WireGuard's installer can replace an
                        // existing stopped service, which we intentionally never permit.
                        try { await RunAsync(WireGuardPath, ["/installtunnelservice", path], cancellationToken); }
                        finally
                        {
                            // An installer can fail after creating its auto-start service.
                            // Recover that partial outcome without touching foreign services.
                            if (ServiceExists(definition.ServiceName))
                            {
                                VerifyService(definition.ServiceName, path);
                                SetManualStart(definition.ServiceName);
                            }
                        }
                    }
                }

                using var service = new ServiceController(definition.ServiceName);
                if (action != "check") SetManualStart(definition.ServiceName);
                if (action == "disconnect")
                {
                    if (service.Status != ServiceControllerStatus.Stopped)
                    {
                        service.Stop();
                        await WaitAsync(service, ServiceControllerStatus.Stopped, cancellationToken);
                    }
                    await ReconcileDnsCoreAsync(cancellationToken);
                    return TunnelResult.Stopped;
                }
                if (service.Status == ServiceControllerStatus.Stopped)
                {
                    if (action == "check")
                    {
                        await ReconcileDnsCoreAsync(cancellationToken);
                        return TunnelResult.Stopped;
                    }
                    service.Start();
                }
                await WaitAsync(service, ServiceControllerStatus.Running, cancellationToken);

                // Query only non-secret fields. Never use `showconf` or `show ... dump`.
                if (await WgAsync(definition.Name, "public-key", cancellationToken) != definition.PublicKey
                    || await WgAsync(definition.Name, "peers", cancellationToken) != definition.ServerPublicKey)
                    return TunnelResult.OwnershipMismatch;
                var routes = (await WgAsync(definition.Name, "allowed-ips", cancellationToken))
                    .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (routes.Length < 2 || routes[0] != definition.ServerPublicKey
                    || !routes.Skip(1).OrderBy(r => r).SequenceEqual(definition.AllowedIps.Split(", ").OrderBy(r => r)))
                    return TunnelResult.OwnershipMismatch;

                var wait = Stopwatch.StartNew();
                do
                {
                    var handshakes = await WgAsync(definition.Name, "latest-handshakes", cancellationToken);
                    if (TunnelDefinition.HasRecentHandshake(handshakes, definition.ServerPublicKey, DateTimeOffset.UtcNow))
                    {
                        try { await SplitDnsManager.ApplyAsync(true, cancellationToken); }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                        catch
                        {
                            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(22));
                            try { await SplitDnsManager.ApplyAsync(false, cleanup.Token); } catch { }
                            return TunnelResult.DnsFailed;
                        }
                        return TunnelResult.RecentHandshake;
                    }
                    if (action == "check" || wait.Elapsed >= TimeSpan.FromSeconds(35)) break;
                    await Task.Delay(2000, cancellationToken);
                } while (true);
                await ReconcileDnsCoreAsync(cancellationToken);
                return TunnelResult.WaitingForHandshake;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(22));
                try { await ReconcileDnsCoreAsync(cleanup.Token); } catch { }
                throw;
            }
        }
    }

    // Startup and periodic repair use only protected machine metadata and non-secret
    // WireGuard runtime fields. User DPAPI profiles are never read as SYSTEM here.
    public static async Task ReconcileDnsAsync(CancellationToken token)
    {
        ProtectedTunnelFiles.EnsureDirectory(ProtectedTunnelFiles.DirectoryPath);
        FileStream operationLock;
        try { operationLock = new FileStream(Path.Combine(ProtectedTunnelFiles.DirectoryPath, "operation.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
        catch (IOException) { return; }
        using (operationLock) { await ReconcileDnsCoreAsync(token); }
    }

    private static async Task ReconcileDnsCoreAsync(CancellationToken token)
    {
        bool active = false;
        var services = ServiceController.GetServices();
        try
        {
            foreach (var service in services)
            {
                if (!service.ServiceName.StartsWith("WireGuardTunnel$avt-", StringComparison.Ordinal)
                    || service.Status != ServiceControllerStatus.Running) continue;
                var name = service.ServiceName["WireGuardTunnel$".Length..];
                if (!BrokerClient.ValidName(name)) continue;
                var path = Path.Combine(ProtectedTunnelFiles.DirectoryPath, name + ".conf.dpapi");
                var owner = Path.Combine(ProtectedTunnelFiles.DirectoryPath, name + ".owner");
                if (!File.Exists(path) || !File.Exists(owner)) continue;
                ProtectedTunnelFiles.ValidateFile(path);
                ProtectedTunnelFiles.ValidateFile(owner);
                VerifyService(service.ServiceName, path);
                var key = await WgAsync(name, "public-key", token);
                WireGuardManager.ValidateKey(key);
                if (name != "avt-" + Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(key)))[..24].ToLowerInvariant()) continue;
                var peer = await WgAsync(name, "peers", token);
                WireGuardManager.ValidateKey(peer);
                var routes = (await WgAsync(name, "allowed-ips", token)).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (routes.Length < 2 || routes[0] != peer
                    || !routes.Skip(1).Any(r => r is "10.40.0.0/24" or "10.40.0.10/32")
                    || !TunnelDefinition.SupportedRoutes.Any(allowed => allowed.Split(", ").OrderBy(r => r)
                        .SequenceEqual(routes.Skip(1).OrderBy(r => r)))) continue;
                if (TunnelDefinition.HasRecentHandshake(await WgAsync(name, "latest-handshakes", token), peer, DateTimeOffset.UtcNow)) active = true;
            }
        }
        // Service shutdown/upgrade must preserve DNS for an already active tunnel.
        // A new broker instance reconciles any interrupted operation at startup.
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(22));
            try { await SplitDnsManager.ApplyAsync(false, cleanup.Token); } catch { }
            throw;
        }
        finally { foreach (var service in services) service.Dispose(); }
        try { await SplitDnsManager.ApplyAsync(active, token); }
        // Service shutdown/upgrade must preserve DNS for an already active tunnel.
        // A new broker instance reconciles any interrupted operation at startup.
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(22));
            try { await SplitDnsManager.ApplyAsync(false, cleanup.Token); } catch { }
            throw;
        }
    }

    private static bool ServiceExists(string name)
    {
        using var service = new ServiceController(name);
        try { _ = service.Status; return true; }
        catch (InvalidOperationException ex) when (ex.InnerException is Win32Exception { NativeErrorCode: 1060 }) { return false; }
    }

    private static bool OtherTunnelActive(string ownName)
    {
        var services = ServiceController.GetServices();
        try
        {
            return services.Any(s => s.ServiceName.StartsWith("WireGuardTunnel$", StringComparison.OrdinalIgnoreCase)
                && !s.ServiceName.Equals(ownName, StringComparison.OrdinalIgnoreCase)
                && s.Status != ServiceControllerStatus.Stopped);
        }
        finally { foreach (var service in services) service.Dispose(); }
    }

    private static async Task WaitAsync(ServiceController service, ServiceControllerStatus target, CancellationToken cancellationToken)
    {
        var wait = Stopwatch.StartNew();
        do
        {
            service.Refresh();
            if (service.Status == target) return;
            await Task.Delay(300, cancellationToken);
        } while (wait.Elapsed < TimeSpan.FromSeconds(12));
        throw new System.TimeoutException();
    }

    private static void VerifyService(string name, string path)
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + name);
        if (key?.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string command
            || key.GetValue("ObjectName") is not string account || !account.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase)
            || !IsExpectedCommand(command, WireGuardPath, path))
            throw new InvalidDataException("Foreign service configuration.");
    }

    public static bool IsExpectedCommand(string command, string executable, string configuration)
    {
        var argv = CommandLineToArgvW(command, out int argc);
        if (argv == IntPtr.Zero) return false;
        try
        {
            return argc == 3
                && string.Equals(Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv)), executable, StringComparison.OrdinalIgnoreCase)
                && Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, IntPtr.Size)) == "/tunnelservice"
                && string.Equals(Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, 2 * IntPtr.Size)), configuration, StringComparison.OrdinalIgnoreCase);
        }
        finally { LocalFree(argv); }
    }

    private static Task<string> WgAsync(string name, string field, CancellationToken cancellationToken)
        => RunAsync(WireGuardManager.WgPath, ["show", name, field], cancellationToken);

    private static async Task<string> RunAsync(string executable, string[] arguments, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(12));
        var start = new ProcessStartInfo(executable)
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new IOException("Process unavailable.");
        try
        {
            var output = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var error = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token);
            await error; // Never relay raw diagnostics.
            var result = await output;
            if (process.ExitCode != 0 || result.Length > 16384) throw new IOException("WireGuard operation failed.");
            return result.Trim();
        }
        finally { if (!process.HasExited) process.Kill(entireProcessTree: true); }
    }

    private static void SetManualStart(string name)
    {
        var manager = OpenSCManager(null, null, 0x0001);
        if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var service = OpenService(manager, name, 0x0002);
            if (service == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                if (!ChangeServiceConfig(service, 0xffffffff, 3, 0xffffffff, null, null, IntPtr.Zero, null, null, null, null))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(manager); }
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig(IntPtr service, uint type, uint start, uint error, string? binary,
        string? group, IntPtr tag, string? dependencies, string? account, string? password, string? display);
    [DllImport("advapi32.dll")] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(string command, out int count);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
}
