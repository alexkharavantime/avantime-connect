using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using Microsoft.Win32.SafeHandles;
using AvantimeConnect.Core.Broker;
using AvantimeConnect.Core.Enrollment;
using AvantimeConnect.Core.WireGuard;

if (args.Length != 0 || !WindowsIdentity.GetCurrent().IsSystem) return 26;
ServiceBase.Run(new BrokerService());
return 0;

sealed class BrokerService : ServiceBase
{
    private readonly CancellationTokenSource shutdown = new();
    private NamedPipeServerStream? pipe;
    private Task? worker;
    public BrokerService() { ServiceName = BrokerClient.ServiceName; AutoLog = false; }
    protected override void OnStart(string[] args)
    {
        // Fail startup if another process has reserved the pipe. Keep one server
        // handle for the whole service lifetime; no name-squatting gap per request.
        pipe = CreatePipe();
        worker = Task.Run(RunAsync);
    }
    protected override void OnStop()
    {
        shutdown.Cancel();
        pipe?.Dispose();
        try { worker?.GetAwaiter().GetResult(); } catch { }
        // Stopping the broker never stops a user's VPN or deletes enrollment.
    }
    private async Task RunAsync()
    {
        while (!shutdown.IsCancellationRequested)
        {
            try
            {
                await pipe!.WaitForConnectionAsync(shutdown.Token);
                var result = TunnelResult.Failed;
                try
                {
                    var request = new byte[30];
                    using var readTimeout = CancellationTokenSource.CreateLinkedTokenSource(shutdown.Token);
                    readTimeout.CancelAfter(TimeSpan.FromSeconds(5));
                    await pipe.ReadExactlyAsync(request, readTimeout.Token);
                    result = await ExecuteAsync(request);
                }
                catch { /* Never emit paths, DPAPI bytes, keys, or raw exceptions. */ }
                using var writeTimeout = CancellationTokenSource.CreateLinkedTokenSource(shutdown.Token);
                writeTimeout.CancelAfter(TimeSpan.FromSeconds(2));
                await pipe.WriteAsync(new[] { (byte)result }, writeTimeout.Token);
                // DisconnectNamedPipe may discard unread response bytes. An ACK
                // avoids that race without an unbounded WaitForPipeDrain call.
                await pipe.ReadExactlyAsync(new byte[1], writeTimeout.Token);
            }
            catch when (shutdown.IsCancellationRequested) { break; }
            catch { }
            finally { try { if (pipe!.IsConnected) pipe.Disconnect(); } catch { } }
        }
    }
    private async Task<TunnelResult> ExecuteAsync(byte[] request)
    {
        var name = Encoding.ASCII.GetString(request, 2, 28);
        if (request[0] != 1 || request[1] is < 1 or > 3 || !BrokerClient.ValidName(name)) return TunnelResult.Failed;
        EnrollmentState? state = null;
        string? sid = null;
        try
        {
            // SID and file location are obtained from the authenticated pipe token,
            // never from caller-supplied paths or JSON. No async inside impersonation.
            pipe!.RunAsClient(() =>
            {
                using var identity = WindowsIdentity.GetCurrent(true) ?? throw new UnauthorizedAccessException();
                if (!identity.IsAuthenticated || identity.IsSystem || identity.ImpersonationLevel != TokenImpersonationLevel.Impersonation)
                    throw new UnauthorizedAccessException();
                sid = identity.User!.Value;
                var folder = new Guid("F1B32785-6FBA-4FCF-9D55-7B8E7F157091");
                Marshal.ThrowExceptionForHR(SHGetKnownFolderPath(ref folder, 0, identity.AccessToken, out var pointer));
                string path;
                try { path = Path.Combine(Marshal.PtrToStringUni(pointer)!, "AvantimeConnect", "enrollment.dpapi"); }
                finally { Marshal.FreeCoTaskMem(pointer); }
                if (path.StartsWith(@"\\", StringComparison.Ordinal)) throw new UnauthorizedAccessException();
                for (string? part = Path.GetDirectoryName(path); part is not null; part = Path.GetDirectoryName(part))
                    if ((File.GetAttributes(part) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException();
                state = new ProtectedEnrollmentStore(path).Load();
            });
            if (state is null || new TunnelDefinition(state).Name != name) return TunnelResult.InvalidProfile;
        }
        catch { return TunnelResult.InvalidProfile; }
        // Additional deployment policy: arbitrary destinations must not be installed
        // by a privileged broker. Loopback discard is allowed for isolated CI tests.
        if (state.Profile!.Endpoint is not ("65.21.22.189:51820" or "127.0.0.1:9")) return TunnelResult.InvalidProfile;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(shutdown.Token);
        timeout.CancelAfter(TimeSpan.FromSeconds(80));
        if (await WireGuardManager.DerivePublicKeyAsync(state.PrivateKey, timeout.Token) != state.PublicKey)
            return TunnelResult.InvalidProfile;
        ProtectedTunnelFiles.EnsureDirectory(ProtectedTunnelFiles.DirectoryPath);
        var owner = Path.Combine(ProtectedTunnelFiles.DirectoryPath, name + ".owner");
        // Adopt an existing 0.2.0 tunnel only after normal config/key/service checks.
        // Owner records are admin/SYSTEM-only and survive upgrade and uninstall.
        if (File.Exists(owner))
        {
            ProtectedTunnelFiles.ValidateFile(owner);
            if (new FileInfo(owner).Length > 256 || File.ReadAllText(owner) != sid) return TunnelResult.OwnershipMismatch;
        }
        else
        {
            using var file = new FileStream(owner, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            file.Write(Encoding.UTF8.GetBytes(sid!)); file.Flush(true);
        }
        return await new WindowsTunnelController().ExecuteAsync(request[1] switch { 1 => "connect", 2 => "disconnect", _ => "check" }, state, timeout.Token);
    }
    private static NamedPipeServerStream CreatePipe()
    {
        // Deny network logons. Authenticated local users can exchange data, but
        // cannot create server instances, change the ACL, or take ownership.
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor("D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;0x12019b;;;AU)", 1, out var descriptor, out _))
            throw new IOException();
        try
        {
            var security = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = descriptor };
            var handle = CreateNamedPipe(@"\\.\pipe\" + BrokerClient.PipeName, 0x40080003, 8, 1, 256, 256, 0, ref security);
            if (handle.IsInvalid) { handle.Dispose(); throw new IOException(); }
            return new NamedPipeServerStream(PipeDirection.InOut, true, false, handle);
        }
        finally { LocalFree(descriptor); }
    }
    [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int Inherit; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW")]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl, uint version, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "CreateNamedPipeW", SetLastError = true)]
    private static extern SafePipeHandle CreateNamedPipe(string name, uint openMode, uint pipeMode, uint maxInstances, uint output, uint input, uint timeout, ref SecurityAttributes security);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr pointer);
    [DllImport("shell32.dll")]
    private static extern int SHGetKnownFolderPath(ref Guid folder, uint flags, SafeAccessTokenHandle token, out IntPtr path);
}
