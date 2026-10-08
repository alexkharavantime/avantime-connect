using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using AvantimeConnect.Core.WireGuard;

namespace AvantimeConnect.Core.Broker;

public static class BrokerClient
{
    public const string ServiceName = "AvantimeConnectBroker";
    public const string PipeName = "AvantimeConnect.Broker.v1";
    public static byte[] Request(string action, string name)
    {
        byte code = action switch { "connect" => 1, "disconnect" => 2, "check" => 3, _ => throw new ArgumentException() };
        if (!ValidName(name)) throw new ArgumentException();
        return new byte[] { 1, code }.Concat(Encoding.ASCII.GetBytes(name)).ToArray();
    }
    public static bool ValidName(string name) => name.Length == 28 && name.StartsWith("avt-", StringComparison.Ordinal)
        && name.AsSpan(4).ToArray().All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    public static async Task<TunnelResult> ExecuteAsync(string action, string name, CancellationToken cancellationToken = default)
    {
        var request = Request(action, name);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(90));
        SafePipeHandle? handle = null;
        for (int attempt = 0; attempt < 30; attempt++)
        {
            // Specific rights exclude FILE_CREATE_PIPE_INSTANCE. Local only, with
            // impersonation so the broker can read CurrentUser DPAPI as this caller.
            handle = CreateFile(@"\\.\pipe\" + PipeName, 0x12019b, 0, IntPtr.Zero, 3, 0x40120000, IntPtr.Zero);
            if (!handle.IsInvalid) break;
            var error = Marshal.GetLastWin32Error();
            handle.Dispose(); handle = null;
            if (error != 231 && error != 2) throw new Win32Exception(error);
            await Task.Delay(100, timeout.Token);
        }
        if (handle is null) throw new IOException("Broker unavailable.");
        using (handle)
        using (var pipe = new NamedPipeClientStream(PipeDirection.InOut, true, true, handle))
        {
            // Do not trust a process merely because it owns the well-known name.
            if (!GetNamedPipeServerProcessId(handle, out var pid) || pid != ServiceProcessId())
                throw new IOException("Broker identity mismatch.");
            await pipe.WriteAsync(request, timeout.Token);
            var response = new byte[1];
            await pipe.ReadExactlyAsync(response, timeout.Token);
            return Enum.IsDefined(typeof(TunnelResult), (int)response[0]) ? (TunnelResult)response[0] : TunnelResult.Failed;
        }
    }

    private static uint ServiceProcessId()
    {
        var manager = OpenSCManager(null, null, 1);
        if (manager == IntPtr.Zero) throw new IOException();
        try
        {
            var service = OpenService(manager, ServiceName, 4);
            if (service == IntPtr.Zero) throw new IOException();
            try
            {
                if (!QueryServiceStatusEx(service, 0, out var status, 36, out _) || status.State != 4 || status.Pid == 0)
                    throw new IOException();
                return status.Pid;
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(manager); }
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Status { public uint Type, State, Controls, Win32Exit, ServiceExit, Checkpoint, WaitHint, Pid, Flags; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafePipeHandle CreateFile(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle handle, out uint pid);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll")]
    private static extern bool QueryServiceStatusEx(IntPtr service, int level, out Status status, int size, out int needed);
    [DllImport("advapi32.dll")] private static extern bool CloseServiceHandle(IntPtr handle);
}
