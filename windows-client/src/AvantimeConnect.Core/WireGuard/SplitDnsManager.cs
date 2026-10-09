using System.Diagnostics;
using System.Reflection;
using System.Text;

namespace AvantimeConnect.Core.WireGuard;

public static class SplitDnsManager
{
    // Embedded trusted script and two fixed modes: no user-supplied PowerShell.
    public static async Task ApplyAsync(bool enable, CancellationToken cancellationToken)
    {
        using var stream = typeof(SplitDnsManager).Assembly.GetManifestResourceStream(
            "AvantimeConnect.Core.WireGuard.SplitDns.ps1") ?? throw new IOException("DNS resource missing.");
        using var reader = new StreamReader(stream);
        var script = await reader.ReadToEndAsync(cancellationToken);
        var command = "& {\n" + script + "\n} -Action " + (enable ? "enable" : "remove");
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell", "v1.0", "powershell.exe");
        var start = new ProcessStartInfo(path) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                     Convert.ToBase64String(Encoding.Unicode.GetBytes(command)) }) start.ArgumentList.Add(arg);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));
        using var process = Process.Start(start) ?? throw new IOException("DNS process unavailable.");
        try
        {
            var stdout = DrainAsync(process.StandardOutput, timeout.Token);
            var stderr = DrainAsync(process.StandardError, timeout.Token);
            await process.WaitForExitAsync(timeout.Token);
            await Task.WhenAll(stdout, stderr);
            if (process.ExitCode != 0) throw new IOException("DNS policy failed.");
        }
        finally { if (!process.HasExited) process.Kill(entireProcessTree: true); }
    }
    private static async Task DrainAsync(StreamReader reader, CancellationToken token)
    {
        var buffer = new char[1024];
        while (await reader.ReadAsync(buffer.AsMemory(), token) > 0) { }
    }
}
