using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace AvantimeConnect.Core.WireGuard;

// WireGuard .conf.dpapi format: no optional entropy, tunnel name as DPAPI description.
// Machine scope lets the LocalSystem tunnel service decrypt. A restricted file ACL
// is mandatory: machine-scope DPAPI alone does NOT isolate local users.
public static class TunnelDpapi
{
    public static byte[] Protect(byte[] plaintext, string tunnelName)
        => Transform(plaintext, tunnelName, true);
    public static byte[] Unprotect(byte[] encrypted, string tunnelName)
        => Transform(encrypted, tunnelName, false);

    private static byte[] Transform(byte[] input, string name, bool protect)
    {
        var pin = GCHandle.Alloc(input, GCHandleType.Pinned);
        var source = new Blob { Length = input.Length, Data = pin.AddrOfPinnedObject() };
        Blob output = default;
        IntPtr description = IntPtr.Zero;
        try
        {
            bool ok = protect
                ? CryptProtectData(ref source, name, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0x1 | 0x4, out output)
                : CryptUnprotectData(ref source, out description, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0x1, out output);
            if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!protect && Marshal.PtrToStringUni(description) != name)
                throw new CryptographicException("Tunnel name mismatch.");
            if (output.Length is < 1 or > 65536) throw new CryptographicException("Invalid DPAPI size.");
            var result = new byte[output.Length];
            Marshal.Copy(output.Data, result, 0, result.Length);
            return result;
        }
        finally
        {
            pin.Free();
            if (output.Data != IntPtr.Zero)
            {
                // Zero decrypted native memory as well as callers' managed buffers.
                if (!protect && output.Length is > 0 and <= 65536)
                    Marshal.Copy(new byte[output.Length], 0, output.Data, output.Length);
                LocalFree(output.Data);
            }
            if (description != IntPtr.Zero) LocalFree(description);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Blob { public int Length; public IntPtr Data; }
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(ref Blob data, string description, IntPtr entropy,
        IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref Blob data, out IntPtr description, IntPtr entropy,
        IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
}
