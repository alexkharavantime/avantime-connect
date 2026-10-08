using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AvantimeConnect.Core.Enrollment;

public sealed class ProtectedEnrollmentStore(string path) : IEnrollmentStore
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("AvantimeConnect.Enrollment.v1");
    public EnrollmentState? Load()
    {
        if (!File.Exists(path)) return null;
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length is < 1 or > 65536) throw new InvalidDataException("Invalid enrollment length.");
        var encrypted = new byte[(int)input.Length];
        input.ReadExactly(encrypted);
        byte[] plaintext = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.CurrentUser);
        try
        {
            var state = JsonSerializer.Deserialize<EnrollmentState>(plaintext);
            if (state is null || state.Version != 1) throw new InvalidDataException("Unsupported enrollment state.");
            return state;
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    public void Save(EnrollmentState state)
    {
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(state);
        byte[] encrypted;
        try { encrypted = ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.CurrentUser); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                file.Write(encrypted);
                file.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
