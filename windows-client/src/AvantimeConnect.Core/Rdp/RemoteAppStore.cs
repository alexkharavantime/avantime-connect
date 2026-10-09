using System.Security.Cryptography;
using System.Text;
using AvantimeConnect.Core.Enrollment;

namespace AvantimeConnect.Core.Rdp;

// Published RDP bytes remain unchanged, encrypted for the current Windows user.
public sealed class RemoteAppStore(string directory)
{
    private string FilePath(string slot)
    {
        if (slot is not ("32" or "64")) throw new ClientException("Неизвестная версия приложения.");
        return Path.Combine(directory, "remoteapp-" + slot + ".dpapi");
    }
    public byte[]? Load(string slot)
    {
        var path = FilePath(slot);
        if (!File.Exists(path)) return null;
        var file = new FileInfo(path);
        if (file.Length > RemoteAppPreflight.MaximumFileBytes + 8192) throw new ClientException("Сохранённый файл RemoteApp повреждён. Выберите файл заново.");
        var bytes = ProtectedData.Unprotect(File.ReadAllBytes(path), Encoding.UTF8.GetBytes("AvantimeConnect.RemoteApp.v1." + slot), DataProtectionScope.CurrentUser);
        RemoteAppPreflight.ValidateFile(bytes);
        return bytes;
    }
    public void Save(string slot, byte[] bytes)
    {
        var path = FilePath(slot);
        RemoteAppPreflight.ValidateFile(bytes);
        var encrypted = ProtectedData.Protect(bytes, Encoding.UTF8.GetBytes("AvantimeConnect.RemoteApp.v1." + slot), DataProtectionScope.CurrentUser);
        Directory.CreateDirectory(directory);
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try { File.WriteAllBytes(temporary, encrypted); File.Move(temporary, path, true); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
