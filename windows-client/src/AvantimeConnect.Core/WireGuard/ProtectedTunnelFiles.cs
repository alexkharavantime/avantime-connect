using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace AvantimeConnect.Core.WireGuard;

public static class ProtectedTunnelFiles
{
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier System = new(WellKnownSidType.LocalSystemSid, null);
    public static string DirectoryPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "AvantimeConnect.Tunnels");

    public static void EnsureDirectory(string path)
    {
        RejectReparsePoints(Path.GetDirectoryName(path)!);
        var acl = new DirectorySecurity();
        acl.SetOwner(Administrators);
        acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { Administrators, System })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).Create(acl);
        ValidateDirectory(path);
    }

    public static void ValidateDirectory(string path)
    {
        RejectReparsePoints(path);
        ValidateAcl(new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner));
    }

    public static void ValidateFile(string path)
    {
        RejectReparsePoints(path);
        ValidateAcl(new FileInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner));
    }

    private static void RejectReparsePoints(string path)
    {
        for (string? current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Reparse point in tunnel path.");
    }

    private static void ValidateAcl(FileSystemSecurity acl)
    {
        var owner = acl.GetOwner(typeof(SecurityIdentifier));
        if (!Administrators.Equals(owner) && !System.Equals(owner)) throw new InvalidDataException("Untrusted owner.");
        var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier));
        if (rules.Count == 0) throw new InvalidDataException("Empty ACL.");
        foreach (FileSystemAccessRule rule in rules)
            if (rule.AccessControlType == AccessControlType.Allow
                && !Administrators.Equals(rule.IdentityReference) && !System.Equals(rule.IdentityReference))
                throw new InvalidDataException("Untrusted tunnel permissions.");
    }

    public static void Verify(string path, TunnelDefinition definition)
    {
        ValidateFile(path);
        if (new FileInfo(path).Length is < 1 or > 65536) throw new InvalidDataException("Invalid protected configuration.");
        var plain = TunnelDpapi.Unprotect(File.ReadAllBytes(path), definition.Name);
        var expected = Encoding.UTF8.GetBytes(definition.Configuration);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(plain, expected)) throw new InvalidDataException("Configuration mismatch.");
        }
        finally { CryptographicOperations.ZeroMemory(plain); CryptographicOperations.ZeroMemory(expected); }
    }

    public static void Create(string path, TunnelDefinition definition)
    {
        ValidateDirectory(Path.GetDirectoryName(path)!);
        var plain = Encoding.UTF8.GetBytes(definition.Configuration);
        byte[] encrypted;
        try { encrypted = TunnelDpapi.Protect(plain, definition.Name); }
        finally { CryptographicOperations.ZeroMemory(plain); }
        var temporary = Path.Combine(Path.GetDirectoryName(path)!, Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                file.Write(encrypted);
                file.Flush(true);
            }
            var fileAcl = new FileSecurity();
            fileAcl.SetOwner(Administrators);
            fileAcl.SetAccessRuleProtection(true, false);
            foreach (var sid in new[] { Administrators, System })
                fileAcl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(temporary).SetAccessControl(fileAcl);
            ValidateFile(temporary);
            File.Move(temporary, path, overwrite: false);
            Verify(path, definition);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
