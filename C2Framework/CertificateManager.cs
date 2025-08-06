using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace C2Framework
{
    public static class CertificateManager
    {
        private const string CertificatePath = "server_cert.pfx";
        private const string PasswordFilePath = "cert_password.txt";
        private const int KeySize = 4096;
        private const int ValidityDays = 365;

        public static X509Certificate2 GetOrCreateCertificate()
        {
            try
            {
                string password = GetOrCreatePassword();

                // Try to load existing certificate
                if (File.Exists(CertificatePath))
                {
                    X509Certificate2 cert = new X509Certificate2(
                        CertificatePath,
                        password,
                        X509KeyStorageFlags.MachineKeySet |
                        X509KeyStorageFlags.PersistKeySet |
                        X509KeyStorageFlags.Exportable);

                    // Verify the certificate is still valid
                    if (cert.NotAfter > DateTime.Now.AddDays(30))
                    {
                        return cert;
                    }

                    Console.WriteLine("Certificate expiring soon. Generating new certificate.");
                }

                return GenerateSelfSignedCertificate(password);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error managing certificate: {ex.Message}");
                throw;
            }
        }

        private static string GetOrCreatePassword()
        {
            try
            {
                // Try to read existing password
                if (File.Exists(PasswordFilePath))
                {
                    string existingPassword = File.ReadAllText(PasswordFilePath).Trim();
                    if (!string.IsNullOrEmpty(existingPassword))
                    {
                        return existingPassword;
                    }
                }

                // Generate new password
                string newPassword = GenerateSecurePassword();

                // Save password to file with restricted permissions
                File.WriteAllText(PasswordFilePath, newPassword);
                SetRestrictiveFilePermissions(PasswordFilePath);

                Console.WriteLine($"[+] Generated new certificate password and saved to {PasswordFilePath}");
                return newPassword;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error managing password: {ex.Message}");
                throw;
            }
        }

        private static string GenerateSecurePassword()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
            var random = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(random);
            }

            var result = new StringBuilder(32);
            foreach (byte b in random)
            {
                result.Append(chars[b % chars.Length]);
            }

            return result.ToString();
        }

        private static void SetRestrictiveFilePermissions(string filePath)
        {
            try
            {
                // On Windows, restrict access to current user only
                if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                {
                    var fileInfo = new FileInfo(filePath);
                    var fileSecurity = fileInfo.GetAccessControl();
                    fileSecurity.SetAccessRuleProtection(true, false); // Remove inherited permissions

                    var currentUser = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                    var accessRule = new System.Security.AccessControl.FileSystemAccessRule(
                        currentUser,
                        System.Security.AccessControl.FileSystemRights.FullControl,
                        System.Security.AccessControl.AccessControlType.Allow);

                    fileSecurity.SetAccessRule(accessRule);
                    fileInfo.SetAccessControl(fileSecurity);
                }
                else
                {
                    var process = new System.Diagnostics.Process
                    {
                        StartInfo = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "chmod",
                            Arguments = $"600 \"{filePath}\"",
                            UseShellExecute = false
                        }
                    };
                    process.Start();
                    process.WaitForExit();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not set restrictive file permissions: {ex.Message}");
            }
        }

        private static X509Certificate2 GenerateSelfSignedCertificate(string password)
        {
            using (RSA rsa = RSA.Create(KeySize))
            {
                var certificateRequest = new CertificateRequest(
                    "CN=C2Server,O=PenTest,C=AU",
                    rsa,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                certificateRequest.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        new OidCollection {
                            new Oid("1.3.6.1.5.5.7.3.1"),
                            new Oid("1.3.6.1.5.5.7.3.2")
                        }, true));

                var sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddDnsName("localhost");
                sanBuilder.AddDnsName("c2server");
                sanBuilder.AddIpAddress(IPAddress.Loopback);
                sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);
                certificateRequest.CertificateExtensions.Add(sanBuilder.Build());

                certificateRequest.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(false, false, 0, true));

                certificateRequest.CertificateExtensions.Add(
                    new X509KeyUsageExtension(
                        X509KeyUsageFlags.DigitalSignature |
                        X509KeyUsageFlags.KeyEncipherment |
                        X509KeyUsageFlags.DataEncipherment, true));

                var certificate = certificateRequest.CreateSelfSigned(
                    DateTimeOffset.Now.AddDays(-1),
                    DateTimeOffset.Now.AddDays(ValidityDays));

                certificate.FriendlyName = "C2 Server Certificate";

                File.WriteAllBytes(
                    CertificatePath,
                    certificate.Export(X509ContentType.Pfx, password));

                Console.WriteLine($"[+] Generated new certificate with fingerprint: {certificate.Thumbprint}");

                return certificate;
            }
        }
    }
}