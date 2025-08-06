using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace C2Framework
{
    public class OperatorProfile
    {
        public string ProfileName { get; set; }
        public string ServerIP { get; set; }
        public int OperatorPort { get; set; }
        public string Username { get; set; }
        public string EncryptedPassword { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public DateTime LastUsed { get; set; } = DateTime.MinValue;
        public bool IsDefault { get; set; } = false;

        public override string ToString()
        {
            return $"{ProfileName} ({Username}@{ServerIP}:{OperatorPort})";
        }

        public string DisplayName => ToString();
    }

    public static class OperatorProfileManager
    {
        private static readonly string ProfilesPath = "operator_profiles.json";
        private static readonly string EncryptionKey = "C2OpProfiles2024!";
        private static List<OperatorProfile> _profiles = new List<OperatorProfile>();

        public static List<OperatorProfile> LoadProfiles()
        {
            try
            {
                if (File.Exists(ProfilesPath))
                {
                    string json = File.ReadAllText(ProfilesPath);

                    if (string.IsNullOrWhiteSpace(json))
                    {
                        _profiles = new List<OperatorProfile>();
                    }
                    else
                    {
                        var savedProfiles = JsonSerializer.Deserialize<List<OperatorProfile>>(json);
                        _profiles = savedProfiles ?? new List<OperatorProfile>();
                    }
                }
                else
                {
                    _profiles = new List<OperatorProfile>();
                }

                EnsureDefaultProfiles();

                return _profiles;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Failed to load operator profiles: {ex.Message}");
                _profiles = new List<OperatorProfile>();
                EnsureDefaultProfiles();
                return _profiles;
            }
        }
        private static void EnsureDefaultProfiles()
        {
            // Default profiles that should always exist
            var defaultProfiles = new[]
            {
        new { Name = "Local Server", IP = "192.168.159.130", Port = 9191, User = "operator", Pass = "OpPass2024!" },
        new { Name = "Local Observer", IP = "192.168.159.130", Port = 9191, User = "observer", Pass = "ObsPass2024!" }
    };

            bool profilesAdded = false;

            foreach (var defaultProfile in defaultProfiles)
            {
                // Check if this default profile already exists
                bool exists = _profiles.Any(p =>
                    p.ProfileName.Equals(defaultProfile.Name, StringComparison.OrdinalIgnoreCase) ||
                    (p.ServerIP == defaultProfile.IP &&
                     p.OperatorPort == defaultProfile.Port &&
                     p.Username.Equals(defaultProfile.User, StringComparison.OrdinalIgnoreCase)));

                if (!exists)
                {
                    var newProfile = new OperatorProfile
                    {
                        ProfileName = defaultProfile.Name,
                        ServerIP = defaultProfile.IP,
                        OperatorPort = defaultProfile.Port,
                        Username = defaultProfile.User,
                        EncryptedPassword = EncryptPassword(defaultProfile.Pass),
                        CreatedAt = DateTime.Now,
                        IsDefault = defaultProfile.Name == "Local Server" && !_profiles.Any(p => p.IsDefault)
                    };

                    _profiles.Add(newProfile);
                    profilesAdded = true;
                }
            }

            if (profilesAdded)
            {
                SaveProfiles();
            }
        }
        public static void UpdateProfilePasswordForUser(string username, string newPassword)
        {
            try
            {
                LoadProfiles();

                bool profilesUpdated = false;

                // Find all profiles that use this username
                foreach (var profile in _profiles.Where(p => p.Username.Equals(username, StringComparison.OrdinalIgnoreCase)))
                {
                    // Update the encrypted password
                    profile.EncryptedPassword = EncryptPassword(newPassword);
                    profilesUpdated = true;

                    // Log the update (optional)
                    Console.WriteLine($"[*] Updated password for profile '{profile.ProfileName}' (user: {username})");
                }

                if (profilesUpdated)
                {
                    SaveProfiles();
                    Console.WriteLine($"[+] Synchronized {_profiles.Count(p => p.Username.Equals(username, StringComparison.OrdinalIgnoreCase))} profile(s) for user '{username}'");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error updating profile passwords for user '{username}': {ex.Message}");
            }
        }

        public static List<string> GetAllUsernames()
        {
            LoadProfiles();
            return _profiles.Select(p => p.Username).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        public static void SaveProfiles()
        {
            try
            {
                var options = new JsonSerializerOptions { WriteIndented = true };
                string json = JsonSerializer.Serialize(_profiles, options);
                File.WriteAllText(ProfilesPath, json);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to save operator profiles: {ex.Message}");
            }
        }

        public static void AddProfile(string profileName, string serverIP, int port, string username, string password, bool setAsDefault = false)
        {
            // Check if profile name already exists
            if (_profiles.Any(p => p.ProfileName.Equals(profileName, StringComparison.OrdinalIgnoreCase)))
            {
                throw new Exception($"Profile '{profileName}' already exists");
            }

            // If setting as default, remove default flag from other profiles
            if (setAsDefault)
            {
                foreach (var profile in _profiles)
                {
                    profile.IsDefault = false;
                }
            }

            var newProfile = new OperatorProfile
            {
                ProfileName = profileName,
                ServerIP = serverIP,
                OperatorPort = port,
                Username = username,
                EncryptedPassword = EncryptPassword(password),
                CreatedAt = DateTime.Now,
                IsDefault = setAsDefault
            };

            _profiles.Add(newProfile);
            SaveProfiles();
        }

        public static void UpdateProfile(string profileName, string serverIP, int port, string username, string password, bool setAsDefault = false)
        {
            var existingProfile = _profiles.FirstOrDefault(p => p.ProfileName.Equals(profileName, StringComparison.OrdinalIgnoreCase));
            if (existingProfile == null)
            {
                throw new Exception($"Profile '{profileName}' not found");
            }

            // If setting as default, remove default flag from other profiles
            if (setAsDefault)
            {
                foreach (var profile in _profiles)
                {
                    profile.IsDefault = false;
                }
            }

            existingProfile.ServerIP = serverIP;
            existingProfile.OperatorPort = port;
            existingProfile.Username = username;
            if (!string.IsNullOrEmpty(password))
            {
                existingProfile.EncryptedPassword = EncryptPassword(password);
            }
            existingProfile.IsDefault = setAsDefault;

            SaveProfiles();
        }

        public static void RemoveProfile(string profileName)
        {
            var profileToRemove = _profiles.FirstOrDefault(p => p.ProfileName.Equals(profileName, StringComparison.OrdinalIgnoreCase));
            if (profileToRemove != null)
            {
                _profiles.Remove(profileToRemove);
                SaveProfiles();
            }
        }

        public static OperatorProfile GetProfile(string profileName)
        {
            return _profiles.FirstOrDefault(p => p.ProfileName.Equals(profileName, StringComparison.OrdinalIgnoreCase));
        }

        public static OperatorProfile GetDefaultProfile()
        {
            return _profiles.FirstOrDefault(p => p.IsDefault);
        }

        public static List<OperatorProfile> GetAllProfiles()
        {
            return _profiles.ToList();
        }

        public static string DecryptPassword(string encryptedPassword)
        {
            try
            {
                byte[] data = Convert.FromBase64String(encryptedPassword);
                byte[] key = Encoding.UTF8.GetBytes(EncryptionKey.PadRight(32).Substring(0, 32));

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    {
                        byte[] decryptedBytes = decryptor.TransformFinalBlock(data, 0, data.Length);
                        return Encoding.UTF8.GetString(decryptedBytes);
                    }
                }
            }
            catch
            {
                return string.Empty; // Return empty if decryption fails
            }
        }

        public static string EncryptPassword(string password)
        {
            try
            {
                byte[] data = Encoding.UTF8.GetBytes(password);
                byte[] key = Encoding.UTF8.GetBytes(EncryptionKey.PadRight(32).Substring(0, 32));

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    {
                        byte[] encryptedBytes = encryptor.TransformFinalBlock(data, 0, data.Length);
                        return Convert.ToBase64String(encryptedBytes);
                    }
                }
            }
            catch
            {
                return password; // Return original if encryption fails
            }
        }
        public static void UpdateLastUsed(string profileName)
        {
            var profile = GetProfile(profileName);
            if (profile != null)
            {
                profile.LastUsed = DateTime.Now;
                SaveProfiles();
            }
        }

        public static void SetDefaultProfile(string profileName)
        {
            // Remove default flag from all profiles
            foreach (var profile in _profiles)
            {
                profile.IsDefault = false;
            }

            // Set the specified profile as default
            var targetProfile = GetProfile(profileName);
            if (targetProfile != null)
            {
                targetProfile.IsDefault = true;
                SaveProfiles();
            }
        }

        public static int GetProfileCount()
        {
            return _profiles.Count;
        }

        public static bool HasProfiles()
        {
            // Load profiles first to ensure defaults are included
            LoadProfiles();
            return _profiles.Count > 0;
        }
    }
}