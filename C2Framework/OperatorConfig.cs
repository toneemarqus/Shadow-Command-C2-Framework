using System.Security.Cryptography;
using System.Text;
using System.Text.Json;


namespace C2Framework
{
    public class OperatorCredential
    {
        public string Username { get; set; }
        public string PasswordHash { get; set; }
        public string Role { get; set; } = "Operator";
        public bool Enabled { get; set; } = true;
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public DateTime LastLogin { get; set; } = DateTime.MinValue;
        public string CreatedBy { get; set; } = "System";
        public int LoginCount { get; set; } = 0;
    }

    public class OperatorConfig
    {
        public bool MultiplayerEnabled { get; set; } = false;
        public int OperatorPort { get; set; } = 9191;
        public int MaxOperators { get; set; } = 10;
        public bool RequireAuthentication { get; set; } = true;
        public bool LogOperatorActivity { get; set; } = true;
        public List<OperatorCredential> Operators { get; set; } = new();
    }

    public static class OperatorConfigManager
    {
        private static readonly string ConfigPath = "operators.json";
        private static OperatorConfig _config;
        private static readonly object _configLock = new object();

        public static OperatorConfig LoadConfig()
        {
            lock (_configLock)
            {
                try
                {
                    if (File.Exists(ConfigPath))
                    {
                        string json = File.ReadAllText(ConfigPath);
                        _config = JsonSerializer.Deserialize<OperatorConfig>(json, new JsonSerializerOptions { WriteIndented = true });
                    }
                    else
                    {
                        _config = CreateDefaultConfig();
                        SaveConfig();
                    }
                    return _config;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error loading config: {ex.Message}");
                    _config = CreateDefaultConfig();
                    SaveConfig();
                    return _config;
                }
            }
        }

        public static void SaveConfig()
        {
            lock (_configLock)
            {
                try
                {
                    string json = JsonSerializer.Serialize(_config, new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(ConfigPath, json);
                }
                catch (Exception ex)
                {
                    throw new Exception($"Failed to save operator config: {ex.Message}");
                }
            }
        }
        public static void UpdateConfig(OperatorConfig config)
        {
            lock (_configLock)
            {
                _config = config;
            }
        }

        public static OperatorConfig GetConfig() => _config ?? LoadConfig();

        public static string HashPassword(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password + "C2Salt2024"));
                return Convert.ToBase64String(hashedBytes);
            }
        }

        private static OperatorConfig CreateDefaultConfig()
        {
            return new OperatorConfig
            {
                MultiplayerEnabled = false,
                OperatorPort = 9191,
                MaxOperators = 10,
                RequireAuthentication = true,
                LogOperatorActivity = true,
                Operators = new List<OperatorCredential>
                {
                    new()
                    {
                        Username = "operator",
                        PasswordHash = HashPassword("OpPass2024!"),
                        Role = "Operator",
                        Enabled = true,
                        CreatedAt = DateTime.Now,
                        CreatedBy = "System"
                    },
                    new()
                    {
                        Username = "observer",
                        PasswordHash = HashPassword("ObsPass2024!"),
                        Role = "Observer",
                        Enabled = true,
                        CreatedAt = DateTime.Now,
                        CreatedBy = "System"
                    }
                }
            };
        }

        // USER MANAGEMENT METHODS

        public static void AddOperator(string username, string password, string role, bool enabled = true, string createdBy = "Admin")
        {
            var config = GetConfig();

            // Validate input
            if (string.IsNullOrWhiteSpace(username))
                throw new ArgumentException("Username cannot be empty");

            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password cannot be empty");

            if (role != "Operator" && role != "Observer")
                throw new ArgumentException("Role must be 'Operator' or 'Observer'");

            // Check if username already exists
            if (config.Operators.Any(op => op.Username.Equals(username, StringComparison.OrdinalIgnoreCase)))
                throw new Exception($"Username '{username}' already exists");

            // Create new operator
            var newOperator = new OperatorCredential
            {
                Username = username.Trim(),
                PasswordHash = HashPassword(password),
                Role = role,
                Enabled = enabled,
                CreatedAt = DateTime.Now,
                CreatedBy = createdBy
            };

            config.Operators.Add(newOperator);
            SaveConfig();
        }

        public static void UpdateOperator(string username, string newPassword, string role, bool enabled)
        {
            var config = GetConfig();
            var operator_ = config.Operators.FirstOrDefault(op =>
                op.Username.Equals(username, StringComparison.OrdinalIgnoreCase));

            if (operator_ == null)
                throw new Exception($"Operator '{username}' not found");

            // Update password only if provided
            if (!string.IsNullOrEmpty(newPassword))
            {
                operator_.PasswordHash = HashPassword(newPassword);

                try
                {
                    OperatorProfileManager.UpdateProfilePasswordForUser(username, newPassword);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Warning: Could not sync password change to profiles: {ex.Message}");
                }
            }

            operator_.Role = role;
            operator_.Enabled = enabled;

            SaveConfig();
        }

        public static void ChangePassword(string username, string newPassword)
        {
            if (string.IsNullOrWhiteSpace(newPassword))
                throw new ArgumentException("Password cannot be empty");

            var config = GetConfig();
            var operator_ = config.Operators.FirstOrDefault(op =>
                op.Username.Equals(username, StringComparison.OrdinalIgnoreCase));

            if (operator_ == null)
                throw new Exception($"Operator '{username}' not found");

            operator_.PasswordHash = HashPassword(newPassword);
            SaveConfig();

            try
            {
                OperatorProfileManager.UpdateProfilePasswordForUser(username, newPassword);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Warning: Could not sync password change to profiles: {ex.Message}");
            }
        }
        public static void EnableOperator(string username, bool enabled)
        {
            var config = GetConfig();
            var operator_ = config.Operators.FirstOrDefault(op =>
                op.Username.Equals(username, StringComparison.OrdinalIgnoreCase));

            if (operator_ == null)
                throw new Exception($"Operator '{username}' not found");

            operator_.Enabled = enabled;
            SaveConfig();
        }

        public static void RemoveOperator(string username)
        {
            var config = GetConfig();
            int removedCount = config.Operators.RemoveAll(op =>
                op.Username.Equals(username, StringComparison.OrdinalIgnoreCase));

            if (removedCount == 0)
                throw new Exception($"Operator '{username}' not found");

            SaveConfig();
        }

        public static List<OperatorCredential> GetAllOperators()
        {
            var config = GetConfig();
            return config.Operators.ToList();
        }

        public static OperatorCredential GetOperator(string username)
        {
            var config = GetConfig();
            return config.Operators.FirstOrDefault(op =>
                op.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
        }

        public static bool ValidateCredentials(string username, string password, out OperatorCredential credential)
        {
            credential = null;
            var config = GetConfig();

            string hashedPassword = HashPassword(password);

            credential = config.Operators.Find(op =>
                op.Username.Equals(username, StringComparison.OrdinalIgnoreCase) &&
                op.PasswordHash == hashedPassword &&
                op.Enabled);

            // Update login statistics
            if (credential != null)
            {
                credential.LastLogin = DateTime.Now;
                credential.LoginCount++;
                SaveConfig();
            }

            return credential != null;
        }

        // UTILITY METHODS

        public static bool HasOperators()
        {
            var config = GetConfig();
            return config.Operators.Any();
        }

        public static int GetOperatorCount()
        {
            var config = GetConfig();
            return config.Operators.Count;
        }

        public static int GetEnabledOperatorCount()
        {
            var config = GetConfig();
            return config.Operators.Count(op => op.Enabled);
        }

        public static List<OperatorCredential> GetOperatorsByRole(string role)
        {
            var config = GetConfig();
            return config.Operators.Where(op => op.Role.Equals(role, StringComparison.OrdinalIgnoreCase)).ToList();
        }

        public static void ToggleMultiplayer(bool enabled)
        {
            var config = GetConfig();
            config.MultiplayerEnabled = enabled;
            SaveConfig();
        }

        public static void EnsureDefaultOperator()
        {
            var config = GetConfig();

            // Create default operator if no operators exist
            if (!config.Operators.Any())
            {
                config.Operators.Add(new OperatorCredential
                {
                    Username = "operator",
                    PasswordHash = HashPassword("OpPass2024!"),
                    Role = "Operator",
                    Enabled = true,
                    CreatedAt = DateTime.Now,
                    CreatedBy = "System"
                });
                SaveConfig();
            }
        }
    }
}
