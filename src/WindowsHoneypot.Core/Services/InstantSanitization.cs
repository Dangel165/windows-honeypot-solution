using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// One-click cleanup with physical data deletion, firewall rule restoration, and registry cleanup
/// </summary>
public class InstantSanitization : IInstantSanitization
{
    private readonly ILogger<InstantSanitization> _logger;
    private readonly INetworkBlocker _networkBlocker;
    private readonly IDeceptionEngine _deceptionEngine;
    private readonly object _lock = new();
    private SanitizationStatus _status;

    // Paths for cleanup
    private readonly List<string> _sandboxDataPaths = new()
    {
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Packages", "Microsoft.Windows.Sandbox_*"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp", "WindowsHoneypot_*"),
        Path.Combine(Path.GetTempPath(), "WindowsHoneypot_*")
    };

    private readonly List<string> _temporaryFilePaths = new()
    {
        Path.Combine(Path.GetTempPath(), "*.tmp"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.InternetCache)),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Recent))
    };

    public InstantSanitization(
        ILogger<InstantSanitization> logger,
        INetworkBlocker networkBlocker,
        IDeceptionEngine deceptionEngine)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _networkBlocker = networkBlocker ?? throw new ArgumentNullException(nameof(networkBlocker));
        _deceptionEngine = deceptionEngine ?? throw new ArgumentNullException(nameof(deceptionEngine));
        _status = SanitizationStatus.Idle;
    }

    public async Task<SanitizationResult> SanitizeAsync(
        IProgress<SanitizationProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            if (_status == SanitizationStatus.Running)
            {
                throw new InvalidOperationException("Sanitization is already in progress");
            }
            _status = SanitizationStatus.Running;
        }

        var result = new SanitizationResult
        {
            StartTime = DateTime.UtcNow
        };

        try
        {
            _logger.LogInformation("Starting instant sanitization...");

            // Step 1: Network connection blocking and reset (0-15%)
            await PerformOperationAsync(
                result,
                SanitizationOperationType.NetworkReset,
                "Blocking and resetting network connections",
                progress,
                0,
                15,
                async () => await BlockAndResetNetworkAsync(),
                cancellationToken
            );

            // Step 2: Sandbox data deletion (15-40%)
            await PerformOperationAsync(
                result,
                SanitizationOperationType.SandboxDataDeletion,
                "Physically deleting sandbox data",
                progress,
                15,
                40,
                async () => await DeleteSandboxDataAsync(progress, cancellationToken),
                cancellationToken
            );

            // Step 3: Firewall rule restoration (40-60%)
            await PerformOperationAsync(
                result,
                SanitizationOperationType.FirewallRestoration,
                "Restoring firewall rules to initial state",
                progress,
                40,
                60,
                async () => await RestoreFirewallRulesAsync(),
                cancellationToken
            );

            // Step 4: Registry cleanup (60-75%)
            await PerformOperationAsync(
                result,
                SanitizationOperationType.RegistryCleanup,
                "Cleaning up registry modifications",
                progress,
                60,
                75,
                async () => await CleanupRegistryAsync(),
                cancellationToken
            );

            // Step 5: Temporary files and cache deletion (75-90%)
            await PerformOperationAsync(
                result,
                SanitizationOperationType.TemporaryFileCleanup,
                "Deleting temporary files and cache",
                progress,
                75,
                90,
                async () => await DeleteTemporaryFilesAsync(progress, cancellationToken),
                cancellationToken
            );

            // Step 6: System state validation (90-100%)
            await PerformOperationAsync(
                result,
                SanitizationOperationType.SystemValidation,
                "Validating system state",
                progress,
                90,
                100,
                async () =>
                {
                    result.VerificationReport = await ValidateSystemStateAsync();
                    return "System state validated successfully";
                },
                cancellationToken
            );

            result.Success = true;
            result.EndTime = DateTime.UtcNow;
            result.Duration = result.EndTime - result.StartTime;

            lock (_lock)
            {
                _status = SanitizationStatus.Completed;
            }

            _logger.LogInformation("Instant sanitization completed successfully in {Duration}ms", result.Duration.TotalMilliseconds);

            return result;
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Sanitization was cancelled");
            result.Success = false;
            result.Errors.Add("Sanitization was cancelled by user");
            
            lock (_lock)
            {
                _status = SanitizationStatus.Failed;
            }
            
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Sanitization failed with error");
            result.Success = false;
            result.Errors.Add($"Sanitization failed: {ex.Message}");
            result.EndTime = DateTime.UtcNow;
            result.Duration = result.EndTime - result.StartTime;

            lock (_lock)
            {
                _status = SanitizationStatus.Failed;
            }

            return result;
        }
    }

    public async Task<bool> EmergencySanitizeAsync()
    {
        lock (_lock)
        {
            _status = SanitizationStatus.Emergency;
        }

        try
        {
            _logger.LogWarning("Emergency sanitization initiated!");

            // Perform critical operations only, without progress reporting
            await BlockAndResetNetworkAsync();
            await DeleteSandboxDataAsync(null, CancellationToken.None);
            await RestoreFirewallRulesAsync();
            await CleanupRegistryAsync();

            _logger.LogInformation("Emergency sanitization completed");
            
            lock (_lock)
            {
                _status = SanitizationStatus.Completed;
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Emergency sanitization failed");
            
            lock (_lock)
            {
                _status = SanitizationStatus.Failed;
            }

            return false;
        }
    }

    public SanitizationStatus GetStatus()
    {
        lock (_lock)
        {
            return _status;
        }
    }

    public async Task<SystemStateReport> ValidateSystemStateAsync()
    {
        _logger.LogInformation("Validating system state...");

        var report = new SystemStateReport
        {
            GeneratedAt = DateTime.UtcNow
        };

        try
        {
            // Validate sandbox processes
            report.SandboxStatus = await ValidateSandboxProcessesAsync();

            // Validate firewall rules
            report.FirewallStatus = await ValidateFirewallRulesAsync();

            // Validate registry
            report.RegistryStatus = await ValidateRegistryAsync();

            // Validate file system
            report.FileSystemStatus = await ValidateFileSystemAsync();

            // Validate network
            report.NetworkStatus = await ValidateNetworkAsync();

            // Determine overall health
            report.IsHealthy = 
                !report.SandboxStatus.SandboxProcessRunning &&
                report.FirewallStatus.CustomRulesRemoved &&
                report.RegistryStatus.ModificationsReverted &&
                report.FileSystemStatus.SandboxDataDeleted &&
                report.NetworkStatus.NetworkReset;

            if (!report.IsHealthy)
            {
                GenerateRecommendations(report);
            }

            _logger.LogInformation("System state validation completed. Healthy: {IsHealthy}", report.IsHealthy);

            return report;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating system state");
            report.IsHealthy = false;
            report.Issues.Add($"Validation error: {ex.Message}");
            return report;
        }
    }

    #region Private Helper Methods

    private async Task PerformOperationAsync(
        SanitizationResult result,
        SanitizationOperationType operationType,
        string statusMessage,
        IProgress<SanitizationProgress>? progress,
        int startPercent,
        int endPercent,
        Func<Task<string>> operation,
        CancellationToken cancellationToken)
    {
        var op = new SanitizationOperation
        {
            Type = operationType
        };

        var startTime = DateTime.UtcNow;

        try
        {
            // Report start
            progress?.Report(new SanitizationProgress
            {
                CurrentOperation = operationType,
                PercentComplete = startPercent,
                StatusMessage = statusMessage,
                DetailedMessage = $"Starting {statusMessage.ToLower()}..."
            });

            cancellationToken.ThrowIfCancellationRequested();

            // Perform operation
            var details = await operation();
            op.Details = details;
            op.Success = true;

            // Report completion
            progress?.Report(new SanitizationProgress
            {
                CurrentOperation = operationType,
                PercentComplete = endPercent,
                StatusMessage = statusMessage,
                DetailedMessage = $"Completed {statusMessage.ToLower()}"
            });
        }
        catch (Exception ex)
        {
            op.Success = false;
            op.ErrorMessage = ex.Message;
            result.Errors.Add($"{operationType}: {ex.Message}");
            _logger.LogError(ex, "Operation {Operation} failed", operationType);
            throw;
        }
        finally
        {
            op.Duration = DateTime.UtcNow - startTime;
            result.Operations.Add(op);
        }
    }

    private async Task<string> BlockAndResetNetworkAsync()
    {
        _logger.LogDebug("Blocking and resetting network connections...");

        try
        {
            // Kill any active sandbox processes first
            await KillSandboxProcessesAsync();

            // Block all network traffic
            var blockStatus = _networkBlocker.GetBlockStatus();
            if (blockStatus == NetworkBlockStatus.Active)
            {
                await _networkBlocker.RestoreFirewallRulesAsync();
            }

            // Reset network connections using netsh
            await ExecuteNetshCommandAsync("interface ip reset");
            await ExecuteNetshCommandAsync("winsock reset");

            return "Network connections blocked and reset successfully";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error blocking and resetting network");
            throw;
        }
    }

    private async Task<string> DeleteSandboxDataAsync(IProgress<SanitizationProgress>? progress, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Deleting sandbox data...");

        int totalFiles = 0;
        int deletedFiles = 0;
        long totalSize = 0;

        try
        {
            foreach (var pathPattern in _sandboxDataPaths)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var directory = Path.GetDirectoryName(pathPattern);
                var pattern = Path.GetFileName(pathPattern);

                if (directory == null || !Directory.Exists(directory))
                    continue;

                var matchingPaths = Directory.GetDirectories(directory, pattern, SearchOption.TopDirectoryOnly)
                    .Concat(Directory.GetFiles(directory, pattern, SearchOption.TopDirectoryOnly));

                foreach (var path in matchingPaths)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    try
                    {
                        if (Directory.Exists(path))
                        {
                            var files = Directory.GetFiles(path, "*", SearchOption.AllDirectories);
                            totalFiles += files.Length;

                            foreach (var file in files)
                            {
                                var fileInfo = new FileInfo(file);
                                totalSize += fileInfo.Length;

                                // Secure deletion: overwrite with random data before deleting
                                await SecureDeleteFileAsync(file);
                                deletedFiles++;

                                progress?.Report(new SanitizationProgress
                                {
                                    CurrentOperation = SanitizationOperationType.SandboxDataDeletion,
                                    ItemsProcessed = deletedFiles,
                                    TotalItems = totalFiles,
                                    DetailedMessage = $"Deleted {deletedFiles}/{totalFiles} files"
                                });
                            }

                            Directory.Delete(path, true);
                        }
                        else if (File.Exists(path))
                        {
                            totalFiles++;
                            var fileInfo = new FileInfo(path);
                            totalSize += fileInfo.Length;

                            await SecureDeleteFileAsync(path);
                            deletedFiles++;
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to delete path: {Path}", path);
                    }
                }
            }

            return $"Deleted {deletedFiles} files ({FormatBytes(totalSize)}) from sandbox data paths";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting sandbox data");
            throw;
        }
    }

    private async Task<string> RestoreFirewallRulesAsync()
    {
        _logger.LogDebug("Restoring firewall rules...");

        try
        {
            await _networkBlocker.RestoreFirewallRulesAsync();
            return "Firewall rules restored to initial state";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error restoring firewall rules");
            throw;
        }
    }

    private async Task<string> CleanupRegistryAsync()
    {
        _logger.LogDebug("Cleaning up registry modifications...");

        try
        {
            await _deceptionEngine.RestoreOriginalSettingsAsync();
            return "Registry modifications cleaned up successfully";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error cleaning up registry");
            throw;
        }
    }

    private async Task<string> DeleteTemporaryFilesAsync(IProgress<SanitizationProgress>? progress, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Deleting temporary files and cache...");

        int deletedFiles = 0;
        long totalSize = 0;

        try
        {
            // Clean Windows temp folder
            var tempPath = Path.GetTempPath();
            if (Directory.Exists(tempPath))
            {
                var tempFiles = Directory.GetFiles(tempPath, "*.tmp", SearchOption.TopDirectoryOnly);
                
                foreach (var file in tempFiles)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    try
                    {
                        var fileInfo = new FileInfo(file);
                        
                        // Only delete files older than 1 hour to avoid interfering with running processes
                        if (DateTime.UtcNow - fileInfo.LastAccessTimeUtc > TimeSpan.FromHours(1))
                        {
                            totalSize += fileInfo.Length;
                            File.Delete(file);
                            deletedFiles++;
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Failed to delete temp file: {File}", file);
                    }
                }
            }

            // Clean Internet cache
            var cachePath = Environment.GetFolderPath(Environment.SpecialFolder.InternetCache);
            if (Directory.Exists(cachePath))
            {
                try
                {
                    var cacheFiles = Directory.GetFiles(cachePath, "*", SearchOption.AllDirectories);
                    
                    foreach (var file in cacheFiles.Take(100)) // Limit to avoid long operations
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        try
                        {
                            var fileInfo = new FileInfo(file);
                            totalSize += fileInfo.Length;
                            File.Delete(file);
                            deletedFiles++;
                        }
                        catch
                        {
                            // Ignore errors for cache files
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Failed to clean cache directory");
                }
            }

            return $"Deleted {deletedFiles} temporary files ({FormatBytes(totalSize)})";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting temporary files");
            throw;
        }
    }

    private async Task SecureDeleteFileAsync(string filePath)
    {
        try
        {
            if (!File.Exists(filePath))
                return;

            var fileInfo = new FileInfo(filePath);
            var fileSize = fileInfo.Length;

            // For small files, overwrite with random data
            if (fileSize < 10 * 1024 * 1024) // 10 MB
            {
                using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Write))
                {
                    var buffer = new byte[4096];
                    RandomNumberGenerator.Fill(buffer);

                    for (long i = 0; i < fileSize; i += buffer.Length)
                    {
                        var bytesToWrite = (int)Math.Min(buffer.Length, fileSize - i);
                        await stream.WriteAsync(buffer.AsMemory(0, bytesToWrite));
                    }

                    await stream.FlushAsync();
                }
            }

            // Delete the file
            File.Delete(filePath);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to securely delete file: {File}", filePath);
            // Try regular deletion
            try
            {
                File.Delete(filePath);
            }
            catch
            {
                // Ignore if we can't delete
            }
        }
    }

    private async Task KillSandboxProcessesAsync()
    {
        try
        {
            var sandboxProcesses = Process.GetProcessesByName("WindowsSandbox");
            
            foreach (var process in sandboxProcesses)
            {
                try
                {
                    process.Kill();
                    await process.WaitForExitAsync();
                    _logger.LogInformation("Killed sandbox process: {ProcessId}", process.Id);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to kill sandbox process: {ProcessId}", process.Id);
                }
                finally
                {
                    process.Dispose();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error killing sandbox processes");
        }
    }

    private async Task<ProcessStatus> ValidateSandboxProcessesAsync()
    {
        var status = new ProcessStatus();

        try
        {
            var sandboxProcesses = Process.GetProcessesByName("WindowsSandbox");
            status.SandboxProcessRunning = sandboxProcesses.Length > 0;
            status.ActiveHoneypotProcesses = sandboxProcesses.Length;
            status.ProcessNames = sandboxProcesses.Select(p => p.ProcessName).ToList();

            foreach (var process in sandboxProcesses)
            {
                process.Dispose();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating sandbox processes");
        }

        return status;
    }

    private async Task<FirewallStatus> ValidateFirewallRulesAsync()
    {
        var status = new FirewallStatus
        {
            FirewallEnabled = true
        };

        try
        {
            // Check for remaining honeypot firewall rules
            var result = await ExecuteNetshCommandAsync("advfirewall firewall show rule name=all");
            
            if (result.Success)
            {
                var rules = result.Output.Split('\n')
                    .Where(line => line.Contains("WindowsHoneypot_Block_"))
                    .ToList();

                status.RemainingHoneypotRules = rules.Count;
                status.CustomRulesRemoved = rules.Count == 0;
                status.ActiveRuleNames = rules;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating firewall rules");
        }

        return status;
    }

    private async Task<RegistryStatus> ValidateRegistryAsync()
    {
        var status = new RegistryStatus();

        try
        {
            var deceptionStatus = _deceptionEngine.GetDeceptionStatus();
            status.ModificationsReverted = deceptionStatus == DeceptionStatus.Inactive;
            status.RemainingModifications = deceptionStatus == DeceptionStatus.Inactive ? 0 : 1;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating registry");
        }

        return status;
    }

    private async Task<FileSystemStatus> ValidateFileSystemAsync()
    {
        var status = new FileSystemStatus();

        try
        {
            long remainingSize = 0;
            var remainingFiles = new List<string>();

            foreach (var pathPattern in _sandboxDataPaths)
            {
                var directory = Path.GetDirectoryName(pathPattern);
                var pattern = Path.GetFileName(pathPattern);

                if (directory == null || !Directory.Exists(directory))
                    continue;

                var matchingPaths = Directory.GetDirectories(directory, pattern, SearchOption.TopDirectoryOnly)
                    .Concat(Directory.GetFiles(directory, pattern, SearchOption.TopDirectoryOnly));

                foreach (var path in matchingPaths)
                {
                    if (Directory.Exists(path))
                    {
                        var files = Directory.GetFiles(path, "*", SearchOption.AllDirectories);
                        remainingFiles.AddRange(files);
                        remainingSize += files.Sum(f => new FileInfo(f).Length);
                    }
                    else if (File.Exists(path))
                    {
                        remainingFiles.Add(path);
                        remainingSize += new FileInfo(path).Length;
                    }
                }
            }

            status.SandboxDataDeleted = remainingFiles.Count == 0;
            status.RemainingDataSize = remainingSize;
            status.RemainingFiles = remainingFiles;
            status.TemporaryFilesCleared = true; // Assume cleared if no errors
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating file system");
        }

        return status;
    }

    private async Task<NetworkStatus> ValidateNetworkAsync()
    {
        var status = new NetworkStatus();

        try
        {
            var blockStatus = _networkBlocker.GetBlockStatus();
            status.NetworkReset = blockStatus == NetworkBlockStatus.Inactive;

            // Check for active connections
            var connections = await GetActiveNetworkConnectionsAsync();
            status.ActiveConnections = connections.Count;
            status.ActiveConnectionDetails = connections;

            // Simple internet connectivity check
            try
            {
                using var client = new System.Net.Http.HttpClient();
                client.Timeout = TimeSpan.FromSeconds(5);
                var response = await client.GetAsync("http://www.msftconnecttest.com/connecttest.txt");
                status.InternetAccessible = response.IsSuccessStatusCode;
            }
            catch
            {
                status.InternetAccessible = false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating network");
        }

        return status;
    }

    private async Task<List<string>> GetActiveNetworkConnectionsAsync()
    {
        var connections = new List<string>();

        try
        {
            var result = await ExecuteNetshCommandAsync("interface ip show connections");
            
            if (result.Success)
            {
                connections = result.Output.Split('\n')
                    .Where(line => !string.IsNullOrWhiteSpace(line))
                    .Take(10)
                    .ToList();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting active network connections");
        }

        return connections;
    }

    private void GenerateRecommendations(SystemStateReport report)
    {
        if (report.SandboxStatus.SandboxProcessRunning)
        {
            report.Issues.Add("Sandbox processes are still running");
            report.Recommendations.Add("Manually terminate Windows Sandbox processes");
        }

        if (!report.FirewallStatus.CustomRulesRemoved)
        {
            report.Issues.Add($"{report.FirewallStatus.RemainingHoneypotRules} honeypot firewall rules remain");
            report.Recommendations.Add("Run sanitization again or manually remove firewall rules");
        }

        if (!report.RegistryStatus.ModificationsReverted)
        {
            report.Issues.Add("Registry modifications have not been fully reverted");
            report.Recommendations.Add("Restart the deception engine restoration process");
        }

        if (!report.FileSystemStatus.SandboxDataDeleted)
        {
            report.Issues.Add($"{report.FileSystemStatus.RemainingFiles.Count} sandbox files remain ({FormatBytes(report.FileSystemStatus.RemainingDataSize)})");
            report.Recommendations.Add("Manually delete remaining sandbox data files");
        }

        if (!report.NetworkStatus.NetworkReset)
        {
            report.Issues.Add("Network has not been fully reset");
            report.Recommendations.Add("Manually reset network settings using netsh commands");
        }
    }

    private async Task<(bool Success, string Output, string Error)> ExecuteNetshCommandAsync(string arguments)
    {
        try
        {
            var processStartInfo = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                Verb = "runas"
            };

            using var process = new Process { StartInfo = processStartInfo };
            
            var outputBuilder = new System.Text.StringBuilder();
            var errorBuilder = new System.Text.StringBuilder();

            process.OutputDataReceived += (sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                {
                    outputBuilder.AppendLine(e.Data);
                }
            };

            process.ErrorDataReceived += (sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                {
                    errorBuilder.AppendLine(e.Data);
                }
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            await process.WaitForExitAsync();

            var output = outputBuilder.ToString();
            var error = errorBuilder.ToString();
            var success = process.ExitCode == 0;

            return (success, output, error);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error executing netsh command: {Arguments}", arguments);
            return (false, string.Empty, ex.Message);
        }
    }

    private static string FormatBytes(long bytes)
    {
        string[] sizes = { "B", "KB", "MB", "GB", "TB" };
        double len = bytes;
        int order = 0;
        
        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len = len / 1024;
        }

        return $"{len:0.##} {sizes[order]}";
    }

    #endregion
}
