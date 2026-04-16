using System.Diagnostics;
using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Tracks and manages Windows Sandbox process lifecycle
/// </summary>
public class ProcessTracker : IDisposable
{
    private readonly ILogger<ProcessTracker> _logger;
    private Process? _sandboxProcess;
    private int? _sandboxProcessId;
    private bool _isTracking;
    private readonly object _lockObject = new();
    private CancellationTokenSource? _monitoringCts;
    private Task? _monitoringTask;

    public ProcessTracker(ILogger<ProcessTracker> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Gets the current sandbox process ID if tracking
    /// </summary>
    public int? SandboxProcessId
    {
        get
        {
            lock (_lockObject)
            {
                return _sandboxProcessId;
            }
        }
    }

    /// <summary>
    /// Gets whether the tracker is currently monitoring a process
    /// </summary>
    public bool IsTracking
    {
        get
        {
            lock (_lockObject)
            {
                return _isTracking;
            }
        }
    }

    /// <summary>
    /// Event fired when the sandbox process exits
    /// </summary>
    public event EventHandler<ProcessExitedEventArgs>? ProcessExited;

    /// <summary>
    /// Starts tracking a sandbox process by launching it
    /// </summary>
    /// <param name="wsbFilePath">Path to the .wsb configuration file</param>
    /// <returns>True if process started successfully and tracking began</returns>
    public async Task<bool> StartTrackingAsync(string wsbFilePath)
    {
        if (string.IsNullOrWhiteSpace(wsbFilePath))
            throw new ArgumentException("WSB file path cannot be null or empty", nameof(wsbFilePath));

        if (!File.Exists(wsbFilePath))
            throw new FileNotFoundException("WSB file not found", wsbFilePath);

        lock (_lockObject)
        {
            if (_isTracking)
            {
                _logger.LogWarning("Already tracking a sandbox process (PID: {ProcessId})", _sandboxProcessId);
                return false;
            }
        }

        try
        {
            _logger.LogInformation("Starting Windows Sandbox with configuration: {WsbFile}", wsbFilePath);

            // Create process start info for Windows Sandbox
            var startInfo = new ProcessStartInfo
            {
                FileName = wsbFilePath,
                UseShellExecute = true, // Required to launch .wsb files
                CreateNoWindow = false
            };

            // Start the process
            var process = Process.Start(startInfo);
            if (process == null)
            {
                _logger.LogError("Failed to start Windows Sandbox process");
                return false;
            }

            // Wait a moment for the process to initialize
            await Task.Delay(500);

            // Find the actual WindowsSandbox.exe process
            var sandboxProcess = await FindSandboxProcessAsync();
            if (sandboxProcess == null)
            {
                _logger.LogError("Could not find Windows Sandbox process after launch");
                return false;
            }

            lock (_lockObject)
            {
                _sandboxProcess = sandboxProcess;
                _sandboxProcessId = sandboxProcess.Id;
                _isTracking = true;
            }

            _logger.LogInformation("Successfully started tracking Windows Sandbox process (PID: {ProcessId})", _sandboxProcessId);

            // Start monitoring the process
            StartProcessMonitoring();

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error starting Windows Sandbox process");
            return false;
        }
    }

    /// <summary>
    /// Starts tracking an existing sandbox process by process ID
    /// </summary>
    /// <param name="processId">Process ID to track</param>
    /// <returns>True if tracking started successfully</returns>
    public bool StartTrackingExisting(int processId)
    {
        if (processId <= 0)
            throw new ArgumentException("Process ID must be positive", nameof(processId));

        lock (_lockObject)
        {
            if (_isTracking)
            {
                _logger.LogWarning("Already tracking a sandbox process (PID: {ProcessId})", _sandboxProcessId);
                return false;
            }
        }

        try
        {
            var process = Process.GetProcessById(processId);
            
            // Verify it's a Windows Sandbox process
            if (!process.ProcessName.Equals("WindowsSandbox", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Process {ProcessId} is not a Windows Sandbox process (Name: {ProcessName})", 
                    processId, process.ProcessName);
                return false;
            }

            lock (_lockObject)
            {
                _sandboxProcess = process;
                _sandboxProcessId = processId;
                _isTracking = true;
            }

            _logger.LogInformation("Successfully started tracking existing Windows Sandbox process (PID: {ProcessId})", processId);

            // Start monitoring the process
            StartProcessMonitoring();

            return true;
        }
        catch (ArgumentException)
        {
            _logger.LogError("Process with ID {ProcessId} not found", processId);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error tracking existing process {ProcessId}", processId);
            return false;
        }
    }

    /// <summary>
    /// Stops tracking and forcefully terminates the sandbox process
    /// </summary>
    /// <returns>True if process was stopped successfully</returns>
    public async Task<bool> StopTrackingAsync()
    {
        Process? processToKill;
        int? processId;

        lock (_lockObject)
        {
            if (!_isTracking)
            {
                _logger.LogInformation("No sandbox process is currently being tracked");
                return true;
            }

            processToKill = _sandboxProcess;
            processId = _sandboxProcessId;
        }

        try
        {
            // Stop monitoring
            await StopProcessMonitoringAsync();

            if (processToKill != null && !processToKill.HasExited)
            {
                _logger.LogInformation("Terminating Windows Sandbox process (PID: {ProcessId})", processId);

                // Try graceful close first
                processToKill.CloseMainWindow();
                
                // Wait up to 3 seconds for graceful shutdown
                if (!processToKill.WaitForExit(3000))
                {
                    _logger.LogWarning("Sandbox process did not exit gracefully, forcing termination");
                    processToKill.Kill(entireProcessTree: true);
                    
                    // Wait for forced termination
                    await Task.Run(() => processToKill.WaitForExit(5000));
                }

                _logger.LogInformation("Windows Sandbox process terminated successfully");
            }
            else
            {
                _logger.LogInformation("Windows Sandbox process already exited");
            }

            lock (_lockObject)
            {
                _sandboxProcess?.Dispose();
                _sandboxProcess = null;
                _sandboxProcessId = null;
                _isTracking = false;
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error stopping Windows Sandbox process");
            
            lock (_lockObject)
            {
                _sandboxProcess?.Dispose();
                _sandboxProcess = null;
                _sandboxProcessId = null;
                _isTracking = false;
            }

            return false;
        }
    }

    /// <summary>
    /// Checks if the tracked process is still running
    /// </summary>
    /// <returns>True if process is running, false otherwise</returns>
    public bool IsProcessRunning()
    {
        lock (_lockObject)
        {
            if (!_isTracking || _sandboxProcess == null)
                return false;

            try
            {
                return !_sandboxProcess.HasExited;
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Gets information about the tracked process
    /// </summary>
    /// <returns>Process information or null if not tracking</returns>
    public ProcessInfo? GetProcessInfo()
    {
        lock (_lockObject)
        {
            if (!_isTracking || _sandboxProcess == null || _sandboxProcessId == null)
                return null;

            try
            {
                if (_sandboxProcess.HasExited)
                    return null;

                return new ProcessInfo
                {
                    ProcessId = _sandboxProcessId.Value,
                    ProcessName = _sandboxProcess.ProcessName,
                    StartTime = _sandboxProcess.StartTime,
                    IsRunning = !_sandboxProcess.HasExited
                };
            }
            catch
            {
                return null;
            }
        }
    }

    /// <summary>
    /// Finds the Windows Sandbox process
    /// </summary>
    private async Task<Process?> FindSandboxProcessAsync()
    {
        // Try multiple times with delays to allow process to start
        for (int attempt = 0; attempt < 10; attempt++)
        {
            var processes = Process.GetProcessesByName("WindowsSandbox");
            if (processes.Length > 0)
            {
                // Return the most recently started process
                return processes.OrderByDescending(p => p.StartTime).FirstOrDefault();
            }

            await Task.Delay(500);
        }

        return null;
    }

    /// <summary>
    /// Starts background monitoring of the process
    /// </summary>
    private void StartProcessMonitoring()
    {
        _monitoringCts = new CancellationTokenSource();
        _monitoringTask = Task.Run(async () => await MonitorProcessAsync(_monitoringCts.Token));
    }

    /// <summary>
    /// Stops background monitoring
    /// </summary>
    private async Task StopProcessMonitoringAsync()
    {
        if (_monitoringCts != null)
        {
            _monitoringCts.Cancel();
            
            if (_monitoringTask != null)
            {
                try
                {
                    await _monitoringTask;
                }
                catch (OperationCanceledException)
                {
                    // Expected when cancelling
                }
            }

            _monitoringCts.Dispose();
            _monitoringCts = null;
            _monitoringTask = null;
        }
    }

    /// <summary>
    /// Background task that monitors the process
    /// </summary>
    private async Task MonitorProcessAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                Process? process;
                int? processId;

                lock (_lockObject)
                {
                    process = _sandboxProcess;
                    processId = _sandboxProcessId;
                }

                if (process != null)
                {
                    try
                    {
                        if (process.HasExited)
                        {
                            _logger.LogInformation("Windows Sandbox process (PID: {ProcessId}) has exited", processId);
                            
                            // Fire exit event
                            ProcessExited?.Invoke(this, new ProcessExitedEventArgs
                            {
                                ProcessId = processId ?? 0,
                                ExitTime = DateTime.UtcNow
                            });

                            lock (_lockObject)
                            {
                                _isTracking = false;
                                _sandboxProcess = null;
                                _sandboxProcessId = null;
                            }

                            break;
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error checking process status");
                    }
                }

                await Task.Delay(1000, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("Process monitoring cancelled");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in process monitoring loop");
        }
    }

    public void Dispose()
    {
        StopProcessMonitoringAsync().GetAwaiter().GetResult();
        
        lock (_lockObject)
        {
            _sandboxProcess?.Dispose();
            _sandboxProcess = null;
        }

        _monitoringCts?.Dispose();
    }
}
