using System.Collections.Concurrent;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Monitors sandbox processes for privilege escalation and escape attempts
/// Implements Requirements 8.1, 8.2, 8.3, 8.4, 8.5
/// </summary>
public class PrivilegeMonitor : IDisposable
{
    private readonly ILogger<PrivilegeMonitor> _logger;
    private readonly ConcurrentBag<AttackEvent> _detectedAttempts;
    private readonly object _lock = new();
    private bool _isMonitoring;
    private bool _disposed;
    private CancellationTokenSource? _cancellationTokenSource;
    private Task? _monitoringTask;
    private readonly HashSet<int> _monitoredProcessIds;
    private readonly HashSet<string> _suspiciousSystemCalls;

    // P/Invoke declarations for process monitoring
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private const uint TOKEN_QUERY = 0x0008;
    private const int TokenElevation = 20;

    public event EventHandler<AttackEvent>? PrivilegeEscalationDetected;
    public event EventHandler<AttackEvent>? SandboxEscapeDetected;

    public PrivilegeMonitor(ILogger<PrivilegeMonitor> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _detectedAttempts = new ConcurrentBag<AttackEvent>();
        _monitoredProcessIds = new HashSet<int>();
        _suspiciousSystemCalls = new HashSet<string>
        {
            "CreateRemoteThread",
            "WriteProcessMemory",
            "VirtualAllocEx",
            "SetWindowsHookEx",
            "NtQuerySystemInformation",
            "ZwQuerySystemInformation"
        };
    }

    /// <summary>
    /// Starts monitoring sandbox processes for privilege escalation and escape attempts
    /// </summary>
    public void StartMonitoring(IEnumerable<int> sandboxProcessIds)
    {
        lock (_lock)
        {
            if (_isMonitoring)
            {
                _logger.LogWarning("Privilege monitoring is already active");
                return;
            }

            _monitoredProcessIds.Clear();
            foreach (var pid in sandboxProcessIds)
            {
                _monitoredProcessIds.Add(pid);
            }

            _cancellationTokenSource = new CancellationTokenSource();
            _isMonitoring = true;
        }

        _logger.LogInformation("Starting privilege monitoring for {Count} processes", _monitoredProcessIds.Count);

        _monitoringTask = Task.Run(() => MonitorProcessesAsync(_cancellationTokenSource.Token), _cancellationTokenSource.Token);
    }

    /// <summary>
    /// Stops monitoring sandbox processes
    /// </summary>
    public void StopMonitoring()
    {
        lock (_lock)
        {
            if (!_isMonitoring)
            {
                return;
            }

            _isMonitoring = false;
        }

        _logger.LogInformation("Stopping privilege monitoring");

        _cancellationTokenSource?.Cancel();
        
        try
        {
            _monitoringTask?.Wait(TimeSpan.FromSeconds(5));
        }
        catch (AggregateException ex) when (ex.InnerException is TaskCanceledException)
        {
            // Expected when cancelling
        }

        _cancellationTokenSource?.Dispose();
        _cancellationTokenSource = null;
        _monitoringTask = null;
    }

    /// <summary>
    /// Gets all detected privilege escalation and escape attempts
    /// </summary>
    public List<AttackEvent> GetDetectedAttempts()
    {
        return _detectedAttempts.ToList();
    }

    /// <summary>
    /// Main monitoring loop that checks for suspicious activities
    /// </summary>
    private async Task MonitorProcessesAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Privilege monitoring loop started");

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                // Check for privilege escalation attempts
                await CheckPrivilegeEscalationAsync(cancellationToken);

                // Check for sandbox escape attempts
                await CheckSandboxEscapeAttemptsAsync(cancellationToken);

                // Check for suspicious system calls
                await CheckSuspiciousSystemCallsAsync(cancellationToken);

                // Wait before next check
                await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in privilege monitoring loop");
                await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
            }
        }

        _logger.LogInformation("Privilege monitoring loop stopped");
    }

    /// <summary>
    /// Checks for privilege escalation attempts in monitored processes
    /// </summary>
    private async Task CheckPrivilegeEscalationAsync(CancellationToken cancellationToken)
    {
        await Task.Run(() =>
        {
            List<int> processIds;
            lock (_lock)
            {
                processIds = new List<int>(_monitoredProcessIds);
            }

            foreach (var pid in processIds)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                try
                {
                    var process = Process.GetProcessById(pid);
                    
                    // Check if process is running with elevated privileges
                    if (IsProcessElevated(process))
                    {
                        var attackEvent = new AttackEvent
                        {
                            EventType = AttackEventType.PrivilegeEscalation,
                            SourceProcess = process.ProcessName,
                            ProcessId = pid,
                            Description = $"Privilege escalation detected: Process {process.ProcessName} (PID: {pid}) is running with elevated privileges",
                            Severity = ThreatSeverity.High,
                            Metadata = new Dictionary<string, object>
                            {
                                ["ProcessPath"] = process.MainModule?.FileName ?? "Unknown",
                                ["StartTime"] = process.StartTime,
                                ["IsElevated"] = true
                            }
                        };

                        _detectedAttempts.Add(attackEvent);
                        _logger.LogWarning("Privilege escalation detected: {ProcessName} (PID: {ProcessId})", process.ProcessName, pid);
                        
                        PrivilegeEscalationDetected?.Invoke(this, attackEvent);

                        // Terminate the process
                        TerminateProcess(process, "Privilege escalation attempt");
                    }
                }
                catch (ArgumentException)
                {
                    // Process no longer exists
                    lock (_lock)
                    {
                        _monitoredProcessIds.Remove(pid);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error checking privilege escalation for PID {ProcessId}", pid);
                }
            }
        }, cancellationToken);
    }

    /// <summary>
    /// Checks for sandbox escape attempts
    /// </summary>
    private async Task CheckSandboxEscapeAttemptsAsync(CancellationToken cancellationToken)
    {
        await Task.Run(() =>
        {
            try
            {
                // Use WMI to detect processes trying to access parent system
                using var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_Process WHERE Name LIKE '%sandbox%' OR Name LIKE '%vm%'"
                );

                foreach (ManagementObject obj in searcher.Get())
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }

                    var processId = Convert.ToInt32(obj["ProcessId"]);
                    var processName = obj["Name"]?.ToString() ?? "Unknown";
                    var commandLine = obj["CommandLine"]?.ToString() ?? string.Empty;

                    // Check if process is trying to escape sandbox
                    if (IsSandboxEscapeAttempt(commandLine))
                    {
                        var attackEvent = new AttackEvent
                        {
                            EventType = AttackEventType.SandboxEscape,
                            SourceProcess = processName,
                            ProcessId = processId,
                            Description = $"Sandbox escape attempt detected: {processName} (PID: {processId})",
                            Severity = ThreatSeverity.Critical,
                            Metadata = new Dictionary<string, object>
                            {
                                ["CommandLine"] = commandLine,
                                ["DetectionMethod"] = "Command line analysis"
                            }
                        };

                        _detectedAttempts.Add(attackEvent);
                        _logger.LogCritical("Sandbox escape attempt detected: {ProcessName} (PID: {ProcessId})", processName, processId);
                        
                        SandboxEscapeDetected?.Invoke(this, attackEvent);

                        // Terminate the process immediately
                        try
                        {
                            var process = Process.GetProcessById(processId);
                            TerminateProcess(process, "Sandbox escape attempt");
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "Failed to terminate escaping process {ProcessId}", processId);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking sandbox escape attempts");
            }
        }, cancellationToken);
    }

    /// <summary>
    /// Checks for suspicious system calls that might indicate escape attempts
    /// </summary>
    private async Task CheckSuspiciousSystemCallsAsync(CancellationToken cancellationToken)
    {
        await Task.Run(() =>
        {
            // This is a simplified check - in production, you would use ETW or kernel-level monitoring
            // For now, we log that we're monitoring for suspicious calls
            _logger.LogDebug("Monitoring for suspicious system calls");
        }, cancellationToken);
    }

    /// <summary>
    /// Checks if a process is running with elevated privileges
    /// </summary>
    private bool IsProcessElevated(Process process)
    {
        try
        {
            IntPtr tokenHandle;
            if (!OpenProcessToken(process.Handle, TOKEN_QUERY, out tokenHandle))
            {
                return false;
            }

            try
            {
                var elevationResult = Marshal.AllocHGlobal(sizeof(int));
                try
                {
                    uint returnedSize;
                    if (GetTokenInformation(tokenHandle, TokenElevation, elevationResult, sizeof(int), out returnedSize))
                    {
                        var elevation = Marshal.ReadInt32(elevationResult);
                        return elevation != 0;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(elevationResult);
                }
            }
            finally
            {
                CloseHandle(tokenHandle);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not check elevation status for process {ProcessId}", process.Id);
        }

        return false;
    }

    /// <summary>
    /// Determines if a command line indicates a sandbox escape attempt
    /// </summary>
    private bool IsSandboxEscapeAttempt(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return false;
        }

        var suspiciousPatterns = new[]
        {
            "\\\\?\\pipe\\",  // Named pipe access to host
            "\\\\localhost\\", // Network access to host
            "\\\\127.0.0.1\\", // Loopback access
            "vboxservice",     // VirtualBox service
            "vmtoolsd",        // VMware tools
            "qemu-ga",         // QEMU guest agent
            "sandbox-escape",  // Explicit escape attempt
            "breakout",        // Breakout attempt
            "privilege",       // Privilege manipulation
            "SeDebugPrivilege" // Debug privilege
        };

        var lowerCommandLine = commandLine.ToLowerInvariant();
        return suspiciousPatterns.Any(pattern => lowerCommandLine.Contains(pattern.ToLowerInvariant()));
    }

    /// <summary>
    /// Terminates a process that attempted privilege escalation or sandbox escape
    /// </summary>
    private void TerminateProcess(Process process, string reason)
    {
        try
        {
            _logger.LogWarning("Terminating process {ProcessName} (PID: {ProcessId}) - Reason: {Reason}", 
                process.ProcessName, process.Id, reason);

            process.Kill(entireProcessTree: true);
            
            _logger.LogInformation("Successfully terminated process {ProcessName} (PID: {ProcessId})", 
                process.ProcessName, process.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to terminate process {ProcessName} (PID: {ProcessId})", 
                process.ProcessName, process.Id);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        StopMonitoring();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
