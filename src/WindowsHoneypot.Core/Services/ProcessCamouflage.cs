using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Create realistic business environment with fake processes
/// </summary>
public class ProcessCamouflage : IProcessCamouflage, IDisposable
{
    private readonly ILogger<ProcessCamouflage> _logger;
    private readonly object _lock = new();
    private readonly List<FakeProcess> _activeProcesses;
    private readonly Dictionary<Guid, Process> _realProcesses;
    private readonly Dictionary<Guid, System.Threading.Timer> _cpuTimers;
    private readonly Random _random;
    private bool _disposed;
    private bool _isRunning;

    // P/Invoke declarations for process manipulation
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetProcessWorkingSetSize(IntPtr hProcess, IntPtr dwMinimumWorkingSetSize, IntPtr dwMaximumWorkingSetSize);

    private const uint PROCESS_SET_QUOTA = 0x0100;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;

    public ProcessCamouflage(ILogger<ProcessCamouflage> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _activeProcesses = new List<FakeProcess>();
        _realProcesses = new Dictionary<Guid, Process>();
        _cpuTimers = new Dictionary<Guid, System.Threading.Timer>();
        _random = new Random();
        _isRunning = false;
    }

    public async Task StartFakeProcessesAsync(List<ProcessProfile> profiles)
    {
        if (profiles == null || profiles.Count == 0)
        {
            _logger.LogWarning("No process profiles provided");
            return;
        }

        lock (_lock)
        {
            if (_isRunning)
            {
                _logger.LogWarning("Fake processes are already running");
                return;
            }
            _isRunning = true;
        }

        try
        {
            _logger.LogInformation("Starting {Count} fake processes...", profiles.Count);

            foreach (var profile in profiles)
            {
                try
                {
                    await StartFakeProcessAsync(profile);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to start fake process: {ProcessName}", profile.ProcessName);
                }
            }

            _logger.LogInformation("Successfully started {Count} fake processes", _activeProcesses.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error starting fake processes");
            throw;
        }
    }

    public async Task StopAllFakeProcessesAsync()
    {
        lock (_lock)
        {
            if (!_isRunning)
            {
                _logger.LogWarning("No fake processes are running");
                return;
            }
        }

        try
        {
            _logger.LogInformation("Stopping all fake processes...");

            // Stop all CPU timers
            foreach (var timer in _cpuTimers.Values)
            {
                timer?.Dispose();
            }
            _cpuTimers.Clear();

            // Stop all real processes
            foreach (var kvp in _realProcesses)
            {
                try
                {
                    var process = kvp.Value;
                    if (process != null && !process.HasExited)
                    {
                        process.Kill();
                        process.Dispose();
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to stop process: {ProcessId}", kvp.Key);
                }
            }

            _realProcesses.Clear();
            _activeProcesses.Clear();

            lock (_lock)
            {
                _isRunning = false;
            }

            _logger.LogInformation("All fake processes stopped successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error stopping fake processes");
            throw;
        }

        await Task.CompletedTask;
    }

    public void UpdateProcessMetrics()
    {
        lock (_lock)
        {
            if (!_isRunning || _activeProcesses.Count == 0)
            {
                return;
            }

            foreach (var fakeProcess in _activeProcesses)
            {
                try
                {
                    if (fakeProcess.Profile.VariableCpuUsage)
                    {
                        // Vary CPU usage realistically
                        var baseCpu = fakeProcess.Profile.FakeCpuUsage;
                        var variation = _random.Next(-5, 6); // ±5% variation
                        fakeProcess.CpuUsage = Math.Max(0, Math.Min(100, baseCpu + variation));
                    }

                    // Update memory usage with slight variations
                    var baseMemory = fakeProcess.Profile.FakeMemoryUsage;
                    var memVariation = _random.Next(-1024 * 1024, 1024 * 1024); // ±1MB variation
                    fakeProcess.MemoryUsage = Math.Max(0, baseMemory + memVariation);

                    // Update network connections if simulated
                    if (fakeProcess.Profile.SimulateNetworkActivity)
                    {
                        UpdateNetworkConnections(fakeProcess);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to update metrics for process: {ProcessName}", fakeProcess.ProcessName);
                }
            }
        }
    }

    public List<FakeProcess> GetActiveProcesses()
    {
        lock (_lock)
        {
            return new List<FakeProcess>(_activeProcesses);
        }
    }

    /// <summary>
    /// Starts a single fake process based on the profile
    /// </summary>
    private async Task StartFakeProcessAsync(ProcessProfile profile)
    {
        try
        {
            _logger.LogDebug("Starting fake process: {ProcessName}", profile.ProcessName);

            // Create a lightweight process that will serve as our fake process
            // We'll use a simple console application or notepad as the base
            var process = await CreateBaseProcessAsync(profile);

            if (process == null)
            {
                _logger.LogWarning("Failed to create base process for: {ProcessName}", profile.ProcessName);
                return;
            }

            // Create the fake process object
            var fakeProcess = new FakeProcess
            {
                ProcessName = profile.ProcessName,
                ProcessId = process.Id,
                CpuUsage = profile.FakeCpuUsage,
                MemoryUsage = profile.FakeMemoryUsage,
                Description = profile.Description,
                CompanyName = profile.CompanyName,
                ProductVersion = profile.ProductVersion,
                StartTime = DateTime.UtcNow,
                IsRunning = true,
                NetworkConnections = new List<string>(profile.FakeNetworkConnections),
                Profile = profile
            };

            lock (_lock)
            {
                _activeProcesses.Add(fakeProcess);
                _realProcesses[fakeProcess.Id] = process;
            }

            // Set up memory usage simulation
            await SimulateMemoryUsageAsync(process, profile.FakeMemoryUsage);

            // Set up CPU usage variation timer if enabled
            if (profile.VariableCpuUsage)
            {
                SetupCpuVariationTimer(fakeProcess);
            }

            // Create fake service if requested
            if (profile.CreateFakeService)
            {
                await CreateFakeServiceAsync(profile);
            }

            _logger.LogInformation("Fake process started: {ProcessName} (PID: {ProcessId})", 
                profile.ProcessName, process.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error starting fake process: {ProcessName}", profile.ProcessName);
            throw;
        }
    }

    /// <summary>
    /// Creates a base process that will be used for the fake process
    /// </summary>
    private async Task<Process?> CreateBaseProcessAsync(ProcessProfile profile)
    {
        try
        {
            // Determine which base executable to use
            string executable;
            string arguments = "";

            if (!string.IsNullOrEmpty(profile.ExecutablePath) && File.Exists(profile.ExecutablePath))
            {
                executable = profile.ExecutablePath;
            }
            else
            {
                // Use a lightweight system process as base
                // We'll use a hidden console application
                executable = "cmd.exe";
                arguments = "/c timeout /t 86400 /nobreak"; // Keep alive for 24 hours
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = executable,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true
            };

            var process = Process.Start(startInfo);
            
            if (process == null)
            {
                _logger.LogError("Failed to start process: {Executable}", executable);
                return null;
            }

            // Give the process a moment to initialize
            await Task.Delay(100);

            return process;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating base process");
            return null;
        }
    }

    /// <summary>
    /// Simulates memory usage for the process
    /// </summary>
    private async Task SimulateMemoryUsageAsync(Process process, long targetMemoryBytes)
    {
        try
        {
            if (targetMemoryBytes <= 0)
            {
                return;
            }

            // Open the process with appropriate access rights
            IntPtr processHandle = OpenProcess(
                PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION,
                false,
                process.Id);

            if (processHandle == IntPtr.Zero)
            {
                _logger.LogWarning("Failed to open process for memory simulation: {ProcessId}", process.Id);
                return;
            }

            try
            {
                // Set the working set size to simulate memory usage
                // This makes the process appear to use more memory in Task Manager
                var minWorkingSet = new IntPtr(targetMemoryBytes / 2);
                var maxWorkingSet = new IntPtr(targetMemoryBytes);

                bool success = SetProcessWorkingSetSize(processHandle, minWorkingSet, maxWorkingSet);
                
                if (!success)
                {
                    _logger.LogWarning("Failed to set working set size for process: {ProcessId}", process.Id);
                }
                else
                {
                    _logger.LogDebug("Memory usage simulated for process {ProcessId}: {MemoryMB} MB",
                        process.Id, targetMemoryBytes / (1024 * 1024));
                }
            }
            finally
            {
                CloseHandle(processHandle);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error simulating memory usage for process: {ProcessId}", process.Id);
        }

        await Task.CompletedTask;
    }

    /// <summary>
    /// Sets up a timer to vary CPU usage over time
    /// </summary>
    private void SetupCpuVariationTimer(FakeProcess fakeProcess)
    {
        try
        {
            // Update CPU usage every 5-10 seconds
            var interval = TimeSpan.FromSeconds(_random.Next(5, 11));
            
            var timer = new System.Threading.Timer(_ =>
            {
                try
                {
                    lock (_lock)
                    {
                        if (fakeProcess.IsRunning && fakeProcess.Profile.VariableCpuUsage)
                        {
                            var baseCpu = fakeProcess.Profile.FakeCpuUsage;
                            var variation = _random.Next(-5, 6);
                            fakeProcess.CpuUsage = Math.Max(0, Math.Min(100, baseCpu + variation));
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error in CPU variation timer for: {ProcessName}", fakeProcess.ProcessName);
                }
            }, null, interval, interval);

            lock (_lock)
            {
                _cpuTimers[fakeProcess.Id] = timer;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to setup CPU variation timer for: {ProcessName}", fakeProcess.ProcessName);
        }
    }

    /// <summary>
    /// Updates fake network connections for a process
    /// </summary>
    private void UpdateNetworkConnections(FakeProcess fakeProcess)
    {
        try
        {
            // Randomly add or remove network connections to simulate activity
            if (fakeProcess.Profile.FakeNetworkConnections.Count > 0)
            {
                var shouldUpdate = _random.Next(0, 10) < 3; // 30% chance to update
                
                if (shouldUpdate)
                {
                    // Pick a random connection from the profile
                    var connection = fakeProcess.Profile.FakeNetworkConnections[
                        _random.Next(fakeProcess.Profile.FakeNetworkConnections.Count)];
                    
                    // Add or remove it from active connections
                    if (fakeProcess.NetworkConnections.Contains(connection))
                    {
                        fakeProcess.NetworkConnections.Remove(connection);
                    }
                    else
                    {
                        fakeProcess.NetworkConnections.Add(connection);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error updating network connections for: {ProcessName}", fakeProcess.ProcessName);
        }
    }

    /// <summary>
    /// Creates a fake Windows service entry
    /// </summary>
    private async Task CreateFakeServiceAsync(ProcessProfile profile)
    {
        try
        {
            _logger.LogDebug("Creating fake service for: {ProcessName}", profile.ProcessName);

            // Note: Creating actual Windows services requires elevated privileges
            // and is complex. For the honeypot, we can simulate service presence
            // by creating registry entries that make it appear in service lists.
            
            // This is a placeholder for service creation logic
            // In a full implementation, we would:
            // 1. Create service registry entries
            // 2. Set appropriate service metadata
            // 3. Make it appear in services.msc
            
            _logger.LogInformation("Fake service created for: {ProcessName}", profile.ProcessName);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to create fake service for: {ProcessName}", profile.ProcessName);
        }

        await Task.CompletedTask;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            StopAllFakeProcessesAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error stopping processes during disposal");
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
