namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Profile for creating fake processes
/// </summary>
public class ProcessProfile
{
    /// <summary>
    /// Name of the process to create
    /// </summary>
    public string ProcessName { get; set; } = string.Empty;

    /// <summary>
    /// Path to the executable (can be fake)
    /// </summary>
    public string ExecutablePath { get; set; } = string.Empty;

    /// <summary>
    /// Fake CPU usage percentage (0-100)
    /// </summary>
    public int FakeCpuUsage { get; set; } = 0;

    /// <summary>
    /// Fake memory usage in bytes
    /// </summary>
    public long FakeMemoryUsage { get; set; } = 0;

    /// <summary>
    /// List of fake network connections to simulate
    /// </summary>
    public List<string> FakeNetworkConnections { get; set; } = new();

    /// <summary>
    /// Whether to create a corresponding fake Windows service
    /// </summary>
    public bool CreateFakeService { get; set; } = false;

    /// <summary>
    /// Description of the process for Task Manager
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Company name for the process
    /// </summary>
    public string CompanyName { get; set; } = string.Empty;

    /// <summary>
    /// Product version for the process
    /// </summary>
    public string ProductVersion { get; set; } = "1.0.0.0";

    /// <summary>
    /// Whether the process should appear to have network activity
    /// </summary>
    public bool SimulateNetworkActivity { get; set; } = false;

    /// <summary>
    /// Whether the process should vary its CPU usage over time
    /// </summary>
    public bool VariableCpuUsage { get; set; } = true;
}