namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Represents a fake process created for camouflage
/// </summary>
public class FakeProcess
{
    /// <summary>
    /// Unique identifier for the fake process
    /// </summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Process name as it appears in Task Manager
    /// </summary>
    public string ProcessName { get; set; } = string.Empty;

    /// <summary>
    /// Fake process ID
    /// </summary>
    public int ProcessId { get; set; }

    /// <summary>
    /// Current CPU usage percentage
    /// </summary>
    public double CpuUsage { get; set; }

    /// <summary>
    /// Current memory usage in bytes
    /// </summary>
    public long MemoryUsage { get; set; }

    /// <summary>
    /// Process description
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Company name
    /// </summary>
    public string CompanyName { get; set; } = string.Empty;

    /// <summary>
    /// Product version
    /// </summary>
    public string ProductVersion { get; set; } = string.Empty;

    /// <summary>
    /// Timestamp when the process was started
    /// </summary>
    public DateTime StartTime { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Whether the process is currently running
    /// </summary>
    public bool IsRunning { get; set; } = true;

    /// <summary>
    /// List of fake network connections
    /// </summary>
    public List<string> NetworkConnections { get; set; } = new();

    /// <summary>
    /// Associated process profile
    /// </summary>
    public ProcessProfile Profile { get; set; } = new();
}