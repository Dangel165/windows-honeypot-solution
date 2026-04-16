namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Information about a tracked process
/// </summary>
public class ProcessInfo
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public DateTime StartTime { get; set; }
    public bool IsRunning { get; set; }
}
