namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Represents a network connection attempt that was blocked
/// </summary>
public class NetworkAttempt
{
    /// <summary>
    /// Unique identifier for the network attempt
    /// </summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Timestamp of the attempt
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Source IP address
    /// </summary>
    public string SourceIP { get; set; } = string.Empty;

    /// <summary>
    /// Destination IP address
    /// </summary>
    public string DestinationIP { get; set; } = string.Empty;

    /// <summary>
    /// Source port
    /// </summary>
    public int SourcePort { get; set; }

    /// <summary>
    /// Destination port
    /// </summary>
    public int DestinationPort { get; set; }

    /// <summary>
    /// Protocol used (TCP, UDP, etc.)
    /// </summary>
    public string Protocol { get; set; } = string.Empty;

    /// <summary>
    /// Process that attempted the connection
    /// </summary>
    public string ProcessName { get; set; } = string.Empty;

    /// <summary>
    /// Process ID that attempted the connection
    /// </summary>
    public int ProcessId { get; set; }

    /// <summary>
    /// Direction of the connection (Inbound/Outbound)
    /// </summary>
    public string Direction { get; set; } = string.Empty;

    /// <summary>
    /// Reason why the connection was blocked
    /// </summary>
    public string BlockReason { get; set; } = string.Empty;
}