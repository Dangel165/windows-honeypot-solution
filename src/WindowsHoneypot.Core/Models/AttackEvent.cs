namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Represents an attack event detected by the honeypot
/// </summary>
public class AttackEvent
{
    /// <summary>
    /// Unique identifier for the event
    /// </summary>
    public Guid EventId { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Timestamp when the event occurred
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Type of attack event
    /// </summary>
    public AttackEventType EventType { get; set; }

    /// <summary>
    /// Name of the process that caused the event
    /// </summary>
    public string SourceProcess { get; set; } = string.Empty;

    /// <summary>
    /// Process ID that caused the event
    /// </summary>
    public int ProcessId { get; set; }

    /// <summary>
    /// Target file or resource affected
    /// </summary>
    public string TargetFile { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable description of the event
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Additional metadata about the event
    /// </summary>
    public Dictionary<string, object> Metadata { get; set; } = new();

    /// <summary>
    /// Severity of the attack event
    /// </summary>
    public ThreatSeverity Severity { get; set; } = ThreatSeverity.Medium;

    /// <summary>
    /// Whether this event has been acknowledged by an administrator
    /// </summary>
    public bool Acknowledged { get; set; } = false;
}