namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Event arguments for file system events
/// </summary>
public class FileEventArgs : EventArgs
{
    public string FilePath { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public AttackEventType EventType { get; set; }
}

/// <summary>
/// Event arguments for file rename events
/// </summary>
public class FileRenamedEventArgs : FileEventArgs
{
    public string OldName { get; set; } = string.Empty;
    public string NewName { get; set; } = string.Empty;
}

/// <summary>
/// Event arguments for intrusion detection
/// </summary>
public class IntrusionDetectedEventArgs : EventArgs
{
    public AttackEvent AttackEvent { get; set; } = new();
    public string AlertMessage { get; set; } = string.Empty;
    public ThreatSeverity Severity { get; set; } = ThreatSeverity.Medium;
}

/// <summary>
/// Event arguments for sandbox status changes
/// </summary>
public class SandboxStatusChangedEventArgs : EventArgs
{
    public SandboxStatus OldStatus { get; set; }
    public SandboxStatus NewStatus { get; set; }
    public string? ErrorMessage { get; set; }
}

/// <summary>
/// Event arguments for network attempt blocking
/// </summary>
public class NetworkAttemptBlockedEventArgs : EventArgs
{
    public NetworkAttempt NetworkAttempt { get; set; } = new();
    public string BlockReason { get; set; } = string.Empty;
}

/// <summary>
/// Event arguments for credential usage attempts
/// </summary>
public class CredentialAttemptEventArgs : EventArgs
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string SourceIP { get; set; } = string.Empty;
    public string UserAgent { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public AttackerProfile AttackerProfile { get; set; } = new();
}

/// <summary>
/// Event arguments for threat intelligence reception
/// </summary>
public class ThreatIntelligenceReceivedEventArgs : EventArgs
{
    public List<ThreatIndicator> ThreatIndicators { get; set; } = new();
    public int NewIndicatorCount { get; set; }
    public DateTime ReceivedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Event arguments for process exit events
/// </summary>
public class ProcessExitedEventArgs : EventArgs
{
    public int ProcessId { get; set; }
    public DateTime ExitTime { get; set; }
}

/// <summary>
/// Event arguments for real-time threat detection
/// </summary>
public class ThreatDetectedEventArgs : EventArgs
{
    public ThreatAssessment Assessment { get; set; } = new();
    public string ThreatName { get; set; } = string.Empty;
    public ThreatSeverity Severity { get; set; }
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    public bool WasBlocked { get; set; }
}

/// <summary>
/// Event arguments for file operation blocking
/// </summary>
public class FileOperationBlockedEventArgs : EventArgs
{
    public string FilePath { get; set; } = string.Empty;
    public string Operation { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public List<ThreatPattern> MatchedPatterns { get; set; } = new();
    public DateTime BlockedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Event arguments for process blocking
/// </summary>
public class ProcessBlockedEventArgs : EventArgs
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string ExecutablePath { get; set; } = string.Empty;
    public string CommandLine { get; set; } = string.Empty;
    public List<ThreatPattern> MatchedPatterns { get; set; } = new();
    public DateTime BlockedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Event arguments for network connection blocking
/// </summary>
public class NetworkBlockedEventArgs : EventArgs
{
    public string RemoteAddress { get; set; } = string.Empty;
    public int RemotePort { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public List<ThreatPattern> MatchedPatterns { get; set; } = new();
    public DateTime BlockedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Event arguments for behavioral indicator detection
/// </summary>
public class BehavioralIndicatorEventArgs : EventArgs
{
    public BehavioralIndicator Indicator { get; set; } = new();
    public string Description { get; set; } = string.Empty;
    public ThreatSeverity Severity { get; set; }
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}