namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Current status of real-time protection
/// </summary>
public class ProtectionStatus
{
    public bool IsActive { get; set; }
    public DateTime StartTime { get; set; }
    public TimeSpan Uptime => IsActive ? DateTime.UtcNow - StartTime : TimeSpan.Zero;
    
    // Component status
    public bool FileSystemMonitorActive { get; set; }
    public bool ProcessMonitorActive { get; set; }
    public bool NetworkMonitorActive { get; set; }
    public bool RegistryMonitorActive { get; set; }
    public bool BehavioralAnalysisActive { get; set; }
    
    // Integration status
    public bool WindowsDefenderIntegrated { get; set; }
    public bool AMSIIntegrated { get; set; }
    public bool ETWIntegrated { get; set; }
    
    // Pattern database
    public int TotalThreatPatterns { get; set; }
    public int ActivePatterns { get; set; }
    public DateTime LastPatternUpdate { get; set; }
    
    // Performance metrics
    public double CPUUsagePercent { get; set; }
    public long MemoryUsageBytes { get; set; }
    public int EventsProcessedPerSecond { get; set; }
    
    // Error tracking
    public List<string> RecentErrors { get; set; } = new();
    public DateTime? LastError { get; set; }
}

/// <summary>
/// Protection statistics
/// </summary>
public class ProtectionStatistics
{
    public DateTime Since { get; set; } = DateTime.UtcNow;
    
    // Detection counts
    public int TotalThreatsDetected { get; set; }
    public int FilesBlocked { get; set; }
    public int ProcessesBlocked { get; set; }
    public int NetworkConnectionsBlocked { get; set; }
    public int RegistryOperationsBlocked { get; set; }
    
    // Threat breakdown by severity
    public int CriticalThreats { get; set; }
    public int HighThreats { get; set; }
    public int MediumThreats { get; set; }
    public int LowThreats { get; set; }
    
    // Advanced threat detection
    public int TimeDelayedMalwareDetected { get; set; }
    public int VMAwareMalwareDetected { get; set; }
    public int HardwareAttacksDetected { get; set; }
    public int SandboxEvasionDetected { get; set; }
    
    // Performance
    public long TotalEventsProcessed { get; set; }
    public double AverageProcessingTimeMs { get; set; }
    public int FalsePositives { get; set; }
    
    // Top threats
    public List<ThreatSummary> TopThreats { get; set; } = new();
}

/// <summary>
/// Summary of a detected threat
/// </summary>
public class ThreatSummary
{
    public string ThreatName { get; set; } = string.Empty;
    public ThreatSeverity Severity { get; set; }
    public int DetectionCount { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
}
