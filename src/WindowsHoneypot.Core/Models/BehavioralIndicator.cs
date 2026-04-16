namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Represents a behavioral indicator of suspicious activity
/// </summary>
public class BehavioralIndicator
{
    public string IndicatorId { get; set; } = Guid.NewGuid().ToString();
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    
    // Indicator details
    public BehavioralIndicatorType Type { get; set; }
    public string Description { get; set; } = string.Empty;
    public ThreatSeverity Severity { get; set; }
    public double ConfidenceScore { get; set; }
    
    // Source information
    public int? ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string RegistryKey { get; set; } = string.Empty;
    
    // Behavioral details
    public string BehaviorCategory { get; set; } = string.Empty;
    public List<string> ObservedActions { get; set; } = new();
    public Dictionary<string, object> BehaviorMetadata { get; set; } = new();
    
    // Time-based analysis
    public TimeSpan? DelayBeforeActivation { get; set; }
    public bool IsScheduledTask { get; set; }
    public bool IsPersistenceMechanism { get; set; }
    
    // Evasion techniques
    public bool UsesVMDetection { get; set; }
    public bool UsesSandboxEvasion { get; set; }
    public bool UsesAntiDebugging { get; set; }
    public bool UsesCodeObfuscation { get; set; }
}

/// <summary>
/// Types of behavioral indicators
/// </summary>
public enum BehavioralIndicatorType
{
    // Time-based
    TimeDelayedExecution,
    ScheduledTaskCreation,
    RegistryPersistence,
    
    // Evasion
    VMDetectionAttempt,
    SandboxEvasion,
    AntiDebugging,
    ProcessHollowing,
    
    // Privilege escalation
    PrivilegeEscalation,
    TokenManipulation,
    BypassUAC,
    
    // Data exfiltration
    DataExfiltration,
    NetworkBeaconing,
    DNSTunneling,
    
    // System modification
    BootkitInstallation,
    FirmwareModification,
    DriverInstallation,
    SystemFileModification,
    
    // Credential theft
    CredentialDumping,
    KeyLogging,
    BrowserDataTheft,
    
    // Lateral movement
    RemoteExecution,
    NetworkScanning,
    ShareEnumeration,
    
    // Other
    SuspiciousAPICall,
    AnomalousNetworkActivity,
    UnusualFileOperation,
    SuspiciousRegistryAccess
}

/// <summary>
/// Result of behavioral analysis
/// </summary>
public class BehavioralAnalysisResult
{
    public string AnalysisId { get; set; } = Guid.NewGuid().ToString();
    public DateTime AnalysisStartTime { get; set; }
    public DateTime AnalysisEndTime { get; set; }
    public TimeSpan AnalysisDuration => AnalysisEndTime - AnalysisStartTime;
    
    // Target information
    public string TargetPath { get; set; } = string.Empty;
    public int? TargetProcessId { get; set; }
    
    // Analysis results
    public bool IsSuspicious { get; set; }
    public double SuspicionScore { get; set; }
    public List<BehavioralIndicator> Indicators { get; set; } = new();
    
    // Specific threat types detected
    public bool IsTimeDelayed { get; set; }
    public bool IsVMAware { get; set; }
    public bool IsHardwareLevel { get; set; }
    public bool UsesSandboxEvasion { get; set; }
    
    // Behavioral patterns
    public List<string> DetectedPatterns { get; set; } = new();
    public Dictionary<string, int> ActionFrequency { get; set; } = new();
    
    // Recommendation
    public ThreatAction RecommendedAction { get; set; }
    public string Recommendation { get; set; } = string.Empty;
}
