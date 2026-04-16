namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Analysis of attack patterns detected by the honeypot
/// </summary>
public class AttackPatternAnalysis
{
    /// <summary>
    /// Total number of attacks detected
    /// </summary>
    public int TotalAttacks { get; set; }

    /// <summary>
    /// Number of unique attack types
    /// </summary>
    public int UniqueAttackTypes { get; set; }

    /// <summary>
    /// Most common attack type
    /// </summary>
    public AttackEventType? MostCommonAttackType { get; set; }

    /// <summary>
    /// Number of attacks by type
    /// </summary>
    public Dictionary<AttackEventType, int> AttacksByType { get; set; } = new();

    /// <summary>
    /// Time range of attacks
    /// </summary>
    public TimeSpan AttackTimeRange { get; set; }

    /// <summary>
    /// First attack timestamp
    /// </summary>
    public DateTime? FirstAttackTime { get; set; }

    /// <summary>
    /// Last attack timestamp
    /// </summary>
    public DateTime? LastAttackTime { get; set; }

    /// <summary>
    /// Average time between attacks
    /// </summary>
    public TimeSpan AverageTimeBetweenAttacks { get; set; }

    /// <summary>
    /// Most targeted files
    /// </summary>
    public List<string> MostTargetedFiles { get; set; } = new();

    /// <summary>
    /// Most active attacking processes
    /// </summary>
    public List<string> MostActiveProcesses { get; set; } = new();

    /// <summary>
    /// Whether a coordinated attack pattern is detected
    /// </summary>
    public bool CoordinatedAttackDetected { get; set; }

    /// <summary>
    /// Description of detected patterns
    /// </summary>
    public string PatternDescription { get; set; } = string.Empty;

    /// <summary>
    /// Severity assessment of the attack pattern
    /// </summary>
    public ThreatSeverity OverallSeverity { get; set; } = ThreatSeverity.Medium;
}

/// <summary>
/// Event arguments for attack pattern detection
/// </summary>
public class AttackPatternDetectedEventArgs : EventArgs
{
    /// <summary>
    /// The detected attack pattern analysis
    /// </summary>
    public AttackPatternAnalysis Analysis { get; set; } = new();

    /// <summary>
    /// Description of the detected pattern
    /// </summary>
    public string PatternDescription { get; set; } = string.Empty;

    /// <summary>
    /// Timestamp when the pattern was detected
    /// </summary>
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}
