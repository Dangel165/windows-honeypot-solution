namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Assessment result for a potential threat
/// </summary>
public class ThreatAssessment
{
    public string AssessmentId { get; set; } = Guid.NewGuid().ToString();
    public DateTime AssessmentTime { get; set; } = DateTime.UtcNow;
    
    // Assessment result
    public bool IsThreat { get; set; }
    public ThreatSeverity Severity { get; set; }
    public double ConfidenceScore { get; set; }
    
    // Target information
    public string TargetPath { get; set; } = string.Empty;
    public string TargetType { get; set; } = string.Empty; // File, Process, Network, etc.
    public Dictionary<string, object> TargetMetadata { get; set; } = new();
    
    // Matched patterns
    public List<ThreatPattern> MatchedPatterns { get; set; } = new();
    public List<string> MatchedIndicators { get; set; } = new();
    
    // Behavioral analysis
    public List<BehavioralIndicator> BehavioralIndicators { get; set; } = new();
    public bool IsTimeDelayed { get; set; }
    public bool IsVMAware { get; set; }
    public bool IsHardwareLevel { get; set; }
    public bool UsesSandboxEvasion { get; set; }
    
    // Recommended action
    public ThreatAction RecommendedAction { get; set; }
    public string ActionReason { get; set; } = string.Empty;
    
    // Additional details
    public string Description { get; set; } = string.Empty;
    public List<string> TechnicalDetails { get; set; } = new();
}

/// <summary>
/// Recommended action for a detected threat
/// </summary>
public enum ThreatAction
{
    Allow,
    Monitor,
    Warn,
    Block,
    Quarantine,
    Terminate
}
