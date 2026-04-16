namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Represents a threat pattern learned from honeypot intelligence
/// </summary>
public class ThreatPattern
{
    public string PatternId { get; set; } = Guid.NewGuid().ToString();
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public ThreatPatternType Type { get; set; }
    public ThreatSeverity Severity { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime LastUpdated { get; set; } = DateTime.UtcNow;
    
    // Pattern matching criteria
    public List<string> FileHashes { get; set; } = new();
    public List<string> FileNamePatterns { get; set; } = new();
    public List<string> ProcessNamePatterns { get; set; } = new();
    public List<string> RegistryKeyPatterns { get; set; } = new();
    public List<string> NetworkAddressPatterns { get; set; } = new();
    public List<int> NetworkPorts { get; set; } = new();
    
    // Behavioral indicators
    public List<string> BehavioralSignatures { get; set; } = new();
    public Dictionary<string, object> Metadata { get; set; } = new();
    
    // Detection statistics
    public int DetectionCount { get; set; }
    public int FalsePositiveCount { get; set; }
    public double ConfidenceScore { get; set; } = 1.0;
    
    // Source information
    public string SourceHoneypotId { get; set; } = string.Empty;
    public bool IsFromCommunity { get; set; }
}

/// <summary>
/// Types of threat patterns
/// </summary>
public enum ThreatPatternType
{
    FileHash,
    FileName,
    ProcessName,
    RegistryKey,
    NetworkAddress,
    Behavioral,
    Composite
}
