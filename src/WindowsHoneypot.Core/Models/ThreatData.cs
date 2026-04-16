namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Threat data shared with the community
/// </summary>
public class ThreatData
{
    /// <summary>
    /// Unique identifier for the threat
    /// </summary>
    public string ThreatId { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// IP address of the attacker
    /// </summary>
    public string AttackerIP { get; set; } = string.Empty;

    /// <summary>
    /// List of attack patterns observed
    /// </summary>
    public List<string> AttackPatterns { get; set; } = new();

    /// <summary>
    /// Timestamp when the threat was detected
    /// </summary>
    public DateTime DetectionTime { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Severity level of the threat
    /// </summary>
    public ThreatSeverity Severity { get; set; } = ThreatSeverity.Medium;

    /// <summary>
    /// Geographic location of the threat (anonymized)
    /// </summary>
    public string GeographicLocation { get; set; } = string.Empty;

    /// <summary>
    /// Threat indicators and their values
    /// </summary>
    public Dictionary<string, string> Indicators { get; set; } = new();

    /// <summary>
    /// Hash of the threat data for integrity
    /// </summary>
    public string DataHash { get; set; } = string.Empty;

    /// <summary>
    /// Version of the threat data format
    /// </summary>
    public string Version { get; set; } = "1.0";

    /// <summary>
    /// Source honeypot identifier (anonymized)
    /// </summary>
    public string SourceId { get; set; } = string.Empty;
}

/// <summary>
/// Threat indicator from community intelligence
/// </summary>
public class ThreatIndicator
{
    /// <summary>
    /// Type of indicator (IP, Domain, Hash, etc.)
    /// </summary>
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// Value of the indicator
    /// </summary>
    public string Value { get; set; } = string.Empty;

    /// <summary>
    /// Confidence score (0-100)
    /// </summary>
    public int Confidence { get; set; }

    /// <summary>
    /// Severity of the threat
    /// </summary>
    public ThreatSeverity Severity { get; set; } = ThreatSeverity.Medium;

    /// <summary>
    /// Description of the threat
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Tags associated with the threat
    /// </summary>
    public List<string> Tags { get; set; } = new();

    /// <summary>
    /// First seen timestamp
    /// </summary>
    public DateTime FirstSeen { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Last seen timestamp
    /// </summary>
    public DateTime LastSeen { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Global threat statistics
/// </summary>
public class ThreatStatistics
{
    /// <summary>
    /// Total number of threats detected globally
    /// </summary>
    public long TotalThreats { get; set; }

    /// <summary>
    /// Threats detected in the last 24 hours
    /// </summary>
    public long ThreatsLast24Hours { get; set; }

    /// <summary>
    /// Top attacking countries
    /// </summary>
    public Dictionary<string, int> TopAttackingCountries { get; set; } = new();

    /// <summary>
    /// Most common attack patterns
    /// </summary>
    public Dictionary<string, int> CommonAttackPatterns { get; set; } = new();

    /// <summary>
    /// Threat severity distribution
    /// </summary>
    public Dictionary<ThreatSeverity, int> SeverityDistribution { get; set; } = new();

    /// <summary>
    /// Timestamp when statistics were generated
    /// </summary>
    public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Regional threat statistics
/// Requirement 15.7: Regional statistics and attack pattern analysis
/// </summary>
public class RegionalThreatStatistics
{
    /// <summary>
    /// Region identifier (country, continent, etc.)
    /// </summary>
    public string Region { get; set; } = string.Empty;

    /// <summary>
    /// Total threats in this region
    /// </summary>
    public int ThreatCount { get; set; }

    /// <summary>
    /// Threats in the last 24 hours
    /// </summary>
    public int ThreatsLast24Hours { get; set; }

    /// <summary>
    /// Most common attack types in this region
    /// </summary>
    public Dictionary<string, int> CommonAttackTypes { get; set; } = new();

    /// <summary>
    /// Top targeted sectors in this region
    /// </summary>
    public Dictionary<string, int> TargetedSectors { get; set; } = new();

    /// <summary>
    /// Severity distribution for this region
    /// </summary>
    public Dictionary<ThreatSeverity, int> SeverityDistribution { get; set; } = new();

    /// <summary>
    /// Timestamp when statistics were generated
    /// </summary>
    public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Threat indicator analysis results from community intelligence
/// Requirement 15.7: Attack pattern categorization
/// </summary>
public class ThreatIndicatorAnalysis
{
    /// <summary>
    /// Total number of indicators analyzed
    /// </summary>
    public int TotalIndicators { get; set; }

    /// <summary>
    /// Indicators grouped by type (IP, Domain, Hash, etc.)
    /// </summary>
    public Dictionary<string, int> IndicatorsByType { get; set; } = new();

    /// <summary>
    /// Indicators grouped by severity
    /// </summary>
    public Dictionary<ThreatSeverity, int> IndicatorsBySeverity { get; set; } = new();

    /// <summary>
    /// Most common tags across all indicators
    /// </summary>
    public Dictionary<string, int> CommonTags { get; set; } = new();

    /// <summary>
    /// Average confidence score
    /// </summary>
    public int AverageConfidence { get; set; }

    /// <summary>
    /// Number of high-risk indicators (confidence >= 90)
    /// </summary>
    public int HighRiskIndicatorCount { get; set; }

    /// <summary>
    /// Timestamp when analysis was performed
    /// </summary>
    public DateTime AnalyzedAt { get; set; } = DateTime.UtcNow;
}