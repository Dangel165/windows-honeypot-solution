namespace WindowsHoneypot.Core.Models;

public class PhishingDetectionResult
{
    public string Url { get; set; } = string.Empty;
    public bool IsPhishing { get; set; }
    public ThreatSeverity Severity { get; set; }
    public double ConfidenceScore { get; set; }
    public List<string> PhishingIndicators { get; set; } = new();
    public string SpoofedBrand { get; set; } = string.Empty;
    public string Recommendation { get; set; } = string.Empty;
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}

public class CredentialWarningEventArgs : EventArgs
{
    public string Url { get; set; } = string.Empty;
    public string WarningMessage { get; set; } = string.Empty;
    public ThreatSeverity Severity { get; set; }
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}
