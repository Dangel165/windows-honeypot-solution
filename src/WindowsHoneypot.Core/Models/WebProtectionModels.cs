namespace WindowsHoneypot.Core.Models;

public class UrlReputationResult
{
    public string Url { get; set; } = string.Empty;
    public bool IsMalicious { get; set; }
    public ThreatSeverity Severity { get; set; }
    public double ConfidenceScore { get; set; }
    public List<string> ThreatCategories { get; set; } = new();
    public string Recommendation { get; set; } = string.Empty;
    public DateTime CheckedAt { get; set; } = DateTime.UtcNow;
}

public class DownloadScanResult
{
    public string Url { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public bool IsThreat { get; set; }
    public bool IsSafe { get; set; }
    public ThreatSeverity Severity { get; set; }
    public List<string> DetectedThreats { get; set; } = new();
    public string FileHash { get; set; } = string.Empty;
    public DateTime ScannedAt { get; set; } = DateTime.UtcNow;
}

public enum BrowserType { Chrome, Edge, Firefox, Unknown }

public class WebThreatEventArgs : EventArgs
{
    public string Url { get; set; } = string.Empty;
    public ThreatSeverity Severity { get; set; }
    public string Description { get; set; } = string.Empty;
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}
