namespace WindowsHoneypot.Core.Models;

public class AttachmentScanResult
{
    public string FilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string FileExtension { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public bool IsThreat { get; set; }
    public bool IsSafe { get; set; }
    public ThreatSeverity Severity { get; set; }
    public double ConfidenceScore { get; set; }
    public List<string> DetectedThreats { get; set; } = new();
    public string FileHash { get; set; } = string.Empty;
    public DateTime ScannedAt { get; set; } = DateTime.UtcNow;
    public string Recommendation { get; set; } = string.Empty;
    public bool IsPreviewSafe { get; set; }
    public string SafePreviewPath { get; set; } = string.Empty;
}

public class SafePreviewResult
{
    public bool Success { get; set; }
    public string PreviewPath { get; set; } = string.Empty;
    public string PreviewType { get; set; } = string.Empty; // "text", "image", "html"
    public string Content { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;
}

public class EmailScanEventArgs : EventArgs
{
    public AttachmentScanResult Result { get; set; } = new();
    public string EmailSubject { get; set; } = string.Empty;
    public string SenderAddress { get; set; } = string.Empty;
}
