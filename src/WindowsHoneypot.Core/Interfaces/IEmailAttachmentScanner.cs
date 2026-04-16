using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Interfaces;

public interface IEmailAttachmentScanner
{
    Task<AttachmentScanResult> ScanAttachmentAsync(string filePath);
    Task<SafePreviewResult> CreateSafePreviewAsync(string filePath);
    bool IsOutlookIntegrationAvailable();
    Task<List<AttachmentScanResult>> ScanOutlookAttachmentsAsync();
    List<AttachmentScanResult> GetScanHistory();
    void ClearScanHistory();
    event EventHandler<EmailScanEventArgs> ThreatDetected;
}
