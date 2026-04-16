using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Email attachment scanner with real-time scanning and Outlook integration.
/// Task 20.1: Email attachment scanner
/// </summary>
public class EmailAttachmentScanner : IEmailAttachmentScanner
{
    private readonly ILogger<EmailAttachmentScanner> _logger;
    private readonly List<AttachmentScanResult> _scanHistory = new();
    private readonly object _lock = new();

    public event EventHandler<EmailScanEventArgs>? ThreatDetected;

    private static readonly HashSet<string> DangerousExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr",
        ".pif", ".com", ".msi", ".dll", ".hta", ".wsf", ".lnk"
    };

    private static readonly HashSet<string> OfficeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt"
    };

    private static readonly HashSet<string> ImageExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp"
    };

    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".log", ".csv", ".json", ".xml"
    };

    private static readonly HashSet<string> ArchiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".rar", ".7z"
    };

    public EmailAttachmentScanner(ILogger<EmailAttachmentScanner> logger)
    {
        _logger = logger;
    }

    public async Task<AttachmentScanResult> ScanAttachmentAsync(string filePath)
    {
        var result = new AttachmentScanResult { FilePath = filePath };

        try
        {
            if (!File.Exists(filePath))
            {
                result.IsThreat = false;
                result.IsSafe = false;
                result.DetectedThreats.Add("File not found or inaccessible");
                result.Recommendation = "File could not be scanned - it may not exist";
                return result;
            }

            var fileInfo = new FileInfo(filePath);
            result.FileName = fileInfo.Name;
            result.FileExtension = fileInfo.Extension.ToLowerInvariant();
            result.FileSizeBytes = fileInfo.Length;
            result.FileHash = await ComputeFileHashAsync(filePath);

            // Check dangerous extension
            if (DangerousExtensions.Contains(result.FileExtension))
            {
                result.IsThreat = true;
                result.Severity = ThreatSeverity.Critical;
                result.ConfidenceScore = 0.95;
                result.DetectedThreats.Add($"Dangerous file extension: {result.FileExtension}");
            }

            // Check double extension (e.g., document.pdf.exe)
            var nameWithoutExt = Path.GetFileNameWithoutExtension(result.FileName);
            if (!string.IsNullOrEmpty(nameWithoutExt))
            {
                var innerExt = Path.GetExtension(nameWithoutExt);
                if (!string.IsNullOrEmpty(innerExt) && DangerousExtensions.Contains(result.FileExtension))
                {
                    if (!result.DetectedThreats.Any(t => t.Contains("double extension")))
                    {
                        result.IsThreat = true;
                        result.DetectedThreats.Add($"Double extension detected: {innerExt}{result.FileExtension}");
                        result.Severity = ThreatSeverity.Critical;
                        result.ConfidenceScore = Math.Max(result.ConfidenceScore, 0.98);
                    }
                }
                else if (!string.IsNullOrEmpty(innerExt) && DangerousExtensions.Contains(result.FileExtension))
                {
                    result.IsThreat = true;
                    result.DetectedThreats.Add($"Double extension detected: {innerExt}{result.FileExtension}");
                }
            }

            // Check file size (>50MB suspicious for email)
            if (result.FileSizeBytes > 50 * 1024 * 1024)
            {
                result.DetectedThreats.Add("File size exceeds 50MB - suspicious for email attachment");
                if (!result.IsThreat)
                {
                    result.IsThreat = true;
                    result.Severity = ThreatSeverity.Medium;
                    result.ConfidenceScore = Math.Max(result.ConfidenceScore, 0.6);
                }
            }

            // Office macro check
            if (OfficeExtensions.Contains(result.FileExtension))
            {
                if (await ContainsMacrosAsync(filePath))
                {
                    result.IsThreat = true;
                    result.DetectedThreats.Add("Office document contains macro (vbaProject.bin)");
                    if (result.Severity < ThreatSeverity.High)
                        result.Severity = ThreatSeverity.High;
                    result.ConfidenceScore = Math.Max(result.ConfidenceScore, 0.85);
                }
            }

            // PDF JavaScript check
            if (result.FileExtension == ".pdf")
            {
                if (await ContainsPdfThreatsAsync(filePath))
                {
                    result.IsThreat = true;
                    result.DetectedThreats.Add("PDF contains potentially dangerous JavaScript or embedded content");
                    if (result.Severity < ThreatSeverity.High)
                        result.Severity = ThreatSeverity.High;
                    result.ConfidenceScore = Math.Max(result.ConfidenceScore, 0.80);
                }
            }

            // Archive check
            if (ArchiveExtensions.Contains(result.FileExtension))
            {
                result.IsThreat = true;
                result.DetectedThreats.Add("Archive file may contain malware");
                if (result.Severity < ThreatSeverity.Medium)
                    result.Severity = ThreatSeverity.Medium;
                result.ConfidenceScore = Math.Max(result.ConfidenceScore, 0.5);
            }

            result.IsSafe = !result.IsThreat;
            result.IsPreviewSafe = !DangerousExtensions.Contains(result.FileExtension)
                                   && !ArchiveExtensions.Contains(result.FileExtension);
            result.Recommendation = BuildRecommendation(result);

            AddToHistory(result);

            if (result.IsThreat)
            {
                _logger.LogWarning("Threat detected in attachment: {FilePath}, Severity: {Severity}",
                    filePath, result.Severity);
                ThreatDetected?.Invoke(this, new EmailScanEventArgs { Result = result });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning attachment: {FilePath}", filePath);
            result.IsThreat = false;
            result.IsSafe = false;
            result.DetectedThreats.Add($"Scan error: {ex.Message}");
            result.Recommendation = "Scan failed - treat file with caution";
        }

        return result;
    }

    public async Task<SafePreviewResult> CreateSafePreviewAsync(string filePath)
    {
        var result = new SafePreviewResult();

        try
        {
            if (!File.Exists(filePath))
            {
                result.Success = false;
                result.ErrorMessage = "File not found";
                return result;
            }

            var ext = Path.GetExtension(filePath).ToLowerInvariant();

            if (DangerousExtensions.Contains(ext))
            {
                result.Success = false;
                result.ErrorMessage = "Preview not available for potentially dangerous files";
                return result;
            }

            if (TextExtensions.Contains(ext))
            {
                var content = await ReadFirstCharsAsync(filePath, 4096);
                result.Success = true;
                result.PreviewType = "text";
                result.Content = content;
                result.PreviewPath = filePath;
                return result;
            }

            if (ImageExtensions.Contains(ext))
            {
                result.Success = true;
                result.PreviewType = "image";
                result.PreviewPath = filePath;
                return result;
            }

            if (ext == ".pdf")
            {
                result.Success = true;
                result.PreviewType = "pdf";
                result.PreviewPath = filePath;
                return result;
            }

            if (OfficeExtensions.Contains(ext))
            {
                result.Success = true;
                result.PreviewType = "office";
                result.PreviewPath = filePath;
                return result;
            }

            // Unknown type
            result.Success = false;
            result.PreviewType = "unknown";
            result.ErrorMessage = "Preview not available for this file type";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating safe preview for: {FilePath}", filePath);
            result.Success = false;
            result.ErrorMessage = $"Preview error: {ex.Message}";
        }

        return result;
    }

    public bool IsOutlookIntegrationAvailable()
    {
        try
        {
            // Check if Outlook process is running
            var processes = Process.GetProcessesByName("OUTLOOK");
            if (processes.Length > 0)
                return true;

            // Check registry for Outlook installation
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Office");
            return key != null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error checking Outlook availability");
            return false;
        }
    }

    public async Task<List<AttachmentScanResult>> ScanOutlookAttachmentsAsync()
    {
        var results = new List<AttachmentScanResult>();

        if (!IsOutlookIntegrationAvailable())
        {
            _logger.LogInformation("Outlook integration not available, skipping scan");
            return results;
        }

        try
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var outlookCachePath = Path.Combine(localAppData,
                "Microsoft", "Windows", "INetCache", "Content.Outlook");

            if (!Directory.Exists(outlookCachePath))
            {
                _logger.LogInformation("Outlook attachment cache folder not found: {Path}", outlookCachePath);
                return results;
            }

            var files = Directory.GetFiles(outlookCachePath, "*", SearchOption.AllDirectories);
            foreach (var file in files)
            {
                var scanResult = await ScanAttachmentAsync(file);
                results.Add(scanResult);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning Outlook attachments");
        }

        return results;
    }

    public List<AttachmentScanResult> GetScanHistory()
    {
        lock (_lock)
        {
            return new List<AttachmentScanResult>(_scanHistory);
        }
    }

    public void ClearScanHistory()
    {
        lock (_lock)
        {
            _scanHistory.Clear();
        }
    }

    // --- Private helpers ---

    private void AddToHistory(AttachmentScanResult result)
    {
        lock (_lock)
        {
            _scanHistory.Add(result);
        }
    }

    private static async Task<string> ComputeFileHashAsync(string filePath)
    {
        using var sha256 = SHA256.Create();
        await using var stream = File.OpenRead(filePath);
        var hashBytes = await sha256.ComputeHashAsync(stream);
        return Convert.ToHexString(hashBytes);
    }

    private static async Task<bool> ContainsMacrosAsync(string filePath)
    {
        try
        {
            await using var stream = File.OpenRead(filePath);
            using var zip = new ZipArchive(stream, ZipArchiveMode.Read);
            return zip.Entries.Any(e =>
                e.FullName.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> ContainsPdfThreatsAsync(string filePath)
    {
        try
        {
            var buffer = new byte[1024];
            await using var stream = File.OpenRead(filePath);
            var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
            var header = Encoding.ASCII.GetString(buffer, 0, bytesRead);

            return header.Contains("/JS") ||
                   header.Contains("/JavaScript") ||
                   header.Contains("/Launch") ||
                   header.Contains("/EmbeddedFile");
        }
        catch
        {
            return false;
        }
    }

    private static async Task<string> ReadFirstCharsAsync(string filePath, int maxChars)
    {
        await using var stream = File.OpenRead(filePath);
        using var reader = new StreamReader(stream);
        var buffer = new char[maxChars];
        var read = await reader.ReadAsync(buffer, 0, maxChars);
        return new string(buffer, 0, read);
    }

    private static string BuildRecommendation(AttachmentScanResult result)
    {
        if (!result.IsThreat)
            return "File appears safe to open";

        return result.Severity switch
        {
            ThreatSeverity.Critical => "Do not open - delete immediately",
            ThreatSeverity.High => "High risk - do not open without verification",
            ThreatSeverity.Medium => "Caution advised - verify sender before opening",
            _ => "Low risk detected - proceed with caution"
        };
    }
}
