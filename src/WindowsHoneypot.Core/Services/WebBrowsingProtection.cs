using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Web browsing protection service with URL reputation checking and download scanning.
/// Task 20.2: Web browsing protection
/// </summary>
public class WebBrowsingProtection : IWebBrowsingProtection
{
    private readonly ILogger<WebBrowsingProtection> _logger;
    private readonly HashSet<string> _blocklist = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    public event EventHandler<WebThreatEventArgs>? WebThreatDetected;

    private static readonly HashSet<string> MaliciousKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "phishing", "malware", "virus", "hack", "crack", "keygen", "warez"
    };

    private static readonly HashSet<string> SuspiciousTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        ".tk", ".ml", ".ga", ".cf"
    };

    private static readonly HashSet<string> DangerousExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr",
        ".pif", ".com", ".msi", ".dll", ".hta", ".wsf", ".lnk"
    };

    public WebBrowsingProtection(ILogger<WebBrowsingProtection> logger)
    {
        _logger = logger;
    }

    public async Task<UrlReputationResult> CheckUrlReputationAsync(string url)
    {
        var result = new UrlReputationResult { Url = url };

        try
        {
            // Check local blocklist first
            if (IsUrlBlocked(url))
            {
                result.IsMalicious = true;
                result.Severity = ThreatSeverity.High;
                result.ConfidenceScore = 1.0;
                result.ThreatCategories.Add("Blocklisted URL");
                result.Recommendation = "URL is on the local blocklist - access denied";
                return result;
            }

            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                result.IsMalicious = false;
                result.Recommendation = "Invalid URL format";
                return result;
            }

            var host = uri.Host.ToLowerInvariant();
            var fullUrl = url.ToLowerInvariant();

            // Check for malicious keywords in domain
            foreach (var keyword in MaliciousKeywords)
            {
                if (host.Contains(keyword))
                {
                    result.IsMalicious = true;
                    result.ThreatCategories.Add($"Malicious keyword in domain: {keyword}");
                    result.Severity = ThreatSeverity.High;
                    result.ConfidenceScore = Math.Max(result.ConfidenceScore, 0.90);
                }
            }

            // Check for suspicious TLDs
            foreach (var tld in SuspiciousTlds)
            {
                if (host.EndsWith(tld, StringComparison.OrdinalIgnoreCase))
                {
                    result.IsMalicious = true;
                    result.ThreatCategories.Add($"Suspicious free TLD: {tld}");
                    if (result.Severity < ThreatSeverity.Medium)
                        result.Severity = ThreatSeverity.Medium;
                    result.ConfidenceScore = Math.Max(result.ConfidenceScore, 0.65);
                }
            }

            // Check for IP-based URL (direct IP access is suspicious)
            if (IsIpAddress(host))
            {
                result.IsMalicious = true;
                result.ThreatCategories.Add("Direct IP address access - suspicious");
                if (result.Severity < ThreatSeverity.Medium)
                    result.Severity = ThreatSeverity.Medium;
                result.ConfidenceScore = Math.Max(result.ConfidenceScore, 0.70);
            }

            // Check URL length (>200 chars is suspicious)
            if (url.Length > 200)
            {
                result.IsMalicious = true;
                result.ThreatCategories.Add($"Unusually long URL ({url.Length} chars)");
                if (result.Severity < ThreatSeverity.Low)
                    result.Severity = ThreatSeverity.Low;
                result.ConfidenceScore = Math.Max(result.ConfidenceScore, 0.55);
            }

            // Check for too many subdomains (>4 dots in host)
            if (host.Count(c => c == '.') > 4)
            {
                result.IsMalicious = true;
                result.ThreatCategories.Add("Excessive subdomains - suspicious");
                if (result.Severity < ThreatSeverity.Medium)
                    result.Severity = ThreatSeverity.Medium;
                result.ConfidenceScore = Math.Max(result.ConfidenceScore, 0.60);
            }

            // Check for encoded null/control characters
            if (fullUrl.Contains("%00") || fullUrl.Contains("%0a") || fullUrl.Contains("%0d"))
            {
                result.IsMalicious = true;
                result.ThreatCategories.Add("URL contains encoded control characters");
                result.Severity = ThreatSeverity.High;
                result.ConfidenceScore = Math.Max(result.ConfidenceScore, 0.85);
            }

            result.Recommendation = result.IsMalicious
                ? BuildMaliciousRecommendation(result.Severity)
                : "URL appears safe";
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking URL reputation: {Url}", url);
            result.IsMalicious = false;
            result.Recommendation = "Reputation check failed - proceed with caution";
        }

        await Task.CompletedTask;
        return result;
    }

    public async Task<DownloadScanResult> ScanDownloadAsync(string url, string filePath)
    {
        var result = new DownloadScanResult { Url = url, FilePath = filePath };

        try
        {
            result.FileName = Path.GetFileName(filePath);

            // Check URL reputation first
            var urlRep = await CheckUrlReputationAsync(url);
            if (urlRep.IsMalicious)
            {
                result.IsThreat = true;
                result.Severity = urlRep.Severity;
                result.DetectedThreats.Add($"Malicious source URL: {string.Join(", ", urlRep.ThreatCategories)}");
            }

            // Check file extension
            var ext = Path.GetExtension(filePath);
            if (!string.IsNullOrEmpty(ext) && DangerousExtensions.Contains(ext))
            {
                result.IsThreat = true;
                if (result.Severity < ThreatSeverity.Critical)
                    result.Severity = ThreatSeverity.Critical;
                result.DetectedThreats.Add($"Dangerous file extension: {ext}");
            }

            // Compute hash if file exists
            if (File.Exists(filePath))
            {
                result.FileHash = await ComputeFileHashAsync(filePath);
            }

            result.IsSafe = !result.IsThreat;

            if (result.IsThreat)
            {
                _logger.LogWarning("Web download threat detected: {Url} -> {FilePath}, Severity: {Severity}",
                    url, filePath, result.Severity);

                WebThreatDetected?.Invoke(this, new WebThreatEventArgs
                {
                    Url = url,
                    Severity = result.Severity,
                    Description = $"Malicious download detected: {string.Join("; ", result.DetectedThreats)}",
                    DetectedAt = DateTime.UtcNow
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning download: {Url} -> {FilePath}", url, filePath);
            result.IsThreat = false;
            result.IsSafe = false;
            result.DetectedThreats.Add($"Scan error: {ex.Message}");
        }

        return result;
    }

    public bool IsUrlBlocked(string url)
    {
        lock (_lock)
        {
            return _blocklist.Contains(url);
        }
    }

    public void AddToBlocklist(string url)
    {
        lock (_lock)
        {
            _blocklist.Add(url);
        }
        _logger.LogInformation("URL added to blocklist: {Url}", url);
    }

    public void RemoveFromBlocklist(string url)
    {
        lock (_lock)
        {
            _blocklist.Remove(url);
        }
        _logger.LogInformation("URL removed from blocklist: {Url}", url);
    }

    public List<string> GetBlocklist()
    {
        lock (_lock)
        {
            return new List<string>(_blocklist);
        }
    }

    public bool IsBrowserExtensionAvailable(BrowserType browser)
    {
        try
        {
            var path = browser switch
            {
                BrowserType.Chrome => Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Google", "Chrome", "Application", "chrome.exe"),
                BrowserType.Edge => Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    "Microsoft", "Edge", "Application", "msedge.exe"),
                BrowserType.Firefox => Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "Mozilla Firefox", "firefox.exe"),
                _ => null
            };

            return path != null && File.Exists(path);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error checking browser availability for {Browser}", browser);
            return false;
        }
    }

    // --- Private helpers ---

    private static bool IsIpAddress(string host)
    {
        return System.Net.IPAddress.TryParse(host, out _);
    }

    private static string BuildMaliciousRecommendation(ThreatSeverity severity) =>
        severity switch
        {
            ThreatSeverity.Critical => "Do not visit - critical threat detected",
            ThreatSeverity.High => "High risk - do not visit this URL",
            ThreatSeverity.Medium => "Caution - this URL shows suspicious characteristics",
            _ => "Low risk detected - proceed with caution"
        };

    private static async Task<string> ComputeFileHashAsync(string filePath)
    {
        using var sha256 = SHA256.Create();
        await using var stream = File.OpenRead(filePath);
        var hashBytes = await sha256.ComputeHashAsync(stream);
        return Convert.ToHexString(hashBytes);
    }
}
