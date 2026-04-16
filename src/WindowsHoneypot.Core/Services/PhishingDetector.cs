using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Detects phishing sites using brand similarity, homograph attacks, and suspicious pattern analysis.
/// </summary>
public class PhishingDetector : IPhishingDetector
{
    private readonly ILogger<PhishingDetector> _logger;
    private readonly Dictionary<string, string> _protectedBrands;
    private readonly object _lock = new();

    private static readonly string[] SuspiciousKeywords =
    {
        "login", "signin", "secure", "verify", "account", "update", "confirm"
    };

    private static readonly string[] PathKeywords =
    {
        "login", "signin", "password", "credential"
    };

    private static readonly string[] FakeLoginPageKeywords =
    {
        "verify your account", "confirm your identity", "update payment"
    };

    public event EventHandler<CredentialWarningEventArgs>? CredentialWarningRaised;

    public PhishingDetector(ILogger<PhishingDetector> logger)
    {
        _logger = logger;
        _protectedBrands = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "google",     "google.com" },
            { "microsoft",  "microsoft.com" },
            { "apple",      "apple.com" },
            { "amazon",     "amazon.com" },
            { "paypal",     "paypal.com" },
            { "facebook",   "facebook.com" },
            { "netflix",    "netflix.com" },
            { "bank",       "bank.com" },
            { "chase",      "chase.com" },
            { "wellsfargo", "wellsfargo.com" }
        };
    }

    public List<string> GetProtectedBrands()
    {
        lock (_lock)
        {
            return _protectedBrands.Keys.ToList();
        }
    }

    public void AddProtectedBrand(string brand, string officialDomain)
    {
        if (string.IsNullOrWhiteSpace(brand) || string.IsNullOrWhiteSpace(officialDomain))
            return;

        lock (_lock)
        {
            _protectedBrands[brand.ToLowerInvariant()] = officialDomain.ToLowerInvariant();
        }
    }

    public async Task<PhishingDetectionResult> AnalyzeUrlAsync(string url)
    {
        var result = new PhishingDetectionResult { Url = url };

        try
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                result.Recommendation = "Invalid URL format.";
                return result;
            }

            var host = uri.Host.ToLowerInvariant();
            var path = uri.AbsolutePath.ToLowerInvariant();
            var indicators = new List<string>();
            string spoofedBrand = string.Empty;

            Dictionary<string, string> brandsCopy;
            lock (_lock)
            {
                brandsCopy = new Dictionary<string, string>(_protectedBrands, StringComparer.OrdinalIgnoreCase);
            }

            // 1. Brand spoofing check
            foreach (var (brand, officialDomain) in brandsCopy)
            {
                if (host.Contains(brand) && !IsOfficialDomain(host, officialDomain))
                {
                    indicators.Add($"Brand spoofing detected: '{brand}' in domain but not official domain '{officialDomain}'");
                    spoofedBrand = brand;
                }

                // Subdomain spoofing: brand.evil.com
                var parts = host.Split('.');
                if (parts.Length > 2 && parts[0].Equals(brand, StringComparison.OrdinalIgnoreCase))
                {
                    var rootDomain = string.Join(".", parts.Skip(1));
                    if (!rootDomain.Equals(officialDomain, StringComparison.OrdinalIgnoreCase))
                    {
                        var msg = $"Subdomain spoofing: '{brand}' used as subdomain of '{rootDomain}'";
                        if (!indicators.Contains(msg))
                            indicators.Add(msg);
                        if (string.IsNullOrEmpty(spoofedBrand))
                            spoofedBrand = brand;
                    }
                }
            }

            // 2. Homograph attack check (digits replacing letters)
            if (ContainsHomographChars(host))
                indicators.Add("Homograph attack: digits replacing letters (0→o, 1→l, 3→e)");

            // 3. Suspicious domain keywords
            foreach (var keyword in SuspiciousKeywords)
            {
                if (host.Contains(keyword))
                {
                    indicators.Add($"Suspicious keyword in domain: '{keyword}'");
                    break;
                }
            }

            // 4. Hyphen with brand name
            if (host.Contains('-'))
            {
                foreach (var (brand, _) in brandsCopy)
                {
                    if (host.Contains(brand) && host.Contains('-'))
                    {
                        indicators.Add($"Hyphen-brand pattern detected: '{brand}-' in domain");
                        if (string.IsNullOrEmpty(spoofedBrand))
                            spoofedBrand = brand;
                        break;
                    }
                }
            }

            // 5. Suspicious path keywords
            foreach (var keyword in PathKeywords)
            {
                if (path.Contains(keyword))
                {
                    indicators.Add($"Suspicious keyword in URL path: '{keyword}'");
                    break;
                }
            }

            // Calculate confidence score
            double confidence = Math.Min(1.0, indicators.Count * 0.25);
            bool isPhishing = indicators.Count >= 1;

            result.IsPhishing = isPhishing;
            result.PhishingIndicators = indicators;
            result.SpoofedBrand = spoofedBrand;
            result.ConfidenceScore = confidence;
            result.Severity = confidence >= 0.75 ? ThreatSeverity.Critical
                            : confidence >= 0.5  ? ThreatSeverity.High
                            : confidence >= 0.25 ? ThreatSeverity.Medium
                            : ThreatSeverity.Low;
            result.Recommendation = isPhishing
                ? $"Do not enter credentials. This site may be impersonating '{spoofedBrand}'."
                : "URL appears legitimate.";

            if (isPhishing)
            {
                _logger.LogWarning("Phishing detected for URL: {Url} | Indicators: {Count}", url, indicators.Count);
                OnCredentialWarningRaised(new CredentialWarningEventArgs
                {
                    Url = url,
                    WarningMessage = result.Recommendation,
                    Severity = result.Severity
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing URL: {Url}", url);
            result.Recommendation = "Analysis failed due to an error.";
        }

        await Task.CompletedTask;
        return result;
    }

    public bool IsFakeLoginPage(string htmlContent)
    {
        if (string.IsNullOrWhiteSpace(htmlContent))
            return false;

        int indicatorCount = 0;
        var lower = htmlContent.ToLowerInvariant();

        // Password input field
        if (lower.Contains("type=\"password\"") || lower.Contains("type='password'"))
            indicatorCount++;

        // Form with external action
        if (lower.Contains("<form") && lower.Contains("action="))
            indicatorCount++;

        // Suspicious verification keywords
        foreach (var keyword in FakeLoginPageKeywords)
        {
            if (lower.Contains(keyword))
            {
                indicatorCount++;
                break;
            }
        }

        return indicatorCount >= 2;
    }

    public double CalculateBrandSimilarity(string url, string brandName)
    {
        if (string.IsNullOrWhiteSpace(url) || string.IsNullOrWhiteSpace(brandName))
            return 0.0;

        string domain = url;
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
            domain = uri.Host.ToLowerInvariant();

        var distance = LevenshteinDistance(domain.ToLowerInvariant(), brandName.ToLowerInvariant());
        int maxLen = Math.Max(domain.Length, brandName.Length);
        if (maxLen == 0) return 1.0;

        return 1.0 - (double)distance / maxLen;
    }

    // --- Private helpers ---

    private static bool IsOfficialDomain(string host, string officialDomain)
    {
        return host.Equals(officialDomain, StringComparison.OrdinalIgnoreCase)
            || host.EndsWith("." + officialDomain, StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsHomographChars(string host)
    {
        // Check for digits that commonly replace letters: 0→o, 1→l/i, 3→e
        // A domain with letters AND these digits mixed in the same "word" is suspicious
        var parts = host.Split('.');
        foreach (var part in parts)
        {
            bool hasLetter = part.Any(char.IsLetter);
            bool hasHomographDigit = part.Contains('0') || part.Contains('1') || part.Contains('3');
            if (hasLetter && hasHomographDigit)
                return true;
        }
        return false;
    }

    private static int LevenshteinDistance(string s, string t)
    {
        if (s.Length == 0) return t.Length;
        if (t.Length == 0) return s.Length;

        var d = new int[s.Length + 1, t.Length + 1];
        for (int i = 0; i <= s.Length; i++) d[i, 0] = i;
        for (int j = 0; j <= t.Length; j++) d[0, j] = j;

        for (int i = 1; i <= s.Length; i++)
        {
            for (int j = 1; j <= t.Length; j++)
            {
                int cost = s[i - 1] == t[j - 1] ? 0 : 1;
                d[i, j] = Math.Min(
                    Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1),
                    d[i - 1, j - 1] + cost);
            }
        }

        return d[s.Length, t.Length];
    }

    private void OnCredentialWarningRaised(CredentialWarningEventArgs args)
    {
        CredentialWarningRaised?.Invoke(this, args);
    }
}
