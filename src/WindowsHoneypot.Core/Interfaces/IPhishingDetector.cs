using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Interfaces;

public interface IPhishingDetector
{
    Task<PhishingDetectionResult> AnalyzeUrlAsync(string url);
    bool IsFakeLoginPage(string htmlContent);
    double CalculateBrandSimilarity(string url, string brandName);
    List<string> GetProtectedBrands();
    void AddProtectedBrand(string brand, string officialDomain);
    event EventHandler<CredentialWarningEventArgs> CredentialWarningRaised;
}
