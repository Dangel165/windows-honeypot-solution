using Microsoft.Extensions.Logging.Abstractions;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

public class WebBrowsingProtectionTests
{
    private static WebBrowsingProtection CreateService() =>
        new WebBrowsingProtection(NullLogger<WebBrowsingProtection>.Instance);

    [Fact]
    public void Constructor_InitializesSuccessfully()
    {
        var svc = CreateService();
        Assert.NotNull(svc);
    }

    [Fact]
    public void GetBlocklist_ReturnsEmptyListInitially()
    {
        var svc = CreateService();
        var list = svc.GetBlocklist();
        Assert.Empty(list);
    }

    [Fact]
    public void AddToBlocklist_AddsUrl()
    {
        var svc = CreateService();
        svc.AddToBlocklist("http://evil.com");
        Assert.Contains("http://evil.com", svc.GetBlocklist());
    }

    [Fact]
    public void RemoveFromBlocklist_RemovesUrl()
    {
        var svc = CreateService();
        svc.AddToBlocklist("http://evil.com");
        svc.RemoveFromBlocklist("http://evil.com");
        Assert.DoesNotContain("http://evil.com", svc.GetBlocklist());
    }

    [Fact]
    public void IsUrlBlocked_ReturnsTrueForBlockedUrl()
    {
        var svc = CreateService();
        svc.AddToBlocklist("http://blocked.com");
        Assert.True(svc.IsUrlBlocked("http://blocked.com"));
    }

    [Fact]
    public void IsUrlBlocked_ReturnsFalseForNonBlockedUrl()
    {
        var svc = CreateService();
        Assert.False(svc.IsUrlBlocked("http://safe.com"));
    }

    [Fact]
    public async Task CheckUrlReputationAsync_CleanUrl_ReturnsNotMalicious()
    {
        var svc = CreateService();
        var result = await svc.CheckUrlReputationAsync("https://www.microsoft.com/en-us/windows");
        Assert.False(result.IsMalicious);
    }

    [Fact]
    public async Task CheckUrlReputationAsync_MaliciousKeywordInDomain_ReturnsMalicious()
    {
        var svc = CreateService();
        var result = await svc.CheckUrlReputationAsync("http://free-keygen-download.com/tool");
        Assert.True(result.IsMalicious);
        Assert.True(result.ConfidenceScore > 0);
    }

    [Fact]
    public async Task CheckUrlReputationAsync_IpBasedUrl_ReturnsSuspicious()
    {
        var svc = CreateService();
        var result = await svc.CheckUrlReputationAsync("http://192.168.1.100/payload");
        Assert.True(result.IsMalicious);
        Assert.Contains(result.ThreatCategories, c => c.Contains("IP address"));
    }

    [Fact]
    public async Task CheckUrlReputationAsync_BlockedUrl_ReturnsMalicious()
    {
        var svc = CreateService();
        svc.AddToBlocklist("http://blocked-site.com");
        var result = await svc.CheckUrlReputationAsync("http://blocked-site.com");
        Assert.True(result.IsMalicious);
        Assert.Equal(1.0, result.ConfidenceScore);
    }

    [Fact]
    public async Task ScanDownloadAsync_NonExistentFile_ReturnsResultWithoutThrowing()
    {
        var svc = CreateService();
        var result = await svc.ScanDownloadAsync("http://example.com/file.txt", @"C:\nonexistent\file.txt");
        Assert.NotNull(result);
    }

    [Theory]
    [InlineData(BrowserType.Chrome)]
    [InlineData(BrowserType.Edge)]
    [InlineData(BrowserType.Firefox)]
    [InlineData(BrowserType.Unknown)]
    public void IsBrowserExtensionAvailable_ReturnsBoolWithoutThrowing(BrowserType browser)
    {
        var svc = CreateService();
        var result = svc.IsBrowserExtensionAvailable(browser);
        Assert.IsType<bool>(result);
    }

    [Fact]
    public void WebThreatDetected_EventCanBeSubscribed()
    {
        var svc = CreateService();
        WebThreatEventArgs? captured = null;
        svc.WebThreatDetected += (_, args) => captured = args;

        // Just verify subscription doesn't throw
        Assert.Null(captured);
    }
}
