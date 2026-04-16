using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Interfaces;

public interface IWebBrowsingProtection
{
    Task<UrlReputationResult> CheckUrlReputationAsync(string url);
    Task<DownloadScanResult> ScanDownloadAsync(string url, string filePath);
    bool IsUrlBlocked(string url);
    void AddToBlocklist(string url);
    void RemoveFromBlocklist(string url);
    List<string> GetBlocklist();
    bool IsBrowserExtensionAvailable(BrowserType browser);
    event EventHandler<WebThreatEventArgs> WebThreatDetected;
}
