using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Network threat blocker using Windows Filtering Platform (WFP)
/// Blocks malicious network connections based on threat patterns
/// </summary>
public class NetworkThreatBlocker
{
    private readonly ILogger<NetworkThreatBlocker> _logger;
    private readonly HashSet<string> _blockedIPs;
    private readonly HashSet<int> _blockedPorts;
    private readonly Dictionary<string, DateTime> _blockTimestamps;
    private readonly object _lock = new();
    private bool _isActive;

    public event EventHandler<NetworkBlockedEventArgs>? ConnectionBlocked;

    public NetworkThreatBlocker(ILogger<NetworkThreatBlocker> logger)
    {
        _logger = logger;
        _blockedIPs = new HashSet<string>();
        _blockedPorts = new HashSet<int>();
        _blockTimestamps = new Dictionary<string, DateTime>();
    }

    /// <summary>
    /// Start network threat blocking
    /// </summary>
    public async Task StartAsync()
    {
        if (_isActive)
        {
            _logger.LogWarning("Network threat blocker is already active");
            return;
        }

        _logger.LogInformation("Starting network threat blocker...");

        try
        {
            _isActive = true;
            
            // Apply existing block rules
            await ApplyBlockRulesAsync();

            _logger.LogInformation("Network threat blocker started successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start network threat blocker");
            _isActive = false;
            throw;
        }
    }

    /// <summary>
    /// Stop network threat blocking
    /// </summary>
    public async Task StopAsync()
    {
        if (!_isActive)
        {
            _logger.LogWarning("Network threat blocker is not active");
            return;
        }

        _logger.LogInformation("Stopping network threat blocker...");

        try
        {
            _isActive = false;
            
            // Remove all block rules
            await RemoveAllBlockRulesAsync();

            _logger.LogInformation("Network threat blocker stopped");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error stopping network threat blocker");
            throw;
        }
    }

    /// <summary>
    /// Block an IP address
    /// </summary>
    public async Task<bool> BlockIPAddressAsync(string ipAddress, string reason = "")
    {
        if (string.IsNullOrWhiteSpace(ipAddress))
            return false;

        // Validate IP address
        if (!IPAddress.TryParse(ipAddress, out _))
        {
            _logger.LogWarning("Invalid IP address format: {IPAddress}", ipAddress);
            return false;
        }

        lock (_lock)
        {
            if (_blockedIPs.Contains(ipAddress))
            {
                _logger.LogDebug("IP address already blocked: {IPAddress}", ipAddress);
                return true;
            }

            _blockedIPs.Add(ipAddress);
            _blockTimestamps[ipAddress] = DateTime.UtcNow;
        }

        try
        {
            // Add Windows Firewall rule to block the IP
            await AddFirewallBlockRuleAsync(ipAddress, reason);

            _logger.LogInformation("Blocked IP address: {IPAddress} - Reason: {Reason}", 
                ipAddress, reason);

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to block IP address: {IPAddress}", ipAddress);
            
            lock (_lock)
            {
                _blockedIPs.Remove(ipAddress);
                _blockTimestamps.Remove(ipAddress);
            }
            
            return false;
        }
    }

    /// <summary>
    /// Unblock an IP address
    /// </summary>
    public async Task<bool> UnblockIPAddressAsync(string ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress))
            return false;

        lock (_lock)
        {
            if (!_blockedIPs.Contains(ipAddress))
            {
                _logger.LogDebug("IP address not blocked: {IPAddress}", ipAddress);
                return true;
            }

            _blockedIPs.Remove(ipAddress);
            _blockTimestamps.Remove(ipAddress);
        }

        try
        {
            // Remove Windows Firewall rule
            await RemoveFirewallBlockRuleAsync(ipAddress);

            _logger.LogInformation("Unblocked IP address: {IPAddress}", ipAddress);

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to unblock IP address: {IPAddress}", ipAddress);
            return false;
        }
    }

    /// <summary>
    /// Block a port number
    /// </summary>
    public async Task<bool> BlockPortAsync(int port, string reason = "")
    {
        if (port < 1 || port > 65535)
        {
            _logger.LogWarning("Invalid port number: {Port}", port);
            return false;
        }

        lock (_lock)
        {
            if (_blockedPorts.Contains(port))
            {
                _logger.LogDebug("Port already blocked: {Port}", port);
                return true;
            }

            _blockedPorts.Add(port);
        }

        try
        {
            // Add Windows Firewall rule to block the port
            await AddFirewallPortBlockRuleAsync(port, reason);

            _logger.LogInformation("Blocked port: {Port} - Reason: {Reason}", port, reason);

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to block port: {Port}", port);
            
            lock (_lock)
            {
                _blockedPorts.Remove(port);
            }
            
            return false;
        }
    }

    /// <summary>
    /// Unblock a port number
    /// </summary>
    public async Task<bool> UnblockPortAsync(int port)
    {
        lock (_lock)
        {
            if (!_blockedPorts.Contains(port))
            {
                _logger.LogDebug("Port not blocked: {Port}", port);
                return true;
            }

            _blockedPorts.Remove(port);
        }

        try
        {
            // Remove Windows Firewall rule
            await RemoveFirewallPortBlockRuleAsync(port);

            _logger.LogInformation("Unblocked port: {Port}", port);

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to unblock port: {Port}", port);
            return false;
        }
    }

    /// <summary>
    /// Block network connections based on threat patterns
    /// </summary>
    public async Task<int> BlockThreatPatternsAsync(List<ThreatPattern> patterns)
    {
        int blockedCount = 0;

        foreach (var pattern in patterns)
        {
            // Block IP addresses
            foreach (var ipPattern in pattern.NetworkAddressPatterns)
            {
                // Simple IP blocking (exact match)
                if (IPAddress.TryParse(ipPattern, out _))
                {
                    if (await BlockIPAddressAsync(ipPattern, $"Threat pattern: {pattern.Name}"))
                    {
                        blockedCount++;
                    }
                }
            }

            // Block ports
            foreach (var port in pattern.NetworkPorts)
            {
                if (await BlockPortAsync(port, $"Threat pattern: {pattern.Name}"))
                {
                    blockedCount++;
                }
            }
        }

        _logger.LogInformation("Blocked {Count} network threats from {PatternCount} patterns", 
            blockedCount, patterns.Count);

        return blockedCount;
    }

    /// <summary>
    /// Check if an IP address is blocked
    /// </summary>
    public bool IsIPBlocked(string ipAddress)
    {
        lock (_lock)
        {
            return _blockedIPs.Contains(ipAddress);
        }
    }

    /// <summary>
    /// Check if a port is blocked
    /// </summary>
    public bool IsPortBlocked(int port)
    {
        lock (_lock)
        {
            return _blockedPorts.Contains(port);
        }
    }

    /// <summary>
    /// Get all blocked IP addresses
    /// </summary>
    public List<string> GetBlockedIPs()
    {
        lock (_lock)
        {
            return _blockedIPs.ToList();
        }
    }

    /// <summary>
    /// Get all blocked ports
    /// </summary>
    public List<int> GetBlockedPorts()
    {
        lock (_lock)
        {
            return _blockedPorts.ToList();
        }
    }

    /// <summary>
    /// Get blocking statistics
    /// </summary>
    public NetworkBlockingStatistics GetStatistics()
    {
        lock (_lock)
        {
            return new NetworkBlockingStatistics
            {
                IsActive = _isActive,
                BlockedIPCount = _blockedIPs.Count,
                BlockedPortCount = _blockedPorts.Count,
                TotalBlockedConnections = _blockedIPs.Count + _blockedPorts.Count,
                OldestBlock = _blockTimestamps.Values.Any() 
                    ? _blockTimestamps.Values.Min() 
                    : DateTime.MinValue,
                NewestBlock = _blockTimestamps.Values.Any() 
                    ? _blockTimestamps.Values.Max() 
                    : DateTime.MinValue
            };
        }
    }

    /// <summary>
    /// Clear all blocks
    /// </summary>
    public async Task ClearAllBlocksAsync()
    {
        _logger.LogInformation("Clearing all network blocks...");

        await RemoveAllBlockRulesAsync();

        lock (_lock)
        {
            _blockedIPs.Clear();
            _blockedPorts.Clear();
            _blockTimestamps.Clear();
        }

        _logger.LogInformation("All network blocks cleared");
    }

    private async Task ApplyBlockRulesAsync()
    {
        List<string> ips;
        List<int> ports;

        lock (_lock)
        {
            ips = _blockedIPs.ToList();
            ports = _blockedPorts.ToList();
        }

        foreach (var ip in ips)
        {
            await AddFirewallBlockRuleAsync(ip, "Reapplied on startup");
        }

        foreach (var port in ports)
        {
            await AddFirewallPortBlockRuleAsync(port, "Reapplied on startup");
        }
    }

    private async Task RemoveAllBlockRulesAsync()
    {
        List<string> ips;
        List<int> ports;

        lock (_lock)
        {
            ips = _blockedIPs.ToList();
            ports = _blockedPorts.ToList();
        }

        foreach (var ip in ips)
        {
            await RemoveFirewallBlockRuleAsync(ip);
        }

        foreach (var port in ports)
        {
            await RemoveFirewallPortBlockRuleAsync(port);
        }
    }

    private async Task AddFirewallBlockRuleAsync(string ipAddress, string reason)
    {
        try
        {
            var ruleName = $"WindowsHoneypot_Block_{ipAddress.Replace(".", "_")}";
            
            // Use netsh to add firewall rule
            var arguments = $"advfirewall firewall add rule name=\"{ruleName}\" " +
                          $"dir=out action=block remoteip={ipAddress} " +
                          $"description=\"{reason}\"";

            await ExecuteNetshCommandAsync(arguments);

            // Also block inbound
            arguments = $"advfirewall firewall add rule name=\"{ruleName}_In\" " +
                       $"dir=in action=block remoteip={ipAddress} " +
                       $"description=\"{reason}\"";

            await ExecuteNetshCommandAsync(arguments);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to add firewall block rule for IP: {IPAddress}", ipAddress);
            throw;
        }
    }

    private async Task RemoveFirewallBlockRuleAsync(string ipAddress)
    {
        try
        {
            var ruleName = $"WindowsHoneypot_Block_{ipAddress.Replace(".", "_")}";
            
            // Remove outbound rule
            var arguments = $"advfirewall firewall delete rule name=\"{ruleName}\"";
            await ExecuteNetshCommandAsync(arguments);

            // Remove inbound rule
            arguments = $"advfirewall firewall delete rule name=\"{ruleName}_In\"";
            await ExecuteNetshCommandAsync(arguments);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to remove firewall block rule for IP: {IPAddress}", ipAddress);
            throw;
        }
    }

    private async Task AddFirewallPortBlockRuleAsync(int port, string reason)
    {
        try
        {
            var ruleName = $"WindowsHoneypot_BlockPort_{port}";
            
            // Block outbound
            var arguments = $"advfirewall firewall add rule name=\"{ruleName}\" " +
                          $"dir=out action=block protocol=TCP localport={port} " +
                          $"description=\"{reason}\"";

            await ExecuteNetshCommandAsync(arguments);

            // Block inbound
            arguments = $"advfirewall firewall add rule name=\"{ruleName}_In\" " +
                       $"dir=in action=block protocol=TCP localport={port} " +
                       $"description=\"{reason}\"";

            await ExecuteNetshCommandAsync(arguments);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to add firewall port block rule for port: {Port}", port);
            throw;
        }
    }

    private async Task RemoveFirewallPortBlockRuleAsync(int port)
    {
        try
        {
            var ruleName = $"WindowsHoneypot_BlockPort_{port}";
            
            // Remove outbound rule
            var arguments = $"advfirewall firewall delete rule name=\"{ruleName}\"";
            await ExecuteNetshCommandAsync(arguments);

            // Remove inbound rule
            arguments = $"advfirewall firewall delete rule name=\"{ruleName}_In\"";
            await ExecuteNetshCommandAsync(arguments);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to remove firewall port block rule for port: {Port}", port);
            throw;
        }
    }

    private async Task ExecuteNetshCommandAsync(string arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "netsh",
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using var process = new Process { StartInfo = startInfo };
        process.Start();

        var output = await process.StandardOutput.ReadToEndAsync();
        var error = await process.StandardError.ReadToEndAsync();

        await process.WaitForExitAsync();

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"netsh command failed with exit code {process.ExitCode}. Error: {error}");
        }

        _logger.LogDebug("netsh command executed: {Arguments}", arguments);
    }
}

/// <summary>
/// Network blocking statistics
/// </summary>
public class NetworkBlockingStatistics
{
    public bool IsActive { get; set; }
    public int BlockedIPCount { get; set; }
    public int BlockedPortCount { get; set; }
    public int TotalBlockedConnections { get; set; }
    public DateTime OldestBlock { get; set; }
    public DateTime NewestBlock { get; set; }
}
