using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Complete network isolation during sandbox execution using Windows Firewall API
/// </summary>
public class NetworkBlocker : INetworkBlocker, IDisposable
{
    private readonly ILogger<NetworkBlocker> _logger;
    private readonly ConcurrentBag<NetworkAttempt> _blockedAttempts;
    private readonly object _lock = new();
    private NetworkBlockStatus _status;
    private bool _disposed;
    private readonly List<string> _createdRuleNames;
    private const string RULE_PREFIX = "WindowsHoneypot_Block_";

    public NetworkBlocker(ILogger<NetworkBlocker> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _blockedAttempts = new ConcurrentBag<NetworkAttempt>();
        _status = NetworkBlockStatus.Inactive;
        _createdRuleNames = new List<string>();
    }

    public event EventHandler<NetworkAttemptBlockedEventArgs>? NetworkAttemptBlocked;

    public async Task BlockAllTrafficAsync()
    {
        lock (_lock)
        {
            if (_status == NetworkBlockStatus.Active || _status == NetworkBlockStatus.Blocking)
            {
                _logger.LogWarning("Network blocking is already active or in progress");
                return;
            }

            _status = NetworkBlockStatus.Blocking;
        }

        try
        {
            _logger.LogInformation("Starting network traffic blocking...");

            // Create unique rule names with timestamp
            var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            var inboundRuleName = $"{RULE_PREFIX}Inbound_{timestamp}";
            var outboundRuleName = $"{RULE_PREFIX}Outbound_{timestamp}";

            // Block all inbound traffic
            await CreateFirewallRuleAsync(
                inboundRuleName,
                "Block all inbound traffic for Windows Honeypot",
                "in",
                "block"
            );

            // Block all outbound traffic
            await CreateFirewallRuleAsync(
                outboundRuleName,
                "Block all outbound traffic for Windows Honeypot",
                "out",
                "block"
            );

            lock (_lock)
            {
                _createdRuleNames.Add(inboundRuleName);
                _createdRuleNames.Add(outboundRuleName);
                _status = NetworkBlockStatus.Active;
            }

            _logger.LogInformation("Network traffic blocking activated successfully");
        }
        catch (Exception ex)
        {
            lock (_lock)
            {
                _status = NetworkBlockStatus.Error;
            }
            _logger.LogError(ex, "Failed to block network traffic");
            throw;
        }
    }

    public async Task RestoreFirewallRulesAsync()
    {
        lock (_lock)
        {
            if (_status == NetworkBlockStatus.Inactive)
            {
                _logger.LogWarning("Network blocking is not active, nothing to restore");
                return;
            }

            _status = NetworkBlockStatus.Restoring;
        }

        try
        {
            _logger.LogInformation("Restoring firewall rules...");

            List<string> rulesToRemove;
            lock (_lock)
            {
                rulesToRemove = new List<string>(_createdRuleNames);
            }

            foreach (var ruleName in rulesToRemove)
            {
                await RemoveFirewallRuleAsync(ruleName);
            }

            lock (_lock)
            {
                _createdRuleNames.Clear();
                _status = NetworkBlockStatus.Inactive;
            }

            _logger.LogInformation("Firewall rules restored successfully");
        }
        catch (Exception ex)
        {
            lock (_lock)
            {
                _status = NetworkBlockStatus.Error;
            }
            _logger.LogError(ex, "Failed to restore firewall rules");
            throw;
        }
    }

    public NetworkBlockStatus GetBlockStatus()
    {
        lock (_lock)
        {
            return _status;
        }
    }

    public List<NetworkAttempt> GetBlockedAttempts()
    {
        return _blockedAttempts.ToList();
    }

    /// <summary>
    /// Logs a blocked network attempt
    /// </summary>
    public void LogBlockedAttempt(NetworkAttempt attempt)
    {
        if (attempt == null)
        {
            throw new ArgumentNullException(nameof(attempt));
        }

        _blockedAttempts.Add(attempt);
        
        _logger.LogWarning(
            "Network attempt blocked: {Protocol} {Direction} from {SourceIP}:{SourcePort} to {DestIP}:{DestPort} by process {ProcessName} (PID: {ProcessId})",
            attempt.Protocol,
            attempt.Direction,
            attempt.SourceIP,
            attempt.SourcePort,
            attempt.DestinationIP,
            attempt.DestinationPort,
            attempt.ProcessName,
            attempt.ProcessId
        );

        NetworkAttemptBlocked?.Invoke(this, new NetworkAttemptBlockedEventArgs
        {
            NetworkAttempt = attempt
        });
    }

    /// <summary>
    /// Creates a Windows Firewall rule using netsh command
    /// </summary>
    private async Task CreateFirewallRuleAsync(string ruleName, string description, string direction, string action)
    {
        try
        {
            var arguments = $"advfirewall firewall add rule name=\"{ruleName}\" " +
                          $"description=\"{description}\" " +
                          $"dir={direction} " +
                          $"action={action} " +
                          $"enable=yes " +
                          $"profile=any";

            var result = await ExecuteNetshCommandAsync(arguments);

            if (!result.Success)
            {
                throw new InvalidOperationException($"Failed to create firewall rule: {result.Error}");
            }

            _logger.LogInformation("Created firewall rule: {RuleName}", ruleName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating firewall rule: {RuleName}", ruleName);
            throw;
        }
    }

    /// <summary>
    /// Removes a Windows Firewall rule using netsh command
    /// </summary>
    private async Task RemoveFirewallRuleAsync(string ruleName)
    {
        try
        {
            var arguments = $"advfirewall firewall delete rule name=\"{ruleName}\"";

            var result = await ExecuteNetshCommandAsync(arguments);

            if (!result.Success)
            {
                _logger.LogWarning("Failed to remove firewall rule {RuleName}: {Error}", ruleName, result.Error);
            }
            else
            {
                _logger.LogInformation("Removed firewall rule: {RuleName}", ruleName);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing firewall rule: {RuleName}", ruleName);
        }
    }

    /// <summary>
    /// Executes a netsh command and returns the result
    /// </summary>
    private async Task<(bool Success, string Output, string Error)> ExecuteNetshCommandAsync(string arguments)
    {
        try
        {
            var processStartInfo = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                Verb = "runas" // Request administrator privileges
            };

            using var process = new Process { StartInfo = processStartInfo };
            
            var outputBuilder = new System.Text.StringBuilder();
            var errorBuilder = new System.Text.StringBuilder();

            process.OutputDataReceived += (sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                {
                    outputBuilder.AppendLine(e.Data);
                }
            };

            process.ErrorDataReceived += (sender, e) =>
            {
                if (!string.IsNullOrEmpty(e.Data))
                {
                    errorBuilder.AppendLine(e.Data);
                }
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            await process.WaitForExitAsync();

            var output = outputBuilder.ToString();
            var error = errorBuilder.ToString();
            var success = process.ExitCode == 0;

            return (success, output, error);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error executing netsh command: {Arguments}", arguments);
            return (false, string.Empty, ex.Message);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        // Attempt to restore firewall rules on disposal
        try
        {
            RestoreFirewallRulesAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error restoring firewall rules during disposal");
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
