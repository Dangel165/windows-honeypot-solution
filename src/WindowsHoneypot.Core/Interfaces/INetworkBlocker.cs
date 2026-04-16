using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Interfaces;

/// <summary>
/// Complete network isolation during sandbox execution
/// </summary>
public interface INetworkBlocker
{
    /// <summary>
    /// Blocks all network traffic using Windows Firewall API
    /// </summary>
    Task BlockAllTrafficAsync();

    /// <summary>
    /// Restores original firewall rules
    /// </summary>
    Task RestoreFirewallRulesAsync();

    /// <summary>
    /// Gets the current network blocking status
    /// </summary>
    /// <returns>Current network block status</returns>
    NetworkBlockStatus GetBlockStatus();

    /// <summary>
    /// Gets a list of blocked network attempts
    /// </summary>
    /// <returns>List of network attempts that were blocked</returns>
    List<NetworkAttempt> GetBlockedAttempts();

    /// <summary>
    /// Event fired when a network attempt is blocked
    /// </summary>
    event EventHandler<NetworkAttemptBlockedEventArgs>? NetworkAttemptBlocked;
}