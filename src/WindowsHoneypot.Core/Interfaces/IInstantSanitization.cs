using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Interfaces;

/// <summary>
/// One-click cleanup with physical data deletion, firewall rule restoration, and registry cleanup
/// </summary>
public interface IInstantSanitization
{
    /// <summary>
    /// Performs complete system sanitization with progress reporting
    /// </summary>
    /// <param name="progress">Progress reporter for real-time updates</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Sanitization result with verification report</returns>
    Task<SanitizationResult> SanitizeAsync(IProgress<SanitizationProgress>? progress = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs emergency sanitization without progress reporting
    /// </summary>
    /// <returns>True if sanitization succeeded</returns>
    Task<bool> EmergencySanitizeAsync();

    /// <summary>
    /// Gets the current sanitization status
    /// </summary>
    SanitizationStatus GetStatus();

    /// <summary>
    /// Validates system state after sanitization
    /// </summary>
    /// <returns>System state verification report</returns>
    Task<SystemStateReport> ValidateSystemStateAsync();
}
