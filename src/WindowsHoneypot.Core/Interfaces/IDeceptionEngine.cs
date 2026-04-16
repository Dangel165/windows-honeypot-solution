using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Interfaces;

/// <summary>
/// Hardware and system information spoofing to avoid VM detection
/// </summary>
public interface IDeceptionEngine
{
    /// <summary>
    /// Applies hardware spoofing at the specified level
    /// </summary>
    /// <param name="level">Level of deception to apply</param>
    Task ApplyHardwareSpoofingAsync(DeceptionLevel level);

    /// <summary>
    /// Restores original system settings
    /// </summary>
    Task RestoreOriginalSettingsAsync();

    /// <summary>
    /// Checks if VM detection bypass is currently active
    /// </summary>
    /// <returns>True if bypass is active, false otherwise</returns>
    bool IsVMDetectionBypassActive();

    /// <summary>
    /// Gets the current deception status
    /// </summary>
    /// <returns>Current deception status</returns>
    DeceptionStatus GetDeceptionStatus();
}