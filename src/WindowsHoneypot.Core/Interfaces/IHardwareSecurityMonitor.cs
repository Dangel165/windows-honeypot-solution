using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Interfaces;

/// <summary>
/// Hardware security monitor for detecting hardware-level attacks
/// Monitors BIOS/UEFI firmware, bootkits, rootkits, DMA attacks, and hardware keyloggers
/// Task 19.3: Hardware-level attack detection
/// </summary>
public interface IHardwareSecurityMonitor
{
    /// <summary>
    /// Check BIOS/UEFI firmware integrity using TPM
    /// </summary>
    Task<FirmwareIntegrityStatus> CheckFirmwareIntegrityAsync();

    /// <summary>
    /// Detect bootkit installation attempts
    /// </summary>
    Task<bool> DetectBootkitAsync();

    /// <summary>
    /// Detect rootkit presence through kernel-mode driver analysis
    /// </summary>
    Task<bool> DetectRootkitAsync();

    /// <summary>
    /// Validate Secure Boot configuration
    /// </summary>
    Task<bool> ValidateSecureBootAsync();

    /// <summary>
    /// Monitor for DMA attacks and unauthorized DMA-capable devices
    /// </summary>
    Task<bool> DetectDMAAttackAsync();

    /// <summary>
    /// Detect hardware keyloggers through USB device monitoring
    /// </summary>
    Task<bool> DetectHardwareKeyloggerAsync();

    /// <summary>
    /// Monitor hardware device changes
    /// </summary>
    void MonitorHardwareChanges();

    /// <summary>
    /// Stop hardware monitoring
    /// </summary>
    void StopMonitoring();

    /// <summary>
    /// Get list of detected hardware attacks
    /// </summary>
    List<HardwareAttackIndicator> GetDetectedAttacks();

    /// <summary>
    /// Event raised when hardware attack is detected
    /// </summary>
    event EventHandler<HardwareAttackEventArgs> HardwareAttackDetected;
}
