namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Represents a hardware-level attack indicator
/// Task 19.3: Hardware attack detection models
/// </summary>
public class HardwareAttackIndicator
{
    public string IndicatorId { get; set; } = Guid.NewGuid().ToString();
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    
    // Attack details
    public HardwareAttackType AttackType { get; set; }
    public string Description { get; set; } = string.Empty;
    public ThreatSeverity Severity { get; set; }
    public double ConfidenceScore { get; set; }
    
    // Hardware information
    public string DeviceId { get; set; } = string.Empty;
    public string DeviceName { get; set; } = string.Empty;
    public string DeviceType { get; set; } = string.Empty;
    public string VendorId { get; set; } = string.Empty;
    public string ProductId { get; set; } = string.Empty;
    
    // Attack specifics
    public Dictionary<string, object> AttackMetadata { get; set; } = new();
    public List<string> DetectionMethods { get; set; } = new();
    public List<string> AffectedComponents { get; set; } = new();
    
    // Firmware/BIOS specific
    public string? FirmwareVersion { get; set; }
    public string? ExpectedHash { get; set; }
    public string? ActualHash { get; set; }
    public bool? SecureBootEnabled { get; set; }
    
    // Driver specific (for rootkits)
    public string? DriverPath { get; set; }
    public string? DriverSignature { get; set; }
    public bool? IsDriverSigned { get; set; }
    
    // USB/Device specific (for keyloggers)
    public string? USBPort { get; set; }
    public DateTime? DeviceConnectedAt { get; set; }
    public bool? IsKnownDevice { get; set; }
}

/// <summary>
/// Types of hardware-level attacks
/// </summary>
public enum HardwareAttackType
{
    // Firmware attacks
    BIOSModification,
    UEFIModification,
    FirmwareRootkit,
    
    // Boot attacks
    BootkitInstallation,
    MBRModification,
    BootSectorInfection,
    SecureBootBypass,
    
    // Kernel attacks
    RootkitDetected,
    KernelDriverManipulation,
    SystemCallHooking,
    
    // DMA attacks
    DMAAttack,
    PCILeechDetected,
    ThunderboltExploit,
    UnauthorizedDMADevice,
    
    // Hardware keyloggers
    HardwareKeylogger,
    USBKeylogger,
    PS2Keylogger,
    KeyboardDriverManipulation,
    
    // Other hardware attacks
    TPMBypass,
    HardwareImplant,
    BadUSB,
    UnauthorizedHardwareChange
}

/// <summary>
/// Firmware integrity status
/// </summary>
public class FirmwareIntegrityStatus
{
    public bool IsIntact { get; set; }
    public string FirmwareType { get; set; } = string.Empty; // BIOS or UEFI
    public string Version { get; set; } = string.Empty;
    public string Manufacturer { get; set; } = string.Empty;
    public DateTime? LastModified { get; set; }
    
    // TPM validation
    public bool TPMAvailable { get; set; }
    public bool TPMEnabled { get; set; }
    public string? TPMVersion { get; set; }
    public bool? TPMValidationPassed { get; set; }
    
    // Hash validation
    public string? ExpectedHash { get; set; }
    public string? ActualHash { get; set; }
    public bool HashMatches { get; set; }
    
    // Secure Boot
    public bool SecureBootSupported { get; set; }
    public bool SecureBootEnabled { get; set; }
    
    // Issues detected
    public List<string> DetectedIssues { get; set; } = new();
    public ThreatSeverity Severity { get; set; }
}

/// <summary>
/// Event args for hardware attack detection
/// </summary>
public class HardwareAttackEventArgs : EventArgs
{
    public HardwareAttackIndicator Indicator { get; set; } = new();
    public string Description { get; set; } = string.Empty;
    public ThreatSeverity Severity { get; set; }
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}
