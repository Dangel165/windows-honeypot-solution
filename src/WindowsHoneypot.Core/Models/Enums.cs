namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Status of the Windows Sandbox
/// </summary>
public enum SandboxStatus
{
    Stopped,
    Starting,
    Running,
    Stopping,
    Error
}

/// <summary>
/// Level of deception to apply
/// </summary>
public enum DeceptionLevel
{
    None,
    Low,
    Medium,
    High,
    Maximum
}

/// <summary>
/// Status of the deception engine
/// </summary>
public enum DeceptionStatus
{
    Inactive,
    Applying,
    Active,
    Restoring,
    Error
}

/// <summary>
/// Status of network blocking
/// </summary>
public enum NetworkBlockStatus
{
    Inactive,
    Blocking,
    Active,
    Restoring,
    Error
}

/// <summary>
/// Type of attack event
/// </summary>
public enum AttackEventType
{
    FileAccess,
    FileModification,
    FileDeletion,
    FileRename,
    NetworkAttempt,
    CredentialUsage,
    ProcessCreation,
    RegistryAccess,
    PrivilegeEscalation,
    SandboxEscape
}

/// <summary>
/// Severity level of threats
/// </summary>
public enum ThreatSeverity
{
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// Status of the sanitization process
/// </summary>
public enum SanitizationStatus
{
    Idle,
    Running,
    Completed,
    Failed,
    Emergency
}

/// <summary>
/// Type of sanitization operation
/// </summary>
public enum SanitizationOperationType
{
    SandboxDataDeletion,
    FirewallRestoration,
    RegistryCleanup,
    TemporaryFileCleanup,
    NetworkReset,
    SystemValidation
}