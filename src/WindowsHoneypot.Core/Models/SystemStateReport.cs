namespace WindowsHoneypot.Core.Models;

/// <summary>
/// System state verification report after sanitization
/// </summary>
public class SystemStateReport
{
    /// <summary>
    /// Timestamp when the report was generated
    /// </summary>
    public DateTime GeneratedAt { get; set; }

    /// <summary>
    /// Overall system health status
    /// </summary>
    public bool IsHealthy { get; set; }

    /// <summary>
    /// Sandbox process status
    /// </summary>
    public ProcessStatus SandboxStatus { get; set; } = new();

    /// <summary>
    /// Firewall rules status
    /// </summary>
    public FirewallStatus FirewallStatus { get; set; } = new();

    /// <summary>
    /// Registry status
    /// </summary>
    public RegistryStatus RegistryStatus { get; set; } = new();

    /// <summary>
    /// File system status
    /// </summary>
    public FileSystemStatus FileSystemStatus { get; set; } = new();

    /// <summary>
    /// Network status
    /// </summary>
    public NetworkStatus NetworkStatus { get; set; } = new();

    /// <summary>
    /// List of issues found during validation
    /// </summary>
    public List<string> Issues { get; set; } = new();

    /// <summary>
    /// List of recommendations
    /// </summary>
    public List<string> Recommendations { get; set; } = new();
}

/// <summary>
/// Process status information
/// </summary>
public class ProcessStatus
{
    public bool SandboxProcessRunning { get; set; }
    public int ActiveHoneypotProcesses { get; set; }
    public List<string> ProcessNames { get; set; } = new();
}

/// <summary>
/// Firewall status information
/// </summary>
public class FirewallStatus
{
    public bool CustomRulesRemoved { get; set; }
    public int RemainingHoneypotRules { get; set; }
    public bool FirewallEnabled { get; set; }
    public List<string> ActiveRuleNames { get; set; } = new();
}

/// <summary>
/// Registry status information
/// </summary>
public class RegistryStatus
{
    public bool ModificationsReverted { get; set; }
    public int RemainingModifications { get; set; }
    public List<string> ModifiedKeys { get; set; } = new();
}

/// <summary>
/// File system status information
/// </summary>
public class FileSystemStatus
{
    public bool SandboxDataDeleted { get; set; }
    public bool TemporaryFilesCleared { get; set; }
    public long RemainingDataSize { get; set; }
    public List<string> RemainingFiles { get; set; } = new();
}

/// <summary>
/// Network status information
/// </summary>
public class NetworkStatus
{
    public bool NetworkReset { get; set; }
    public int ActiveConnections { get; set; }
    public bool InternetAccessible { get; set; }
    public List<string> ActiveConnectionDetails { get; set; } = new();
}
