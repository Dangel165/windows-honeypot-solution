namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Complete honeypot configuration including all user-customizable settings
/// Requirement 10: Configuration management and user customization
/// </summary>
public class HoneypotConfiguration
{
    /// <summary>
    /// Unique identifier for this configuration profile
    /// </summary>
    public Guid ProfileId { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Name of this configuration profile
    /// Requirement 10.6: Profile save/load functionality
    /// </summary>
    public string ProfileName { get; set; } = "Default";

    /// <summary>
    /// Description of this configuration profile
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Bait folder path configuration
    /// Requirement 10.1: Bait folder path configuration
    /// </summary>
    public string BaitFolderPath { get; set; } = "C:\\BaitFolder";

    /// <summary>
    /// Additional folders to monitor
    /// Requirement 10.4: Custom folder monitoring
    /// </summary>
    public List<string> MonitoredFolders { get; set; } = new();

    /// <summary>
    /// File extensions to monitor (e.g., ".docx", ".xlsx", ".pdf")
    /// Requirement 10.4: Custom file extensions monitoring
    /// </summary>
    public List<string> MonitoredFileExtensions { get; set; } = new()
    {
        ".docx", ".xlsx", ".pdf", ".txt", ".pptx", ".zip", ".rar"
    };

    /// <summary>
    /// Alert configuration settings
    /// Requirement 10.2: Alert method selection
    /// </summary>
    public AlertConfiguration AlertSettings { get; set; } = new();

    /// <summary>
    /// Log management configuration
    /// Requirement 10.3: Log retention and file size limits
    /// </summary>
    public LogConfiguration LogSettings { get; set; } = new();

    /// <summary>
    /// Hardware spoofing level
    /// Requirement 10.5: Hardware spoofing level adjustment
    /// </summary>
    public DeceptionLevel HardwareSpoofingLevel { get; set; } = DeceptionLevel.Medium;

    /// <summary>
    /// Sandbox configuration settings
    /// </summary>
    public SandboxConfiguration SandboxSettings { get; set; } = new();

    /// <summary>
    /// Process camouflage settings
    /// </summary>
    public List<ProcessProfile> FakeProcessProfiles { get; set; } = new();

    /// <summary>
    /// Honey account settings
    /// </summary>
    public List<HoneyAccount> HoneyAccounts { get; set; } = new();

    /// <summary>
    /// Community intelligence settings
    /// </summary>
    public CommunityIntelligenceConfiguration CommunitySettings { get; set; } = new();

    /// <summary>
    /// Timestamp when this profile was created
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Timestamp when this profile was last modified
    /// </summary>
    public DateTime LastModifiedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Whether this is the default profile
    /// </summary>
    public bool IsDefault { get; set; } = false;
}

/// <summary>
/// Alert configuration settings
/// Requirement 10.2: Alert method selection (sound, popup, email)
/// </summary>
public class AlertConfiguration
{
    /// <summary>
    /// Enable sound alerts
    /// </summary>
    public bool EnableSoundAlert { get; set; } = true;

    /// <summary>
    /// Enable popup message box alerts
    /// </summary>
    public bool EnablePopupAlert { get; set; } = true;

    /// <summary>
    /// Enable email alerts
    /// </summary>
    public bool EnableEmailAlert { get; set; } = false;

    /// <summary>
    /// Email address to send alerts to
    /// </summary>
    public string EmailAddress { get; set; } = string.Empty;

    /// <summary>
    /// SMTP server for email alerts
    /// </summary>
    public string SmtpServer { get; set; } = string.Empty;

    /// <summary>
    /// SMTP port
    /// </summary>
    public int SmtpPort { get; set; } = 587;

    /// <summary>
    /// SMTP username
    /// </summary>
    public string SmtpUsername { get; set; } = string.Empty;

    /// <summary>
    /// SMTP password (should be encrypted in storage)
    /// </summary>
    public string SmtpPassword { get; set; } = string.Empty;

    /// <summary>
    /// Use SSL for SMTP
    /// </summary>
    public bool SmtpUseSsl { get; set; } = true;

    /// <summary>
    /// Sound file path for audio alerts
    /// </summary>
    public string SoundFilePath { get; set; } = string.Empty;

    /// <summary>
    /// Minimum time between alerts in seconds (to prevent spam)
    /// </summary>
    public int MinimumAlertIntervalSeconds { get; set; } = 5;
}

/// <summary>
/// Log management configuration
/// Requirement 10.3: Log retention period and file size limits
/// </summary>
public class LogConfiguration
{
    /// <summary>
    /// Log retention period in days
    /// </summary>
    public int RetentionDays { get; set; } = 30;

    /// <summary>
    /// Maximum log file size in MB
    /// </summary>
    public int MaxFileSizeMB { get; set; } = 100;

    /// <summary>
    /// Directory to store log files
    /// </summary>
    public string LogDirectory { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "WindowsHoneypot",
        "Logs"
    );

    /// <summary>
    /// Enable log encryption
    /// </summary>
    public bool EnableEncryption { get; set; } = true;

    /// <summary>
    /// Enable automatic log backup
    /// </summary>
    public bool EnableAutoBackup { get; set; } = true;

    /// <summary>
    /// Backup directory path
    /// </summary>
    public string BackupDirectory { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "WindowsHoneypot",
        "Backups"
    );

    /// <summary>
    /// Log level (Information, Warning, Error, etc.)
    /// </summary>
    public string LogLevel { get; set; } = "Information";

    /// <summary>
    /// Enable log rotation
    /// </summary>
    public bool EnableLogRotation { get; set; } = true;

    /// <summary>
    /// Maximum number of log files to keep
    /// </summary>
    public int MaxLogFiles { get; set; } = 10;
}

/// <summary>
/// Community intelligence configuration
/// Requirement 15.9: User-configurable information sharing levels
/// </summary>
public class CommunityIntelligenceConfiguration
{
    /// <summary>
    /// Enable community intelligence sharing
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Share attack data with community
    /// Requirement 15.9: Configurable sharing level
    /// </summary>
    public bool ShareAttackData { get; set; } = true;

    /// <summary>
    /// Receive threat feeds from community
    /// </summary>
    public bool ReceiveThreatFeeds { get; set; } = true;

    /// <summary>
    /// Automatically update blacklist from threat feeds
    /// Requirement 15.3: Automatic blacklist updates
    /// </summary>
    public bool AutoUpdateBlacklist { get; set; } = true;

    /// <summary>
    /// Minimum confidence threshold for accepting threat indicators (0-100)
    /// Requirement 15.5: Threat scoring system based on confidence levels
    /// </summary>
    public int MinimumConfidenceThreshold { get; set; } = 70;

    /// <summary>
    /// Cloud server URL for threat intelligence
    /// </summary>
    public string CloudServerUrl { get; set; } = "https://honeypot-intelligence.example.com";

    /// <summary>
    /// API key for cloud service
    /// </summary>
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>
    /// Enable offline mode (use cached data when cloud unavailable)
    /// Requirement 15.8: Offline mode with cached threat data
    /// </summary>
    public bool EnableOfflineMode { get; set; } = true;

    /// <summary>
    /// Share detailed attack patterns (more detailed = less privacy)
    /// Requirement 15.9: Configurable information sharing level
    /// </summary>
    public ThreatSharingLevel SharingLevel { get; set; } = ThreatSharingLevel.Standard;
}

/// <summary>
/// Threat sharing level configuration
/// Requirement 15.9: User-configurable information sharing levels
/// </summary>
public enum ThreatSharingLevel
{
    /// <summary>
    /// Share only IP addresses and basic attack types
    /// </summary>
    Minimal = 0,

    /// <summary>
    /// Share IP addresses, attack types, and patterns (default)
    /// </summary>
    Standard = 1,

    /// <summary>
    /// Share detailed attack information including indicators
    /// </summary>
    Detailed = 2,

    /// <summary>
    /// Share all available information for maximum community protection
    /// </summary>
    Full = 3
}
