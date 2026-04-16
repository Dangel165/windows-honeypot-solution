namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Profile information collected about an attacker
/// </summary>
public class AttackerProfile
{
    /// <summary>
    /// Unique session identifier for the attacker
    /// </summary>
    public string SessionId { get; set; } = string.Empty;

    /// <summary>
    /// IP address of the attacker
    /// </summary>
    public string IPAddress { get; set; } = string.Empty;

    /// <summary>
    /// User agent string from the attacker's browser
    /// </summary>
    public string UserAgent { get; set; } = string.Empty;

    /// <summary>
    /// Language settings of the attacker's system
    /// </summary>
    public string Language { get; set; } = string.Empty;

    /// <summary>
    /// Screen resolution of the attacker's system
    /// </summary>
    public string ScreenResolution { get; set; } = string.Empty;

    /// <summary>
    /// List of browser plugins detected
    /// </summary>
    public List<string> BrowserPlugins { get; set; } = new();

    /// <summary>
    /// Timestamp when the attacker was first seen
    /// </summary>
    public DateTime FirstSeen { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// List of honey credentials accessed by the attacker
    /// </summary>
    public List<string> AccessedCredentials { get; set; } = new();

    /// <summary>
    /// Operating system information
    /// </summary>
    public string OperatingSystem { get; set; } = string.Empty;

    /// <summary>
    /// Browser name and version
    /// </summary>
    public string Browser { get; set; } = string.Empty;

    /// <summary>
    /// Timezone of the attacker
    /// </summary>
    public string Timezone { get; set; } = string.Empty;

    /// <summary>
    /// Estimated geographic location
    /// </summary>
    public string GeographicLocation { get; set; } = string.Empty;

    /// <summary>
    /// Additional fingerprinting data
    /// </summary>
    public Dictionary<string, string> FingerprintData { get; set; } = new();

    /// <summary>
    /// Canvas fingerprint hash
    /// </summary>
    public string CanvasFingerprint { get; set; } = string.Empty;

    /// <summary>
    /// WebGL vendor information
    /// </summary>
    public string WebGLVendor { get; set; } = string.Empty;

    /// <summary>
    /// WebGL renderer information
    /// </summary>
    public string WebGLRenderer { get; set; } = string.Empty;

    /// <summary>
    /// Audio fingerprint hash
    /// </summary>
    public string AudioFingerprint { get; set; } = string.Empty;

    /// <summary>
    /// Hardware concurrency (CPU cores)
    /// </summary>
    public string HardwareConcurrency { get; set; } = string.Empty;

    /// <summary>
    /// Device memory in GB
    /// </summary>
    public string DeviceMemory { get; set; } = string.Empty;

    /// <summary>
    /// Platform information
    /// </summary>
    public string Platform { get; set; } = string.Empty;

    /// <summary>
    /// Color depth
    /// </summary>
    public string ColorDepth { get; set; } = string.Empty;

    /// <summary>
    /// Whether cookies are enabled
    /// </summary>
    public bool CookiesEnabled { get; set; }

    /// <summary>
    /// Do Not Track setting
    /// </summary>
    public string DoNotTrack { get; set; } = string.Empty;

    /// <summary>
    /// Encrypted attacker data for evidence storage
    /// </summary>
    public string? EncryptedData { get; set; }

    /// <summary>
    /// Hash of the encrypted data for integrity verification
    /// </summary>
    public string? DataHash { get; set; }
}