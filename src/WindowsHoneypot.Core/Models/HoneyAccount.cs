namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Represents a fake account used to trap attackers
/// </summary>
public class HoneyAccount
{
    /// <summary>
    /// Unique identifier for the honey account
    /// </summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Fake username
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Fake password
    /// </summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Fake website or service URL
    /// </summary>
    public string ServiceUrl { get; set; } = string.Empty;

    /// <summary>
    /// Display name for the service
    /// </summary>
    public string ServiceName { get; set; } = string.Empty;

    /// <summary>
    /// Description of the account
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Whether to plant this in browser bookmarks
    /// </summary>
    public bool PlantInBookmarks { get; set; } = true;

    /// <summary>
    /// Whether to plant this in text files
    /// </summary>
    public bool PlantInTextFiles { get; set; } = true;

    /// <summary>
    /// Whether to plant this in browser saved passwords
    /// </summary>
    public bool PlantInSavedPasswords { get; set; } = false;

    /// <summary>
    /// Additional metadata for the account
    /// </summary>
    public Dictionary<string, string> Metadata { get; set; } = new();

    /// <summary>
    /// Number of times this account has been accessed
    /// </summary>
    public int AccessCount { get; set; } = 0;

    /// <summary>
    /// Last time this account was accessed
    /// </summary>
    public DateTime? LastAccessed { get; set; }
}