using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Interfaces;

/// <summary>
/// Interface for managing honeypot configuration and profiles
/// Requirement 10: Configuration management and user customization
/// </summary>
public interface IConfigurationManager
{
    /// <summary>
    /// Get the current active configuration
    /// </summary>
    /// <returns>Current honeypot configuration</returns>
    HoneypotConfiguration GetCurrentConfiguration();

    /// <summary>
    /// Update the current configuration
    /// Requirement 10.1-10.5: User-configurable settings
    /// </summary>
    /// <param name="configuration">Updated configuration</param>
    /// <returns>True if successful</returns>
    Task<bool> UpdateConfigurationAsync(HoneypotConfiguration configuration);

    /// <summary>
    /// Save configuration as a named profile
    /// Requirement 10.6: Profile save functionality
    /// </summary>
    /// <param name="configuration">Configuration to save</param>
    /// <param name="profileName">Name for the profile</param>
    /// <returns>Profile ID if successful</returns>
    Task<Guid?> SaveProfileAsync(HoneypotConfiguration configuration, string profileName);

    /// <summary>
    /// Load a configuration profile by ID
    /// Requirement 10.6: Profile load functionality
    /// </summary>
    /// <param name="profileId">Profile ID to load</param>
    /// <returns>Configuration if found, null otherwise</returns>
    Task<HoneypotConfiguration?> LoadProfileAsync(Guid profileId);

    /// <summary>
    /// Load a configuration profile by name
    /// Requirement 10.6: Profile load functionality
    /// </summary>
    /// <param name="profileName">Profile name to load</param>
    /// <returns>Configuration if found, null otherwise</returns>
    Task<HoneypotConfiguration?> LoadProfileByNameAsync(string profileName);

    /// <summary>
    /// Get all available configuration profiles
    /// </summary>
    /// <returns>List of all profiles</returns>
    Task<List<HoneypotConfiguration>> GetAllProfilesAsync();

    /// <summary>
    /// Delete a configuration profile
    /// </summary>
    /// <param name="profileId">Profile ID to delete</param>
    /// <returns>True if successful</returns>
    Task<bool> DeleteProfileAsync(Guid profileId);

    /// <summary>
    /// Set a profile as the default
    /// </summary>
    /// <param name="profileId">Profile ID to set as default</param>
    /// <returns>True if successful</returns>
    Task<bool> SetDefaultProfileAsync(Guid profileId);

    /// <summary>
    /// Get the default configuration profile
    /// </summary>
    /// <returns>Default configuration</returns>
    Task<HoneypotConfiguration> GetDefaultProfileAsync();

    /// <summary>
    /// Export configuration to file
    /// </summary>
    /// <param name="configuration">Configuration to export</param>
    /// <param name="filePath">File path to export to</param>
    /// <returns>True if successful</returns>
    Task<bool> ExportConfigurationAsync(HoneypotConfiguration configuration, string filePath);

    /// <summary>
    /// Import configuration from file
    /// </summary>
    /// <param name="filePath">File path to import from</param>
    /// <returns>Imported configuration if successful</returns>
    Task<HoneypotConfiguration?> ImportConfigurationAsync(string filePath);

    /// <summary>
    /// Validate configuration settings
    /// </summary>
    /// <param name="configuration">Configuration to validate</param>
    /// <returns>Validation result with any errors</returns>
    Models.ValidationResult ValidateConfiguration(HoneypotConfiguration configuration);

    /// <summary>
    /// Reset configuration to factory defaults
    /// </summary>
    /// <returns>Default configuration</returns>
    HoneypotConfiguration ResetToDefaults();
}
