using System.Text.Json;
using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Manages honeypot configuration and profiles
/// Requirement 10: Configuration management and user customization
/// </summary>
public class HoneypotConfigurationManager : IConfigurationManager
{
    private readonly ILogger<HoneypotConfigurationManager> _logger;
    private readonly string _configDirectory;
    private readonly string _profilesDirectory;
    private HoneypotConfiguration _currentConfiguration;
    private readonly object _lock = new();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    public HoneypotConfigurationManager(ILogger<HoneypotConfigurationManager> logger)
    {
        _logger = logger;
        
        // Set up configuration directories
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        _configDirectory = Path.Combine(appDataPath, "WindowsHoneypot", "Config");
        _profilesDirectory = Path.Combine(_configDirectory, "Profiles");

        // Ensure directories exist
        Directory.CreateDirectory(_configDirectory);
        Directory.CreateDirectory(_profilesDirectory);

        // Load or create default configuration
        _currentConfiguration = LoadOrCreateDefaultConfiguration();
    }

    /// <summary>
    /// Get the current active configuration
    /// </summary>
    public HoneypotConfiguration GetCurrentConfiguration()
    {
        lock (_lock)
        {
            return CloneConfiguration(_currentConfiguration);
        }
    }

    /// <summary>
    /// Update the current configuration
    /// Requirement 10.1-10.5: User-configurable settings
    /// </summary>
    public async Task<bool> UpdateConfigurationAsync(HoneypotConfiguration configuration)
    {
        try
        {
            // Validate configuration
            var validationResult = ValidateConfiguration(configuration);
            if (!validationResult.IsValid)
            {
                _logger.LogError("Configuration validation failed: {Errors}", 
                    string.Join(", ", validationResult.Errors));
                return false;
            }

            lock (_lock)
            {
                configuration.LastModifiedAt = DateTime.UtcNow;
                _currentConfiguration = CloneConfiguration(configuration);
            }

            // Save to disk
            var currentConfigPath = Path.Combine(_configDirectory, "current.json");
            await SaveConfigurationToFileAsync(configuration, currentConfigPath);

            _logger.LogInformation("Configuration updated successfully");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update configuration");
            return false;
        }
    }

    /// <summary>
    /// Save configuration as a named profile
    /// Requirement 10.6: Profile save functionality
    /// </summary>
    public async Task<Guid?> SaveProfileAsync(HoneypotConfiguration configuration, string profileName)
    {
        try
        {
            // Validate configuration
            var validationResult = ValidateConfiguration(configuration);
            if (!validationResult.IsValid)
            {
                _logger.LogError("Cannot save invalid configuration as profile");
                return null;
            }

            // Update profile metadata
            configuration.ProfileName = profileName;
            configuration.LastModifiedAt = DateTime.UtcNow;

            // If no profile ID, generate new one
            if (configuration.ProfileId == Guid.Empty)
            {
                configuration.ProfileId = Guid.NewGuid();
                configuration.CreatedAt = DateTime.UtcNow;
            }

            // Save to profiles directory
            var profilePath = Path.Combine(_profilesDirectory, $"{configuration.ProfileId}.json");
            await SaveConfigurationToFileAsync(configuration, profilePath);

            _logger.LogInformation("Profile '{ProfileName}' saved with ID {ProfileId}", 
                profileName, configuration.ProfileId);
            return configuration.ProfileId;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save profile '{ProfileName}'", profileName);
            return null;
        }
    }

    /// <summary>
    /// Load a configuration profile by ID
    /// Requirement 10.6: Profile load functionality
    /// </summary>
    public async Task<HoneypotConfiguration?> LoadProfileAsync(Guid profileId)
    {
        try
        {
            var profilePath = Path.Combine(_profilesDirectory, $"{profileId}.json");
            if (!File.Exists(profilePath))
            {
                _logger.LogWarning("Profile {ProfileId} not found", profileId);
                return null;
            }

            var json = await File.ReadAllTextAsync(profilePath);
            var configuration = JsonSerializer.Deserialize<HoneypotConfiguration>(json, JsonOptions);

            if (configuration != null)
            {
                _logger.LogInformation("Profile {ProfileId} loaded successfully", profileId);
            }

            return configuration;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load profile {ProfileId}", profileId);
            return null;
        }
    }

    /// <summary>
    /// Load a configuration profile by name
    /// Requirement 10.6: Profile load functionality
    /// </summary>
    public async Task<HoneypotConfiguration?> LoadProfileByNameAsync(string profileName)
    {
        try
        {
            var profiles = await GetAllProfilesAsync();
            var profile = profiles.FirstOrDefault(p => 
                p.ProfileName.Equals(profileName, StringComparison.OrdinalIgnoreCase));

            if (profile != null)
            {
                _logger.LogInformation("Profile '{ProfileName}' loaded successfully", profileName);
            }
            else
            {
                _logger.LogWarning("Profile '{ProfileName}' not found", profileName);
            }

            return profile;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load profile '{ProfileName}'", profileName);
            return null;
        }
    }

    /// <summary>
    /// Get all available configuration profiles
    /// </summary>
    public async Task<List<HoneypotConfiguration>> GetAllProfilesAsync()
    {
        var profiles = new List<HoneypotConfiguration>();

        try
        {
            var profileFiles = Directory.GetFiles(_profilesDirectory, "*.json");

            foreach (var file in profileFiles)
            {
                try
                {
                    var json = await File.ReadAllTextAsync(file);
                    var profile = JsonSerializer.Deserialize<HoneypotConfiguration>(json, JsonOptions);
                    if (profile != null)
                    {
                        profiles.Add(profile);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to load profile from {File}", file);
                }
            }

            _logger.LogInformation("Loaded {Count} profiles", profiles.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get all profiles");
        }

        return profiles;
    }

    /// <summary>
    /// Delete a configuration profile
    /// </summary>
    public async Task<bool> DeleteProfileAsync(Guid profileId)
    {
        try
        {
            var profilePath = Path.Combine(_profilesDirectory, $"{profileId}.json");
            if (!File.Exists(profilePath))
            {
                _logger.LogWarning("Profile {ProfileId} not found for deletion", profileId);
                return false;
            }

            // Check if it's the default profile
            var profile = await LoadProfileAsync(profileId);
            if (profile?.IsDefault == true)
            {
                _logger.LogError("Cannot delete default profile");
                return false;
            }

            File.Delete(profilePath);
            _logger.LogInformation("Profile {ProfileId} deleted successfully", profileId);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete profile {ProfileId}", profileId);
            return false;
        }
    }

    /// <summary>
    /// Set a profile as the default
    /// </summary>
    public async Task<bool> SetDefaultProfileAsync(Guid profileId)
    {
        try
        {
            // Load the profile to set as default
            var profile = await LoadProfileAsync(profileId);
            if (profile == null)
            {
                _logger.LogError("Profile {ProfileId} not found", profileId);
                return false;
            }

            // Clear default flag from all profiles
            var allProfiles = await GetAllProfilesAsync();
            foreach (var p in allProfiles)
            {
                if (p.IsDefault)
                {
                    p.IsDefault = false;
                    await SaveProfileAsync(p, p.ProfileName);
                }
            }

            // Set new default
            profile.IsDefault = true;
            await SaveProfileAsync(profile, profile.ProfileName);

            _logger.LogInformation("Profile {ProfileId} set as default", profileId);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to set default profile {ProfileId}", profileId);
            return false;
        }
    }

    /// <summary>
    /// Get the default configuration profile
    /// </summary>
    public async Task<HoneypotConfiguration> GetDefaultProfileAsync()
    {
        try
        {
            var profiles = await GetAllProfilesAsync();
            var defaultProfile = profiles.FirstOrDefault(p => p.IsDefault);

            if (defaultProfile != null)
            {
                return defaultProfile;
            }

            // If no default found, return factory defaults
            _logger.LogWarning("No default profile found, returning factory defaults");
            return ResetToDefaults();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get default profile");
            return ResetToDefaults();
        }
    }

    /// <summary>
    /// Export configuration to file
    /// </summary>
    public async Task<bool> ExportConfigurationAsync(HoneypotConfiguration configuration, string filePath)
    {
        try
        {
            await SaveConfigurationToFileAsync(configuration, filePath);
            _logger.LogInformation("Configuration exported to {FilePath}", filePath);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to export configuration to {FilePath}", filePath);
            return false;
        }
    }

    /// <summary>
    /// Import configuration from file
    /// </summary>
    public async Task<HoneypotConfiguration?> ImportConfigurationAsync(string filePath)
    {
        try
        {
            if (!File.Exists(filePath))
            {
                _logger.LogError("Import file not found: {FilePath}", filePath);
                return null;
            }

            var json = await File.ReadAllTextAsync(filePath);
            var configuration = JsonSerializer.Deserialize<HoneypotConfiguration>(json, JsonOptions);

            if (configuration != null)
            {
                // Validate imported configuration
                var validationResult = ValidateConfiguration(configuration);
                if (!validationResult.IsValid)
                {
                    _logger.LogError("Imported configuration is invalid: {Errors}", 
                        string.Join(", ", validationResult.Errors));
                    return null;
                }

                _logger.LogInformation("Configuration imported from {FilePath}", filePath);
            }

            return configuration;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to import configuration from {FilePath}", filePath);
            return null;
        }
    }

    /// <summary>
    /// Validate configuration settings
    /// </summary>
    public ValidationResult ValidateConfiguration(HoneypotConfiguration configuration)
    {
        var result = new ValidationResult { IsValid = true };

        // Validate bait folder path (Requirement 10.1)
        if (string.IsNullOrWhiteSpace(configuration.BaitFolderPath))
        {
            result.Errors.Add("Bait folder path cannot be empty");
            result.IsValid = false;
        }
        else if (!Path.IsPathRooted(configuration.BaitFolderPath))
        {
            result.Errors.Add("Bait folder path must be an absolute path");
            result.IsValid = false;
        }

        // Validate monitored folders (Requirement 10.4)
        foreach (var folder in configuration.MonitoredFolders)
        {
            if (!Path.IsPathRooted(folder))
            {
                result.Errors.Add($"Monitored folder path must be absolute: {folder}");
                result.IsValid = false;
            }
        }

        // Validate file extensions (Requirement 10.4)
        foreach (var ext in configuration.MonitoredFileExtensions)
        {
            if (!ext.StartsWith("."))
            {
                result.Warnings.Add($"File extension should start with '.': {ext}");
            }
        }

        // Validate alert settings (Requirement 10.2)
        if (configuration.AlertSettings.EnableEmailAlert)
        {
            if (string.IsNullOrWhiteSpace(configuration.AlertSettings.EmailAddress))
            {
                result.Errors.Add("Email address is required when email alerts are enabled");
                result.IsValid = false;
            }
            if (string.IsNullOrWhiteSpace(configuration.AlertSettings.SmtpServer))
            {
                result.Errors.Add("SMTP server is required when email alerts are enabled");
                result.IsValid = false;
            }
        }

        // Validate log settings (Requirement 10.3)
        if (configuration.LogSettings.RetentionDays < 1)
        {
            result.Errors.Add("Log retention days must be at least 1");
            result.IsValid = false;
        }
        if (configuration.LogSettings.MaxFileSizeMB < 1)
        {
            result.Errors.Add("Maximum log file size must be at least 1 MB");
            result.IsValid = false;
        }

        // Validate profile name
        if (string.IsNullOrWhiteSpace(configuration.ProfileName))
        {
            result.Errors.Add("Profile name cannot be empty");
            result.IsValid = false;
        }

        return result;
    }

    /// <summary>
    /// Reset configuration to factory defaults
    /// </summary>
    public HoneypotConfiguration ResetToDefaults()
    {
        _logger.LogInformation("Resetting configuration to factory defaults");

        return new HoneypotConfiguration
        {
            ProfileId = Guid.NewGuid(),
            ProfileName = "Default",
            Description = "Factory default configuration",
            BaitFolderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "BaitFolder"),
            MonitoredFolders = new List<string>(),
            MonitoredFileExtensions = new List<string> { ".docx", ".xlsx", ".pdf", ".txt", ".pptx", ".zip", ".rar" },
            AlertSettings = new AlertConfiguration
            {
                EnableSoundAlert = true,
                EnablePopupAlert = true,
                EnableEmailAlert = false,
                MinimumAlertIntervalSeconds = 5
            },
            LogSettings = new LogConfiguration
            {
                RetentionDays = 30,
                MaxFileSizeMB = 100,
                EnableEncryption = true,
                EnableAutoBackup = true,
                LogLevel = "Information",
                EnableLogRotation = true,
                MaxLogFiles = 10
            },
            HardwareSpoofingLevel = DeceptionLevel.Medium,
            SandboxSettings = new SandboxConfiguration
            {
                NetworkingEnabled = false,
                MemoryInMB = 4096,
                DeceptionLevel = DeceptionLevel.Medium
            },
            CommunitySettings = new CommunityIntelligenceConfiguration
            {
                Enabled = true,
                ShareAttackData = true,
                ReceiveThreatFeeds = true,
                AutoUpdateBlacklist = true,
                EnableOfflineMode = true
            },
            IsDefault = true,
            CreatedAt = DateTime.UtcNow,
            LastModifiedAt = DateTime.UtcNow
        };
    }

    // Private helper methods

    private HoneypotConfiguration LoadOrCreateDefaultConfiguration()
    {
        try
        {
            var currentConfigPath = Path.Combine(_configDirectory, "current.json");
            if (File.Exists(currentConfigPath))
            {
                var json = File.ReadAllText(currentConfigPath);
                var config = JsonSerializer.Deserialize<HoneypotConfiguration>(json, JsonOptions);
                if (config != null)
                {
                    _logger.LogInformation("Loaded current configuration");
                    return config;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load current configuration, using defaults");
        }

        return ResetToDefaults();
    }

    private async Task SaveConfigurationToFileAsync(HoneypotConfiguration configuration, string filePath)
    {
        var json = JsonSerializer.Serialize(configuration, JsonOptions);
        await File.WriteAllTextAsync(filePath, json);
    }

    private HoneypotConfiguration CloneConfiguration(HoneypotConfiguration source)
    {
        var json = JsonSerializer.Serialize(source, JsonOptions);
        return JsonSerializer.Deserialize<HoneypotConfiguration>(json, JsonOptions)!;
    }
}
