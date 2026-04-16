using Microsoft.Extensions.Logging;
using Moq;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Unit tests for ConfigurationManager
/// Tests Requirements 10.1-10.6: Configuration management and user customization
/// </summary>
public class ConfigurationManagerTests : IDisposable
{
    private readonly HoneypotConfigurationManager _configManager;
    private readonly Mock<ILogger<HoneypotConfigurationManager>> _mockLogger;
    private readonly string _testConfigDirectory;

    public ConfigurationManagerTests()
    {
        _mockLogger = new Mock<ILogger<HoneypotConfigurationManager>>();
        _configManager = new HoneypotConfigurationManager(_mockLogger.Object);

        // Set up test directory
        _testConfigDirectory = Path.Combine(Path.GetTempPath(), "HoneypotTests", Guid.NewGuid().ToString());
        Directory.CreateDirectory(_testConfigDirectory);
    }

    public void Dispose()
    {
        // Clean up test directory
        if (Directory.Exists(_testConfigDirectory))
        {
            Directory.Delete(_testConfigDirectory, true);
        }
    }

    [Fact]
    public void GetCurrentConfiguration_ReturnsValidConfiguration()
    {
        // Act
        var config = _configManager.GetCurrentConfiguration();

        // Assert
        Assert.NotNull(config);
        Assert.NotNull(config.ProfileName);
        Assert.NotNull(config.AlertSettings);
        Assert.NotNull(config.LogSettings);
        Assert.NotNull(config.SandboxSettings);
    }

    [Fact]
    public async Task UpdateConfigurationAsync_WithValidConfig_ReturnsTrue()
    {
        // Arrange
        var config = _configManager.GetCurrentConfiguration();
        config.BaitFolderPath = "C:\\TestBait";
        config.HardwareSpoofingLevel = DeceptionLevel.High;

        // Act
        var result = await _configManager.UpdateConfigurationAsync(config);

        // Assert
        Assert.True(result);
        var updatedConfig = _configManager.GetCurrentConfiguration();
        Assert.Equal("C:\\TestBait", updatedConfig.BaitFolderPath);
        Assert.Equal(DeceptionLevel.High, updatedConfig.HardwareSpoofingLevel);
    }

    [Fact]
    public async Task UpdateConfigurationAsync_WithInvalidConfig_ReturnsFalse()
    {
        // Arrange
        var config = _configManager.GetCurrentConfiguration();
        config.BaitFolderPath = ""; // Invalid: empty path

        // Act
        var result = await _configManager.UpdateConfigurationAsync(config);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task SaveProfileAsync_WithValidConfig_ReturnsProfileId()
    {
        // Arrange
        var config = _configManager.GetCurrentConfiguration();
        config.ProfileName = "Test Profile";
        config.Description = "Test description";

        // Act
        var profileId = await _configManager.SaveProfileAsync(config, "Test Profile");

        // Assert
        Assert.NotNull(profileId);
        Assert.NotEqual(Guid.Empty, profileId.Value);
    }

    [Fact]
    public async Task LoadProfileAsync_WithExistingProfile_ReturnsConfiguration()
    {
        // Arrange
        var config = _configManager.GetCurrentConfiguration();
        config.ProfileName = "Load Test Profile";
        var profileId = await _configManager.SaveProfileAsync(config, "Load Test Profile");
        Assert.NotNull(profileId);

        // Act
        var loadedConfig = await _configManager.LoadProfileAsync(profileId.Value);

        // Assert
        Assert.NotNull(loadedConfig);
        Assert.Equal("Load Test Profile", loadedConfig.ProfileName);
        Assert.Equal(profileId.Value, loadedConfig.ProfileId);
    }

    [Fact]
    public async Task LoadProfileAsync_WithNonExistentProfile_ReturnsNull()
    {
        // Arrange
        var nonExistentId = Guid.NewGuid();

        // Act
        var loadedConfig = await _configManager.LoadProfileAsync(nonExistentId);

        // Assert
        Assert.Null(loadedConfig);
    }

    [Fact]
    public async Task LoadProfileByNameAsync_WithExistingProfile_ReturnsConfiguration()
    {
        // Arrange
        var config = _configManager.GetCurrentConfiguration();
        config.ProfileName = "Named Profile Test";
        await _configManager.SaveProfileAsync(config, "Named Profile Test");

        // Act
        var loadedConfig = await _configManager.LoadProfileByNameAsync("Named Profile Test");

        // Assert
        Assert.NotNull(loadedConfig);
        Assert.Equal("Named Profile Test", loadedConfig.ProfileName);
    }

    [Fact]
    public async Task GetAllProfilesAsync_ReturnsProfiles()
    {
        // Arrange
        var uniqueName = "GetAllTest_" + Guid.NewGuid().ToString("N").Substring(0, 8);
        var config = _configManager.GetCurrentConfiguration();
        config.ProfileName = uniqueName;
        var savedId = await _configManager.SaveProfileAsync(config, uniqueName);
        Assert.NotNull(savedId);

        // Act
        var profiles = await _configManager.GetAllProfilesAsync();

        // Assert
        Assert.NotNull(profiles);
        Assert.Contains(profiles, p => p.ProfileName == uniqueName);
    }

    [Fact]
    public async Task DeleteProfileAsync_WithExistingProfile_ReturnsTrue()
    {
        // Arrange
        var config = _configManager.GetCurrentConfiguration();
        config.ProfileName = "Delete Test Profile";
        config.IsDefault = false; // Ensure it's not default
        var profileId = await _configManager.SaveProfileAsync(config, "Delete Test Profile");
        Assert.NotNull(profileId);

        // Act
        var result = await _configManager.DeleteProfileAsync(profileId.Value);

        // Assert
        Assert.True(result);
        var deletedProfile = await _configManager.LoadProfileAsync(profileId.Value);
        Assert.Null(deletedProfile);
    }

    [Fact]
    public async Task SetDefaultProfileAsync_SetsProfileAsDefault()
    {
        // Arrange
        var config = _configManager.GetCurrentConfiguration();
        config.ProfileName = "New Default Profile";
        var profileId = await _configManager.SaveProfileAsync(config, "New Default Profile");
        Assert.NotNull(profileId);

        // Act
        var result = await _configManager.SetDefaultProfileAsync(profileId.Value);

        // Assert
        Assert.True(result);
        var defaultProfile = await _configManager.GetDefaultProfileAsync();
        Assert.Equal(profileId.Value, defaultProfile.ProfileId);
    }

    [Fact]
    public void ValidateConfiguration_WithValidConfig_ReturnsValid()
    {
        // Arrange
        var config = new HoneypotConfiguration
        {
            ProfileName = "Valid Config",
            BaitFolderPath = "C:\\ValidPath",
            AlertSettings = new AlertConfiguration
            {
                EnableEmailAlert = false
            },
            LogSettings = new LogConfiguration
            {
                RetentionDays = 30,
                MaxFileSizeMB = 100
            }
        };

        // Act
        var result = _configManager.ValidateConfiguration(config);

        // Assert
        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void ValidateConfiguration_WithEmptyBaitFolder_ReturnsInvalid()
    {
        // Arrange
        var config = new HoneypotConfiguration
        {
            ProfileName = "Invalid Config",
            BaitFolderPath = "", // Invalid
            LogSettings = new LogConfiguration
            {
                RetentionDays = 30,
                MaxFileSizeMB = 100
            }
        };

        // Act
        var result = _configManager.ValidateConfiguration(config);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("Bait folder path"));
    }

    [Fact]
    public void ValidateConfiguration_WithRelativePath_ReturnsInvalid()
    {
        // Arrange
        var config = new HoneypotConfiguration
        {
            ProfileName = "Invalid Config",
            BaitFolderPath = "RelativePath", // Invalid: not absolute
            LogSettings = new LogConfiguration
            {
                RetentionDays = 30,
                MaxFileSizeMB = 100
            }
        };

        // Act
        var result = _configManager.ValidateConfiguration(config);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("absolute path"));
    }

    [Fact]
    public void ValidateConfiguration_WithEmailAlertButNoEmail_ReturnsInvalid()
    {
        // Arrange
        var config = new HoneypotConfiguration
        {
            ProfileName = "Invalid Config",
            BaitFolderPath = "C:\\ValidPath",
            AlertSettings = new AlertConfiguration
            {
                EnableEmailAlert = true,
                EmailAddress = "", // Invalid: email required
                SmtpServer = ""
            },
            LogSettings = new LogConfiguration
            {
                RetentionDays = 30,
                MaxFileSizeMB = 100
            }
        };

        // Act
        var result = _configManager.ValidateConfiguration(config);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("Email address"));
        Assert.Contains(result.Errors, e => e.Contains("SMTP server"));
    }

    [Fact]
    public void ValidateConfiguration_WithInvalidLogSettings_ReturnsInvalid()
    {
        // Arrange
        var config = new HoneypotConfiguration
        {
            ProfileName = "Invalid Config",
            BaitFolderPath = "C:\\ValidPath",
            LogSettings = new LogConfiguration
            {
                RetentionDays = 0, // Invalid: must be at least 1
                MaxFileSizeMB = 0  // Invalid: must be at least 1
            }
        };

        // Act
        var result = _configManager.ValidateConfiguration(config);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("retention days"));
        Assert.Contains(result.Errors, e => e.Contains("log file size"));
    }

    [Fact]
    public void ResetToDefaults_ReturnsValidDefaultConfiguration()
    {
        // Act
        var config = _configManager.ResetToDefaults();

        // Assert
        Assert.NotNull(config);
        Assert.Equal("Default", config.ProfileName);
        Assert.True(config.IsDefault);
        Assert.NotNull(config.BaitFolderPath);
        Assert.NotEmpty(config.MonitoredFileExtensions);
        Assert.Equal(30, config.LogSettings.RetentionDays);
        Assert.Equal(100, config.LogSettings.MaxFileSizeMB);
        Assert.Equal(DeceptionLevel.Medium, config.HardwareSpoofingLevel);
    }

    [Fact]
    public async Task ExportConfigurationAsync_CreatesFile()
    {
        // Arrange
        var config = _configManager.GetCurrentConfiguration();
        var exportPath = Path.Combine(_testConfigDirectory, "export.json");

        // Act
        var result = await _configManager.ExportConfigurationAsync(config, exportPath);

        // Assert
        Assert.True(result);
        Assert.True(File.Exists(exportPath));
    }

    [Fact]
    public async Task ImportConfigurationAsync_WithValidFile_ReturnsConfiguration()
    {
        // Arrange
        var config = _configManager.GetCurrentConfiguration();
        config.ProfileName = "Import Test";
        var exportPath = Path.Combine(_testConfigDirectory, "import.json");
        await _configManager.ExportConfigurationAsync(config, exportPath);

        // Act
        var importedConfig = await _configManager.ImportConfigurationAsync(exportPath);

        // Assert
        Assert.NotNull(importedConfig);
        Assert.Equal("Import Test", importedConfig.ProfileName);
    }

    [Fact]
    public async Task ImportConfigurationAsync_WithNonExistentFile_ReturnsNull()
    {
        // Arrange
        var nonExistentPath = Path.Combine(_testConfigDirectory, "nonexistent.json");

        // Act
        var importedConfig = await _configManager.ImportConfigurationAsync(nonExistentPath);

        // Assert
        Assert.Null(importedConfig);
    }

    [Fact]
    public void ValidateConfiguration_WithMonitoredFileExtensions_ValidatesCorrectly()
    {
        // Arrange
        var config = new HoneypotConfiguration
        {
            ProfileName = "Extension Test",
            BaitFolderPath = "C:\\ValidPath",
            MonitoredFileExtensions = new List<string> { ".docx", "txt" }, // "txt" missing dot
            LogSettings = new LogConfiguration
            {
                RetentionDays = 30,
                MaxFileSizeMB = 100
            }
        };

        // Act
        var result = _configManager.ValidateConfiguration(config);

        // Assert
        Assert.True(result.IsValid); // Should still be valid, just with warnings
        Assert.Contains(result.Warnings, w => w.Contains("txt"));
    }

    [Fact]
    public void ValidateConfiguration_WithMonitoredFolders_ValidatesAbsolutePaths()
    {
        // Arrange
        var config = new HoneypotConfiguration
        {
            ProfileName = "Folder Test",
            BaitFolderPath = "C:\\ValidPath",
            MonitoredFolders = new List<string> { "C:\\Folder1", "RelativeFolder" }, // Second is invalid
            LogSettings = new LogConfiguration
            {
                RetentionDays = 30,
                MaxFileSizeMB = 100
            }
        };

        // Act
        var result = _configManager.ValidateConfiguration(config);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("absolute") && e.Contains("RelativeFolder"));
    }

    [Fact]
    public async Task UpdateConfigurationAsync_UpdatesLastModifiedTimestamp()
    {
        // Arrange
        var config = _configManager.GetCurrentConfiguration();
        var originalTimestamp = config.LastModifiedAt;
        await Task.Delay(100); // Ensure time difference

        config.BaitFolderPath = "C:\\NewPath";

        // Act
        await _configManager.UpdateConfigurationAsync(config);
        var updatedConfig = _configManager.GetCurrentConfiguration();

        // Assert
        Assert.True(updatedConfig.LastModifiedAt > originalTimestamp);
    }

    [Fact]
    public void GetCurrentConfiguration_ReturnsCopy_NotReference()
    {
        // Arrange
        var config1 = _configManager.GetCurrentConfiguration();
        var originalPath = config1.BaitFolderPath;

        // Act
        config1.BaitFolderPath = "C:\\Modified";
        var config2 = _configManager.GetCurrentConfiguration();

        // Assert
        Assert.Equal(originalPath, config2.BaitFolderPath);
        Assert.NotEqual(config1.BaitFolderPath, config2.BaitFolderPath);
    }
}
