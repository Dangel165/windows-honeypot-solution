using FluentAssertions;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Unit tests for SandboxConfigurationGenerator
/// </summary>
public class SandboxConfigurationGeneratorTests
{
    private readonly SandboxConfigurationGenerator _generator;

    public SandboxConfigurationGeneratorTests()
    {
        _generator = new SandboxConfigurationGenerator();
    }

    [Fact]
    public void GenerateWsbXml_WithMinimalConfiguration_GeneratesValidXml()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            NetworkingEnabled = false,
            MemoryInMB = 4096
        };

        // Act
        var xml = _generator.GenerateWsbXml(config);

        // Assert
        xml.Should().NotBeNullOrEmpty();
        xml.Should().Contain("<Configuration>");
        xml.Should().Contain("</Configuration>");
        xml.Should().Contain("<Networking>Disable</Networking>");
        xml.Should().Contain("<MemoryInMB>4096</MemoryInMB>");
    }

    [Fact]
    public void GenerateWsbXml_WithNetworkingDisabled_ContainsDisableNetworking()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            NetworkingEnabled = false
        };

        // Act
        var xml = _generator.GenerateWsbXml(config);

        // Assert
        xml.Should().Contain("<Networking>Disable</Networking>");
    }

    [Fact]
    public void GenerateWsbXml_WithNetworkingEnabled_ContainsEnableNetworking()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            NetworkingEnabled = true
        };

        // Act
        var xml = _generator.GenerateWsbXml(config);

        // Assert
        xml.Should().Contain("<Networking>Enable</Networking>");
    }

    [Fact]
    public void GenerateWsbXml_WithBaitFolder_IncludesMappedFolder()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            BaitFolderPath = @"C:\BaitFolder",
            NetworkingEnabled = false
        };

        // Act
        var xml = _generator.GenerateWsbXml(config);

        // Assert
        xml.Should().Contain("<MappedFolders>");
        xml.Should().Contain("<MappedFolder>");
        xml.Should().Contain(@"<HostFolder>C:\BaitFolder</HostFolder>");
        xml.Should().Contain("<ReadOnly>true</ReadOnly>");
    }

    [Fact]
    public void GenerateWsbXml_WithMultipleMountedFolders_IncludesAllFolders()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            BaitFolderPath = @"C:\BaitFolder",
            MountedFolders = new List<string>
            {
                @"C:\Documents",
                @"C:\Projects"
            },
            NetworkingEnabled = false
        };

        // Act
        var xml = _generator.GenerateWsbXml(config);

        // Assert
        xml.Should().Contain(@"<HostFolder>C:\BaitFolder</HostFolder>");
        xml.Should().Contain(@"<HostFolder>C:\Documents</HostFolder>");
        xml.Should().Contain(@"<HostFolder>C:\Projects</HostFolder>");
        
        // All folders should be ReadOnly
        var readOnlyCount = System.Text.RegularExpressions.Regex.Matches(xml, "<ReadOnly>true</ReadOnly>").Count;
        readOnlyCount.Should().Be(3);
    }

    [Fact]
    public void GenerateWsbXml_WithNoFolders_DoesNotIncludeMappedFoldersSection()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            BaitFolderPath = string.Empty,
            MountedFolders = new List<string>(),
            NetworkingEnabled = false
        };

        // Act
        var xml = _generator.GenerateWsbXml(config);

        // Assert
        xml.Should().NotContain("<MappedFolders>");
    }

    [Fact]
    public void GenerateWsbXml_WithVGpuEnabled_ContainsEnableVGpu()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            VGpuEnabled = true
        };

        // Act
        var xml = _generator.GenerateWsbXml(config);

        // Assert
        xml.Should().Contain("<VGpu>Enable</VGpu>");
    }

    [Fact]
    public void GenerateWsbXml_WithAudioInputEnabled_ContainsEnableAudioInput()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            AudioInputEnabled = true
        };

        // Act
        var xml = _generator.GenerateWsbXml(config);

        // Assert
        xml.Should().Contain("<AudioInput>Enable</AudioInput>");
    }

    [Fact]
    public void GenerateWsbXml_WithVideoInputEnabled_ContainsEnableVideoInput()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            VideoInputEnabled = true
        };

        // Act
        var xml = _generator.GenerateWsbXml(config);

        // Assert
        xml.Should().Contain("<VideoInput>Enable</VideoInput>");
    }

    [Fact]
    public void GenerateWsbXml_WithProtectedClientDisabled_ContainsDisableProtectedClient()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            ProtectedClientEnabled = false
        };

        // Act
        var xml = _generator.GenerateWsbXml(config);

        // Assert
        xml.Should().Contain("<ProtectedClient>Disable</ProtectedClient>");
    }

    [Fact]
    public void GenerateWsbXml_WithPrinterRedirectionEnabled_ContainsEnablePrinterRedirection()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            PrinterRedirectionEnabled = true
        };

        // Act
        var xml = _generator.GenerateWsbXml(config);

        // Assert
        xml.Should().Contain("<PrinterRedirection>Enable</PrinterRedirection>");
    }

    [Fact]
    public void GenerateWsbXml_WithClipboardRedirectionEnabled_ContainsEnableClipboardRedirection()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            ClipboardRedirectionEnabled = true
        };

        // Act
        var xml = _generator.GenerateWsbXml(config);

        // Assert
        xml.Should().Contain("<ClipboardRedirection>Enable</ClipboardRedirection>");
    }

    [Fact]
    public void GenerateWsbXml_WithCustomMemory_ContainsCorrectMemoryValue()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            MemoryInMB = 8192
        };

        // Act
        var xml = _generator.GenerateWsbXml(config);

        // Assert
        xml.Should().Contain("<MemoryInMB>8192</MemoryInMB>");
    }

    [Fact]
    public void GenerateWsbXml_WithNullConfiguration_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _generator.GenerateWsbXml(null!));
    }

    [Fact]
    public async Task SaveWsbFileAsync_WithValidConfiguration_CreatesFile()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            NetworkingEnabled = false,
            MemoryInMB = 4096
        };
        var tempFile = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid()}.wsb");

        try
        {
            // Act
            await _generator.SaveWsbFileAsync(config, tempFile);

            // Assert
            File.Exists(tempFile).Should().BeTrue();
            var content = await File.ReadAllTextAsync(tempFile);
            content.Should().Contain("<Configuration>");
            content.Should().Contain("<Networking>Disable</Networking>");
        }
        finally
        {
            // Cleanup
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Fact]
    public async Task SaveWsbFileAsync_WithEmptyFilePath_ThrowsArgumentException()
    {
        // Arrange
        var config = new SandboxConfiguration();

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() => 
            _generator.SaveWsbFileAsync(config, string.Empty));
    }

    [Fact]
    public void ValidateFolderPath_WithExistingFolder_ReturnsTrue()
    {
        // Arrange
        var tempFolder = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid()}");
        Directory.CreateDirectory(tempFolder);

        try
        {
            // Act
            var result = _generator.ValidateFolderPath(tempFolder);

            // Assert
            result.Should().BeTrue();
        }
        finally
        {
            // Cleanup
            if (Directory.Exists(tempFolder))
            {
                Directory.Delete(tempFolder);
            }
        }
    }

    [Fact]
    public void ValidateFolderPath_WithNonExistingFolder_ReturnsFalse()
    {
        // Arrange
        var nonExistingFolder = @"C:\NonExistingFolder_" + Guid.NewGuid();

        // Act
        var result = _generator.ValidateFolderPath(nonExistingFolder);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ValidateFolderPath_WithEmptyPath_ReturnsFalse()
    {
        // Act
        var result = _generator.ValidateFolderPath(string.Empty);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ValidateConfiguration_WithValidConfiguration_ReturnsValid()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            NetworkingEnabled = false,
            MemoryInMB = 4096
        };

        // Act
        var result = _generator.ValidateConfiguration(config);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public void ValidateConfiguration_WithNullConfiguration_ReturnsInvalid()
    {
        // Act
        var result = _generator.ValidateConfiguration(null!);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain("Configuration cannot be null");
    }

    [Fact]
    public void ValidateConfiguration_WithInsufficientMemory_ReturnsInvalid()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            MemoryInMB = 256
        };

        // Act
        var result = _generator.ValidateConfiguration(config);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain("Memory allocation must be at least 512 MB");
    }

    [Fact]
    public void ValidateConfiguration_WithExcessiveMemory_ReturnsWarning()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            MemoryInMB = 20480 // 20 GB
        };

        // Act
        var result = _generator.ValidateConfiguration(config);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Warnings.Should().Contain(w => w.Contains("exceeds 16 GB"));
    }

    [Fact]
    public void ValidateConfiguration_WithNonExistingBaitFolder_ReturnsInvalid()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            BaitFolderPath = @"C:\NonExistingBaitFolder_" + Guid.NewGuid(),
            MemoryInMB = 4096
        };

        // Act
        var result = _generator.ValidateConfiguration(config);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.Contains("Bait folder path does not exist"));
    }

    [Fact]
    public void ValidateConfiguration_WithNonExistingMountedFolder_ReturnsInvalid()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            MountedFolders = new List<string>
            {
                @"C:\NonExistingFolder_" + Guid.NewGuid()
            },
            MemoryInMB = 4096
        };

        // Act
        var result = _generator.ValidateConfiguration(config);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.Contains("Mounted folder path does not exist"));
    }

    [Fact]
    public void GenerateWsbXml_WithCompleteConfiguration_GeneratesCompleteXml()
    {
        // Arrange
        var config = new SandboxConfiguration
        {
            BaitFolderPath = @"C:\BaitFolder",
            NetworkingEnabled = false,
            MountedFolders = new List<string> { @"C:\Documents" },
            DeceptionLevel = DeceptionLevel.High,
            MemoryInMB = 8192,
            VGpuEnabled = true,
            AudioInputEnabled = false,
            VideoInputEnabled = false,
            ProtectedClientEnabled = true,
            PrinterRedirectionEnabled = false,
            ClipboardRedirectionEnabled = false
        };

        // Act
        var xml = _generator.GenerateWsbXml(config);

        // Assert
        xml.Should().Contain("<Configuration>");
        xml.Should().Contain("<Networking>Disable</Networking>");
        xml.Should().Contain("<VGpu>Enable</VGpu>");
        xml.Should().Contain("<AudioInput>Disable</AudioInput>");
        xml.Should().Contain("<VideoInput>Disable</VideoInput>");
        xml.Should().Contain("<ProtectedClient>Enable</ProtectedClient>");
        xml.Should().Contain("<PrinterRedirection>Disable</PrinterRedirection>");
        xml.Should().Contain("<ClipboardRedirection>Disable</ClipboardRedirection>");
        xml.Should().Contain("<MemoryInMB>8192</MemoryInMB>");
        xml.Should().Contain("<MappedFolders>");
        xml.Should().Contain(@"<HostFolder>C:\BaitFolder</HostFolder>");
        xml.Should().Contain(@"<HostFolder>C:\Documents</HostFolder>");
        xml.Should().Contain("</Configuration>");
    }
}
