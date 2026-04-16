using FluentAssertions;
using WindowsHoneypot.Core.Models;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Unit tests for core model classes
/// </summary>
public class ModelsTests
{
    [Fact]
    public void SandboxConfiguration_ShouldHaveDefaultValues()
    {
        // Arrange & Act
        var config = new SandboxConfiguration();

        // Assert
        config.NetworkingEnabled.Should().BeFalse();
        config.DeceptionLevel.Should().Be(DeceptionLevel.Medium);
        config.MemoryInMB.Should().Be(4096);
        config.ProtectedClientEnabled.Should().BeTrue();
        config.MountedFolders.Should().NotBeNull().And.BeEmpty();
        config.FakeProcesses.Should().NotBeNull().And.BeEmpty();
    }

    [Fact]
    public void AttackEvent_ShouldGenerateUniqueId()
    {
        // Arrange & Act
        var event1 = new AttackEvent();
        var event2 = new AttackEvent();

        // Assert
        event1.EventId.Should().NotBe(Guid.Empty);
        event2.EventId.Should().NotBe(Guid.Empty);
        event1.EventId.Should().NotBe(event2.EventId);
    }

    [Fact]
    public void AttackEvent_ShouldHaveRecentTimestamp()
    {
        // Arrange
        var beforeCreation = DateTime.UtcNow.AddSeconds(-1);
        
        // Act
        var attackEvent = new AttackEvent();
        var afterCreation = DateTime.UtcNow.AddSeconds(1);

        // Assert
        attackEvent.Timestamp.Should().BeAfter(beforeCreation);
        attackEvent.Timestamp.Should().BeBefore(afterCreation);
    }

    [Fact]
    public void ProcessProfile_ShouldAllowConfiguration()
    {
        // Arrange & Act
        var profile = new ProcessProfile
        {
            ProcessName = "chrome.exe",
            FakeCpuUsage = 25,
            FakeMemoryUsage = 1024 * 1024 * 512, // 512 MB
            Description = "Google Chrome Browser",
            CompanyName = "Google LLC"
        };

        // Assert
        profile.ProcessName.Should().Be("chrome.exe");
        profile.FakeCpuUsage.Should().Be(25);
        profile.FakeMemoryUsage.Should().Be(1024 * 1024 * 512);
        profile.Description.Should().Be("Google Chrome Browser");
        profile.CompanyName.Should().Be("Google LLC");
    }

    [Fact]
    public void HoneyAccount_ShouldGenerateUniqueId()
    {
        // Arrange & Act
        var account1 = new HoneyAccount();
        var account2 = new HoneyAccount();

        // Assert
        account1.Id.Should().NotBe(Guid.Empty);
        account2.Id.Should().NotBe(Guid.Empty);
        account1.Id.Should().NotBe(account2.Id);
    }

    [Fact]
    public void AttackerProfile_ShouldInitializeCollections()
    {
        // Arrange & Act
        var profile = new AttackerProfile();

        // Assert
        profile.BrowserPlugins.Should().NotBeNull().And.BeEmpty();
        profile.AccessedCredentials.Should().NotBeNull().And.BeEmpty();
        profile.FingerprintData.Should().NotBeNull().And.BeEmpty();
    }

    [Theory]
    [InlineData(ThreatSeverity.Low)]
    [InlineData(ThreatSeverity.Medium)]
    [InlineData(ThreatSeverity.High)]
    [InlineData(ThreatSeverity.Critical)]
    public void ThreatSeverity_ShouldSupportAllLevels(ThreatSeverity severity)
    {
        // Arrange & Act
        var attackEvent = new AttackEvent { Severity = severity };

        // Assert
        attackEvent.Severity.Should().Be(severity);
    }

    [Fact]
    public void ReplayData_ShouldCalculateDuration()
    {
        // Arrange
        var startTime = DateTime.UtcNow;
        var endTime = startTime.AddMinutes(30);

        // Act
        var replayData = new ReplayData
        {
            StartTime = startTime,
            EndTime = endTime
        };

        // Assert
        replayData.Duration.Should().Be(TimeSpan.FromMinutes(30));
    }
}