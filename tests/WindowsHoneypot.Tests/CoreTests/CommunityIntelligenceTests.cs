using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using System.Text.Json;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Unit tests for CommunityIntelligence
/// Tests specific scenarios and edge cases for threat intelligence sharing
/// Requirement 15: Community Intelligence and Threat Sharing
/// </summary>
public class CommunityIntelligenceTests : IDisposable
{
    private readonly Mock<ILogger<CommunityIntelligence>> _mockLogger;
    private readonly CommunityIntelligenceConfiguration _config;
    private readonly string _testDataPath;

    public CommunityIntelligenceTests()
    {
        _mockLogger = new Mock<ILogger<CommunityIntelligence>>();
        
        _config = new CommunityIntelligenceConfiguration
        {
            Enabled = true,
            ShareAttackData = true,
            ReceiveThreatFeeds = true,
            AutoUpdateBlacklist = true,
            CloudServerUrl = "https://test-server.example.com",
            ApiKey = "test-api-key",
            EnableOfflineMode = true
        };

        // Set up test data path
        _testDataPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "WindowsHoneypot",
            "CommunityIntelligence"
        );
        Directory.CreateDirectory(_testDataPath);
    }

    public void Dispose()
    {
        // Clean up test data
        try
        {
            if (Directory.Exists(_testDataPath))
            {
                Directory.Delete(_testDataPath, true);
            }
        }
        catch
        {
            // Ignore cleanup errors
        }
    }

    [Fact]
    public void Constructor_WithNullLogger_ThrowsArgumentNullException()
    {
        // Act & Assert
        Action act = () => new CommunityIntelligence(null!, _config);
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("logger");
    }

    [Fact]
    public void Constructor_WithNullConfig_ThrowsArgumentNullException()
    {
        // Act & Assert
        Action act = () => new CommunityIntelligence(_mockLogger.Object, null!);
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("config");
    }

    [Fact]
    public void Constructor_WithValidParameters_InitializesSuccessfully()
    {
        // Act
        var service = new CommunityIntelligence(_mockLogger.Object, _config);

        // Assert
        service.Should().NotBeNull();
        service.Should().BeAssignableTo<ICommunityIntelligence>();
    }

    [Fact]
    public async Task ShareThreatDataAsync_WhenDisabled_DoesNotShareData()
    {
        // Arrange
        var disabledConfig = new CommunityIntelligenceConfiguration
        {
            Enabled = false
        };
        var service = new CommunityIntelligence(_mockLogger.Object, disabledConfig);
        var threatData = CreateSampleThreatData();

        // Act
        await service.ShareThreatDataAsync(threatData);

        // Assert - verify it logged that sharing is disabled
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Debug,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("disabled")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.AtLeastOnce);
    }

    [Fact]
    public async Task GetThreatFeedAsync_WhenDisabled_ReturnsEmptyList()
    {
        // Arrange
        var disabledConfig = new CommunityIntelligenceConfiguration
        {
            Enabled = false
        };
        var service = new CommunityIntelligence(_mockLogger.Object, disabledConfig);

        // Act
        var result = await service.GetThreatFeedAsync();

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public async Task UpdateLocalBlacklistAsync_WhenDisabled_DoesNotUpdate()
    {
        // Arrange
        var disabledConfig = new CommunityIntelligenceConfiguration
        {
            Enabled = false
        };
        var service = new CommunityIntelligence(_mockLogger.Object, disabledConfig);

        // Act
        await service.UpdateLocalBlacklistAsync();

        // Assert - verify it logged that update is disabled
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Debug,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("disabled")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.AtLeastOnce);
    }

    [Fact]
    public void GetGlobalStatistics_InitialCall_ReturnsDefaultStatistics()
    {
        // Arrange
        var service = new CommunityIntelligence(_mockLogger.Object, _config);

        // Act
        var statistics = service.GetGlobalStatistics();

        // Assert
        statistics.Should().NotBeNull();
        statistics.TotalThreats.Should().Be(0);
        statistics.ThreatsLast24Hours.Should().Be(0);
        statistics.TopAttackingCountries.Should().BeEmpty();
        statistics.CommonAttackPatterns.Should().BeEmpty();
        statistics.SeverityDistribution.Should().BeEmpty();
    }

    [Fact]
    public void GetGlobalStatistics_WithinCacheWindow_ReturnsCachedData()
    {
        // Arrange
        var service = new CommunityIntelligence(_mockLogger.Object, _config);

        // Act
        var stats1 = service.GetGlobalStatistics();
        var stats2 = service.GetGlobalStatistics();

        // Assert - should return same instance due to caching
        stats1.Should().BeSameAs(stats2);
    }

    [Fact]
    public void ThreatData_HasCorrectDefaultValues()
    {
        // Act
        var threatData = new ThreatData();

        // Assert
        threatData.ThreatId.Should().NotBeEmpty();
        threatData.AttackerIP.Should().BeEmpty();
        threatData.AttackPatterns.Should().BeEmpty();
        threatData.DetectionTime.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
        threatData.Severity.Should().Be(ThreatSeverity.Medium);
        threatData.Indicators.Should().BeEmpty();
        threatData.Version.Should().Be("1.0");
        threatData.SourceId.Should().BeEmpty();
        threatData.DataHash.Should().BeEmpty();
    }

    [Fact]
    public void ThreatIndicator_HasCorrectDefaultValues()
    {
        // Act
        var indicator = new ThreatIndicator();

        // Assert
        indicator.Type.Should().BeEmpty();
        indicator.Value.Should().BeEmpty();
        indicator.Confidence.Should().Be(0);
        indicator.Severity.Should().Be(ThreatSeverity.Medium);
        indicator.Description.Should().BeEmpty();
        indicator.Tags.Should().BeEmpty();
        indicator.FirstSeen.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
        indicator.LastSeen.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void ThreatStatistics_HasCorrectDefaultValues()
    {
        // Act
        var statistics = new ThreatStatistics();

        // Assert
        statistics.TotalThreats.Should().Be(0);
        statistics.ThreatsLast24Hours.Should().Be(0);
        statistics.TopAttackingCountries.Should().BeEmpty();
        statistics.CommonAttackPatterns.Should().BeEmpty();
        statistics.SeverityDistribution.Should().BeEmpty();
        statistics.GeneratedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void CommunityIntelligenceConfiguration_HasCorrectDefaultValues()
    {
        // Act
        var config = new CommunityIntelligenceConfiguration();

        // Assert
        config.Enabled.Should().BeTrue();
        config.ShareAttackData.Should().BeTrue();
        config.ReceiveThreatFeeds.Should().BeTrue();
        config.AutoUpdateBlacklist.Should().BeTrue();
        config.CloudServerUrl.Should().NotBeEmpty();
        config.ApiKey.Should().BeEmpty();
        config.EnableOfflineMode.Should().BeTrue();
    }

    [Fact]
    public void ThreatData_Serialization_WorksCorrectly()
    {
        // Arrange
        var threatData = CreateSampleThreatData();

        // Act
        var json = JsonSerializer.Serialize(threatData);
        var deserialized = JsonSerializer.Deserialize<ThreatData>(json);

        // Assert
        deserialized.Should().NotBeNull();
        deserialized!.ThreatId.Should().Be(threatData.ThreatId);
        deserialized.AttackerIP.Should().Be(threatData.AttackerIP);
        deserialized.Severity.Should().Be(threatData.Severity);
        deserialized.AttackPatterns.Should().BeEquivalentTo(threatData.AttackPatterns);
        deserialized.Indicators.Should().BeEquivalentTo(threatData.Indicators);
    }

    [Fact]
    public void ThreatIndicator_Serialization_WorksCorrectly()
    {
        // Arrange
        var indicator = new ThreatIndicator
        {
            Type = "IP",
            Value = "192.168.1.1",
            Confidence = 85,
            Severity = ThreatSeverity.High,
            Description = "Known malicious IP",
            Tags = new List<string> { "malware", "botnet" }
        };

        // Act
        var json = JsonSerializer.Serialize(indicator);
        var deserialized = JsonSerializer.Deserialize<ThreatIndicator>(json);

        // Assert
        deserialized.Should().NotBeNull();
        deserialized!.Type.Should().Be("IP");
        deserialized.Value.Should().Be("192.168.1.1");
        deserialized.Confidence.Should().Be(85);
        deserialized.Tags.Should().Contain(new[] { "malware", "botnet" });
    }

    [Fact]
    public void ThreatStatistics_Serialization_WorksCorrectly()
    {
        // Arrange
        var statistics = new ThreatStatistics
        {
            TotalThreats = 1000,
            ThreatsLast24Hours = 50,
            TopAttackingCountries = new Dictionary<string, int>
            {
                { "US", 100 },
                { "CN", 200 }
            },
            CommonAttackPatterns = new Dictionary<string, int>
            {
                { "ransomware", 50 },
                { "phishing", 75 }
            },
            SeverityDistribution = new Dictionary<ThreatSeverity, int>
            {
                { ThreatSeverity.Low, 300 },
                { ThreatSeverity.Medium, 400 },
                { ThreatSeverity.High, 250 },
                { ThreatSeverity.Critical, 50 }
            }
        };

        // Act
        var json = JsonSerializer.Serialize(statistics);
        var deserialized = JsonSerializer.Deserialize<ThreatStatistics>(json);

        // Assert
        deserialized.Should().NotBeNull();
        deserialized!.TotalThreats.Should().Be(1000);
        deserialized.ThreatsLast24Hours.Should().Be(50);
        deserialized.TopAttackingCountries.Should().BeEquivalentTo(statistics.TopAttackingCountries);
        deserialized.CommonAttackPatterns.Should().BeEquivalentTo(statistics.CommonAttackPatterns);
        deserialized.SeverityDistribution.Should().BeEquivalentTo(statistics.SeverityDistribution);
    }

    [Fact]
    public void ThreatData_WithMultipleIndicators_SerializesCorrectly()
    {
        // Arrange
        var threatData = new ThreatData
        {
            ThreatId = "threat-123",
            AttackerIP = "10.0.0.1",
            AttackPatterns = new List<string> { "pattern1", "pattern2", "pattern3" },
            Severity = ThreatSeverity.Critical,
            Indicators = new Dictionary<string, string>
            {
                { "hash1", "abc123" },
                { "hash2", "def456" },
                { "domain", "evil.com" }
            }
        };

        // Act
        var json = JsonSerializer.Serialize(threatData);
        var deserialized = JsonSerializer.Deserialize<ThreatData>(json);

        // Assert
        deserialized.Should().NotBeNull();
        deserialized!.AttackPatterns.Should().HaveCount(3);
        deserialized.Indicators.Should().HaveCount(3);
        deserialized.Indicators["domain"].Should().Be("evil.com");
    }

    [Fact]
    public void ThreatIndicator_WithMultipleTags_SerializesCorrectly()
    {
        // Arrange
        var indicator = new ThreatIndicator
        {
            Type = "Domain",
            Value = "malicious.example.com",
            Confidence = 95,
            Tags = new List<string> { "phishing", "credential-theft", "banking-trojan" }
        };

        // Act
        var json = JsonSerializer.Serialize(indicator);
        var deserialized = JsonSerializer.Deserialize<ThreatIndicator>(json);

        // Assert
        deserialized.Should().NotBeNull();
        deserialized!.Tags.Should().HaveCount(3);
        deserialized.Tags.Should().Contain("banking-trojan");
    }

    [Fact]
    public void CommunityIntelligenceConfiguration_CanBeModified()
    {
        // Arrange
        var config = new CommunityIntelligenceConfiguration();

        // Act
        config.Enabled = false;
        config.ShareAttackData = false;
        config.CloudServerUrl = "https://custom-server.com";
        config.ApiKey = "custom-key";

        // Assert
        config.Enabled.Should().BeFalse();
        config.ShareAttackData.Should().BeFalse();
        config.CloudServerUrl.Should().Be("https://custom-server.com");
        config.ApiKey.Should().Be("custom-key");
    }

    [Fact]
    public void ThreatIntelligenceReceivedEventArgs_HasCorrectProperties()
    {
        // Arrange
        var indicators = new List<ThreatIndicator>
        {
            new ThreatIndicator { Type = "IP", Value = "1.2.3.4" },
            new ThreatIndicator { Type = "Domain", Value = "bad.com" }
        };

        // Act
        var eventArgs = new ThreatIntelligenceReceivedEventArgs
        {
            ThreatIndicators = indicators,
            NewIndicatorCount = 2,
            ReceivedAt = DateTime.UtcNow
        };

        // Assert
        eventArgs.ThreatIndicators.Should().HaveCount(2);
        eventArgs.NewIndicatorCount.Should().Be(2);
        eventArgs.ReceivedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    // Helper methods

    private ThreatData CreateSampleThreatData()
    {
        return new ThreatData
        {
            ThreatId = Guid.NewGuid().ToString(),
            AttackerIP = "192.168.1.100",
            AttackPatterns = new List<string> { "file_encryption", "credential_theft" },
            DetectionTime = DateTime.UtcNow,
            Severity = ThreatSeverity.High,
            GeographicLocation = "United States",
            Indicators = new Dictionary<string, string>
            {
                { "file_hash", "abc123def456" },
                { "process_name", "malware.exe" }
            }
        };
    }

    // Tests for Task 15.3 - Threat feed processing and blacklist management

    [Fact]
    public void ThreatSharingLevel_HasCorrectValues()
    {
        // Assert
        ThreatSharingLevel.Minimal.Should().Be((ThreatSharingLevel)0);
        ThreatSharingLevel.Standard.Should().Be((ThreatSharingLevel)1);
        ThreatSharingLevel.Detailed.Should().Be((ThreatSharingLevel)2);
        ThreatSharingLevel.Full.Should().Be((ThreatSharingLevel)3);
    }

    [Fact]
    public void CommunityIntelligenceConfiguration_HasMinimumConfidenceThreshold()
    {
        // Arrange
        var config = new CommunityIntelligenceConfiguration();

        // Assert
        config.MinimumConfidenceThreshold.Should().Be(70);
        config.SharingLevel.Should().Be(ThreatSharingLevel.Standard);
    }

    [Fact]
    public void CommunityIntelligenceConfiguration_CanSetMinimumConfidenceThreshold()
    {
        // Arrange
        var config = new CommunityIntelligenceConfiguration
        {
            MinimumConfidenceThreshold = 85
        };

        // Assert
        config.MinimumConfidenceThreshold.Should().Be(85);
    }

    [Fact]
    public void CommunityIntelligenceConfiguration_CanSetSharingLevel()
    {
        // Arrange
        var config = new CommunityIntelligenceConfiguration
        {
            SharingLevel = ThreatSharingLevel.Minimal
        };

        // Assert
        config.SharingLevel.Should().Be(ThreatSharingLevel.Minimal);
    }

    [Fact]
    public void RegionalThreatStatistics_HasCorrectDefaultValues()
    {
        // Act
        var statistics = new RegionalThreatStatistics();

        // Assert
        statistics.Region.Should().BeEmpty();
        statistics.ThreatCount.Should().Be(0);
        statistics.ThreatsLast24Hours.Should().Be(0);
        statistics.CommonAttackTypes.Should().BeEmpty();
        statistics.TargetedSectors.Should().BeEmpty();
        statistics.SeverityDistribution.Should().BeEmpty();
        statistics.GeneratedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void RegionalThreatStatistics_CanBePopulated()
    {
        // Arrange & Act
        var statistics = new RegionalThreatStatistics
        {
            Region = "North America",
            ThreatCount = 500,
            ThreatsLast24Hours = 25,
            CommonAttackTypes = new Dictionary<string, int>
            {
                { "ransomware", 100 },
                { "phishing", 150 }
            },
            TargetedSectors = new Dictionary<string, int>
            {
                { "finance", 200 },
                { "healthcare", 150 }
            },
            SeverityDistribution = new Dictionary<ThreatSeverity, int>
            {
                { ThreatSeverity.High, 100 },
                { ThreatSeverity.Critical, 50 }
            }
        };

        // Assert
        statistics.Region.Should().Be("North America");
        statistics.ThreatCount.Should().Be(500);
        statistics.ThreatsLast24Hours.Should().Be(25);
        statistics.CommonAttackTypes.Should().HaveCount(2);
        statistics.TargetedSectors.Should().HaveCount(2);
        statistics.SeverityDistribution.Should().HaveCount(2);
    }

    [Fact]
    public void RegionalThreatStatistics_Serialization_WorksCorrectly()
    {
        // Arrange
        var statistics = new RegionalThreatStatistics
        {
            Region = "Europe",
            ThreatCount = 300,
            CommonAttackTypes = new Dictionary<string, int>
            {
                { "ddos", 50 },
                { "malware", 100 }
            }
        };

        // Act
        var json = JsonSerializer.Serialize(statistics);
        var deserialized = JsonSerializer.Deserialize<RegionalThreatStatistics>(json);

        // Assert
        deserialized.Should().NotBeNull();
        deserialized!.Region.Should().Be("Europe");
        deserialized.ThreatCount.Should().Be(300);
        deserialized.CommonAttackTypes.Should().BeEquivalentTo(statistics.CommonAttackTypes);
    }

    [Fact]
    public void ThreatIndicatorAnalysis_HasCorrectDefaultValues()
    {
        // Act
        var analysis = new ThreatIndicatorAnalysis();

        // Assert
        analysis.TotalIndicators.Should().Be(0);
        analysis.IndicatorsByType.Should().BeEmpty();
        analysis.IndicatorsBySeverity.Should().BeEmpty();
        analysis.CommonTags.Should().BeEmpty();
        analysis.AverageConfidence.Should().Be(0);
        analysis.HighRiskIndicatorCount.Should().Be(0);
        analysis.AnalyzedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void ThreatIndicatorAnalysis_CanBePopulated()
    {
        // Arrange & Act
        var analysis = new ThreatIndicatorAnalysis
        {
            TotalIndicators = 100,
            IndicatorsByType = new Dictionary<string, int>
            {
                { "IP", 50 },
                { "Domain", 30 },
                { "Hash", 20 }
            },
            IndicatorsBySeverity = new Dictionary<ThreatSeverity, int>
            {
                { ThreatSeverity.High, 40 },
                { ThreatSeverity.Critical, 20 }
            },
            CommonTags = new Dictionary<string, int>
            {
                { "malware", 60 },
                { "phishing", 40 }
            },
            AverageConfidence = 85,
            HighRiskIndicatorCount = 20
        };

        // Assert
        analysis.TotalIndicators.Should().Be(100);
        analysis.IndicatorsByType.Should().HaveCount(3);
        analysis.IndicatorsBySeverity.Should().HaveCount(2);
        analysis.CommonTags.Should().HaveCount(2);
        analysis.AverageConfidence.Should().Be(85);
        analysis.HighRiskIndicatorCount.Should().Be(20);
    }

    [Fact]
    public void ThreatIndicatorAnalysis_Serialization_WorksCorrectly()
    {
        // Arrange
        var analysis = new ThreatIndicatorAnalysis
        {
            TotalIndicators = 50,
            IndicatorsByType = new Dictionary<string, int>
            {
                { "IP", 25 },
                { "Domain", 25 }
            },
            AverageConfidence = 75
        };

        // Act
        var json = JsonSerializer.Serialize(analysis);
        var deserialized = JsonSerializer.Deserialize<ThreatIndicatorAnalysis>(json);

        // Assert
        deserialized.Should().NotBeNull();
        deserialized!.TotalIndicators.Should().Be(50);
        deserialized.IndicatorsByType.Should().BeEquivalentTo(analysis.IndicatorsByType);
        deserialized.AverageConfidence.Should().Be(75);
    }

    [Fact]
    public void AnalyzeAttackPatterns_WithEmptyBlacklist_ReturnsEmptyAnalysis()
    {
        // Arrange
        var service = new CommunityIntelligence(_mockLogger.Object, _config);

        // Act
        var analysis = service.AnalyzeAttackPatterns();

        // Assert
        analysis.Should().NotBeNull();
        analysis.TotalIndicators.Should().Be(0);
        analysis.IndicatorsByType.Should().BeEmpty();
        analysis.IndicatorsBySeverity.Should().BeEmpty();
        analysis.CommonTags.Should().BeEmpty();
        analysis.AverageConfidence.Should().Be(0);
        analysis.HighRiskIndicatorCount.Should().Be(0);
    }

    [Fact]
    public async Task GetRegionalStatisticsAsync_WhenDisabled_ReturnsEmptyStatistics()
    {
        // Arrange
        var disabledConfig = new CommunityIntelligenceConfiguration
        {
            Enabled = false
        };
        var service = new CommunityIntelligence(_mockLogger.Object, disabledConfig);

        // Act
        var result = await service.GetRegionalStatisticsAsync("North America");

        // Assert
        result.Should().NotBeNull();
        result.Region.Should().Be("North America");
        result.ThreatCount.Should().Be(0);
    }

    [Fact]
    public void ThreatIndicator_ConfidenceScore_CanBeSetAndRetrieved()
    {
        // Arrange
        var indicator = new ThreatIndicator
        {
            Type = "IP",
            Value = "10.0.0.1",
            Confidence = 95
        };

        // Assert
        indicator.Confidence.Should().Be(95);
    }

    [Fact]
    public void ThreatIndicator_WithHighConfidence_IsIdentifiable()
    {
        // Arrange
        var highConfidenceIndicator = new ThreatIndicator
        {
            Confidence = 95
        };
        var lowConfidenceIndicator = new ThreatIndicator
        {
            Confidence = 50
        };

        // Assert
        highConfidenceIndicator.Confidence.Should().BeGreaterThanOrEqualTo(90);
        lowConfidenceIndicator.Confidence.Should().BeLessThan(90);
    }
}
