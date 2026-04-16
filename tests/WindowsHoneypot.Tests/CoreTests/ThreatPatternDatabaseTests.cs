using Microsoft.Extensions.Logging;
using Moq;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Unit tests for ThreatPatternDatabase
/// </summary>
public class ThreatPatternDatabaseTests
{
    private readonly Mock<ILogger<ThreatPatternDatabase>> _mockLogger;
    private readonly string _testDatabasePath;

    public ThreatPatternDatabaseTests()
    {
        _mockLogger = new Mock<ILogger<ThreatPatternDatabase>>();
        _testDatabasePath = Path.Combine(Path.GetTempPath(), $"test_patterns_{Guid.NewGuid()}.db");
    }

    [Fact]
    public void AddOrUpdatePattern_ShouldAddNewPattern()
    {
        // Arrange
        var database = new ThreatPatternDatabase(_mockLogger.Object, _testDatabasePath);
        var pattern = CreateTestPattern("TestPattern1");

        // Act
        database.AddOrUpdatePattern(pattern);
        var retrieved = database.GetPattern(pattern.PatternId);

        // Assert
        Assert.NotNull(retrieved);
        Assert.Equal(pattern.Name, retrieved.Name);
        Assert.Equal(pattern.PatternId, retrieved.PatternId);
    }

    [Fact]
    public void AddOrUpdatePattern_ShouldUpdateExistingPattern()
    {
        // Arrange
        var database = new ThreatPatternDatabase(_mockLogger.Object, _testDatabasePath);
        var pattern = CreateTestPattern("TestPattern1");
        database.AddOrUpdatePattern(pattern);

        // Act
        pattern.Description = "Updated description";
        database.AddOrUpdatePattern(pattern);
        var retrieved = database.GetPattern(pattern.PatternId);

        // Assert
        Assert.NotNull(retrieved);
        Assert.Equal("Updated description", retrieved.Description);
    }

    [Fact]
    public void RemovePattern_ShouldRemoveExistingPattern()
    {
        // Arrange
        var database = new ThreatPatternDatabase(_mockLogger.Object, _testDatabasePath);
        var pattern = CreateTestPattern("TestPattern1");
        database.AddOrUpdatePattern(pattern);

        // Act
        var removed = database.RemovePattern(pattern.PatternId);
        var retrieved = database.GetPattern(pattern.PatternId);

        // Assert
        Assert.True(removed);
        Assert.Null(retrieved);
    }

    [Fact]
    public void GetAllPatterns_ShouldReturnAllPatterns()
    {
        // Arrange
        var database = new ThreatPatternDatabase(_mockLogger.Object, _testDatabasePath);
        var pattern1 = CreateTestPattern("Pattern1");
        var pattern2 = CreateTestPattern("Pattern2");
        var pattern3 = CreateTestPattern("Pattern3");

        database.AddOrUpdatePattern(pattern1);
        database.AddOrUpdatePattern(pattern2);
        database.AddOrUpdatePattern(pattern3);

        // Act
        var allPatterns = database.GetAllPatterns();

        // Assert
        Assert.Equal(3, allPatterns.Count);
    }

    [Fact]
    public void GetPatternsByType_ShouldReturnMatchingPatterns()
    {
        // Arrange
        var database = new ThreatPatternDatabase(_mockLogger.Object, _testDatabasePath);
        var filePattern = CreateTestPattern("FilePattern", ThreatPatternType.FileHash);
        var processPattern = CreateTestPattern("ProcessPattern", ThreatPatternType.ProcessName);

        database.AddOrUpdatePattern(filePattern);
        database.AddOrUpdatePattern(processPattern);

        // Act
        var filePatterns = database.GetPatternsByType(ThreatPatternType.FileHash);

        // Assert
        Assert.Single(filePatterns);
        Assert.Equal("FilePattern", filePatterns[0].Name);
    }

    [Fact]
    public void GetPatternsBySeverity_ShouldReturnMatchingPatterns()
    {
        // Arrange
        var database = new ThreatPatternDatabase(_mockLogger.Object, _testDatabasePath);
        var criticalPattern = CreateTestPattern("Critical", severity: ThreatSeverity.Critical);
        var lowPattern = CreateTestPattern("Low", severity: ThreatSeverity.Low);

        database.AddOrUpdatePattern(criticalPattern);
        database.AddOrUpdatePattern(lowPattern);

        // Act
        var criticalPatterns = database.GetPatternsBySeverity(ThreatSeverity.Critical);

        // Assert
        Assert.Single(criticalPatterns);
        Assert.Equal("Critical", criticalPatterns[0].Name);
    }

    [Fact]
    public void GetHighConfidencePatterns_ShouldReturnOnlyHighConfidence()
    {
        // Arrange
        var database = new ThreatPatternDatabase(_mockLogger.Object, _testDatabasePath);
        var highConfidence = CreateTestPattern("High", confidence: 0.9);
        var lowConfidence = CreateTestPattern("Low", confidence: 0.3);

        database.AddOrUpdatePattern(highConfidence);
        database.AddOrUpdatePattern(lowConfidence);

        // Act
        var highPatterns = database.GetHighConfidencePatterns(0.7);

        // Assert
        Assert.Single(highPatterns);
        Assert.Equal("High", highPatterns[0].Name);
    }

    [Fact]
    public async Task SaveAndLoad_ShouldPersistPatterns()
    {
        // Arrange
        var database1 = new ThreatPatternDatabase(_mockLogger.Object, _testDatabasePath);
        var pattern1 = CreateTestPattern("Pattern1");
        var pattern2 = CreateTestPattern("Pattern2");

        database1.AddOrUpdatePattern(pattern1);
        database1.AddOrUpdatePattern(pattern2);

        // Act
        await database1.SaveAsync();

        var database2 = new ThreatPatternDatabase(_mockLogger.Object, _testDatabasePath);
        await database2.LoadAsync();
        var loadedPatterns = database2.GetAllPatterns();

        // Assert
        Assert.Equal(2, loadedPatterns.Count);
        Assert.Contains(loadedPatterns, p => p.Name == "Pattern1");
        Assert.Contains(loadedPatterns, p => p.Name == "Pattern2");

        // Cleanup
        if (File.Exists(_testDatabasePath))
            File.Delete(_testDatabasePath);
    }

    [Fact]
    public void ImportFromHoneypot_ShouldMarkPatternsAsLocal()
    {
        // Arrange
        var database = new ThreatPatternDatabase(_mockLogger.Object, _testDatabasePath);
        var patterns = new List<ThreatPattern>
        {
            CreateTestPattern("Pattern1"),
            CreateTestPattern("Pattern2")
        };

        // Act
        var count = database.ImportFromHoneypot(patterns, "TestHoneypot");
        var imported = database.GetAllPatterns();

        // Assert
        Assert.Equal(2, count);
        Assert.All(imported, p => Assert.False(p.IsFromCommunity));
        Assert.All(imported, p => Assert.Equal("TestHoneypot", p.SourceHoneypotId));
    }

    [Fact]
    public void ImportFromCommunity_ShouldMarkPatternsAsCommunity()
    {
        // Arrange
        var database = new ThreatPatternDatabase(_mockLogger.Object, _testDatabasePath);
        var patterns = new List<ThreatPattern>
        {
            CreateTestPattern("Pattern1"),
            CreateTestPattern("Pattern2")
        };

        // Act
        var count = database.ImportFromCommunity(patterns);
        var imported = database.GetAllPatterns();

        // Assert
        Assert.Equal(2, count);
        Assert.All(imported, p => Assert.True(p.IsFromCommunity));
    }

    [Fact]
    public void GetStatistics_ShouldReturnCorrectStats()
    {
        // Arrange
        var database = new ThreatPatternDatabase(_mockLogger.Object, _testDatabasePath);
        database.AddOrUpdatePattern(CreateTestPattern("P1", ThreatPatternType.FileHash, ThreatSeverity.High, 0.9));
        database.AddOrUpdatePattern(CreateTestPattern("P2", ThreatPatternType.ProcessName, ThreatSeverity.Low, 0.5));
        
        var communityPattern = CreateTestPattern("P3", confidence: 0.8);
        database.ImportFromCommunity(new List<ThreatPattern> { communityPattern });

        // Act
        var stats = database.GetStatistics();

        // Assert
        Assert.Equal(3, stats.TotalPatterns);
        Assert.Equal(2, stats.LocalPatternsCount);
        Assert.Equal(1, stats.CommunityPatternsCount);
        Assert.Equal(2, stats.HighConfidenceCount); // >= 0.8
    }

    [Fact]
    public void Clear_ShouldRemoveAllPatterns()
    {
        // Arrange
        var database = new ThreatPatternDatabase(_mockLogger.Object, _testDatabasePath);
        database.AddOrUpdatePattern(CreateTestPattern("P1"));
        database.AddOrUpdatePattern(CreateTestPattern("P2"));

        // Act
        database.Clear();
        var patterns = database.GetAllPatterns();

        // Assert
        Assert.Empty(patterns);
    }

    private ThreatPattern CreateTestPattern(
        string name, 
        ThreatPatternType type = ThreatPatternType.FileHash,
        ThreatSeverity severity = ThreatSeverity.Medium,
        double confidence = 0.8)
    {
        return new ThreatPattern
        {
            Name = name,
            Description = $"Test pattern: {name}",
            Type = type,
            Severity = severity,
            ConfidenceScore = confidence,
            FileHashes = new List<string> { "abc123", "def456" },
            FileNamePatterns = new List<string> { "*.exe", "malware.*" },
            ProcessNamePatterns = new List<string> { "malicious.exe" },
            NetworkAddressPatterns = new List<string> { "192.168.1.*" },
            NetworkPorts = new List<int> { 4444, 8080 }
        };
    }
}
