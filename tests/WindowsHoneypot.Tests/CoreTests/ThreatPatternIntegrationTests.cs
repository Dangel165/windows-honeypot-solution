using Microsoft.Extensions.Logging;
using Moq;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Integration tests for threat pattern registration and blocking
/// Tests the complete flow from pattern creation to real-time blocking
/// </summary>
public class ThreatPatternIntegrationTests
{
    private readonly Mock<ILogger<ThreatPatternDatabase>> _mockDbLogger;
    private readonly Mock<ILogger<NetworkThreatBlocker>> _mockBlockerLogger;
    private readonly Mock<ILogger<RealTimeThreatMonitor>> _mockMonitorLogger;
    private readonly string _testDatabasePath;

    public ThreatPatternIntegrationTests()
    {
        _mockDbLogger = new Mock<ILogger<ThreatPatternDatabase>>();
        _mockBlockerLogger = new Mock<ILogger<NetworkThreatBlocker>>();
        _mockMonitorLogger = new Mock<ILogger<RealTimeThreatMonitor>>();
        _testDatabasePath = Path.Combine(Path.GetTempPath(), $"test_integration_{Guid.NewGuid()}.db");
    }

    [Fact]
    public void RegisterThreatPattern_ShouldStoreInDatabase()
    {
        // Arrange
        var database = new ThreatPatternDatabase(_mockDbLogger.Object, _testDatabasePath);
        var blocker = new NetworkThreatBlocker(_mockBlockerLogger.Object);
        var monitor = new RealTimeThreatMonitor(_mockMonitorLogger.Object, database, blocker);

        var pattern = new ThreatPattern
        {
            Name = "TestMalware",
            Description = "Test malware pattern",
            Type = ThreatPatternType.FileHash,
            Severity = ThreatSeverity.High,
            FileHashes = new List<string> { "abc123def456" },
            FileNamePatterns = new List<string> { "malware.exe" },
            ConfidenceScore = 0.9
        };

        // Act
        monitor.RegisterThreatPattern(pattern);
        var patterns = monitor.GetThreatPatterns();

        // Assert
        Assert.Single(patterns);
        Assert.Equal("TestMalware", patterns[0].Name);
        Assert.Equal(0.9, patterns[0].ConfidenceScore);
    }

    [Fact]
    public void RegisterMultiplePatterns_ShouldStoreAll()
    {
        // Arrange
        var database = new ThreatPatternDatabase(_mockDbLogger.Object, _testDatabasePath);
        var blocker = new NetworkThreatBlocker(_mockBlockerLogger.Object);
        var monitor = new RealTimeThreatMonitor(_mockMonitorLogger.Object, database, blocker);

        var patterns = new List<ThreatPattern>
        {
            CreateTestPattern("Pattern1", ThreatSeverity.Critical),
            CreateTestPattern("Pattern2", ThreatSeverity.High),
            CreateTestPattern("Pattern3", ThreatSeverity.Medium)
        };

        // Act
        foreach (var pattern in patterns)
        {
            monitor.RegisterThreatPattern(pattern);
        }

        var registered = monitor.GetThreatPatterns();

        // Assert
        Assert.Equal(3, registered.Count);
        Assert.Contains(registered, p => p.Name == "Pattern1");
        Assert.Contains(registered, p => p.Name == "Pattern2");
        Assert.Contains(registered, p => p.Name == "Pattern3");
    }

    [Fact]
    public void UnregisterThreatPattern_ShouldRemoveFromDatabase()
    {
        // Arrange
        var database = new ThreatPatternDatabase(_mockDbLogger.Object, _testDatabasePath);
        var blocker = new NetworkThreatBlocker(_mockBlockerLogger.Object);
        var monitor = new RealTimeThreatMonitor(_mockMonitorLogger.Object, database, blocker);

        var pattern = CreateTestPattern("TestPattern");
        monitor.RegisterThreatPattern(pattern);

        // Act
        monitor.UnregisterThreatPattern(pattern.PatternId);
        var patterns = monitor.GetThreatPatterns();

        // Assert
        Assert.Empty(patterns);
    }

    [Fact]
    public async Task AssessFileAsync_WithMatchingPattern_ShouldDetectThreat()
    {
        // Arrange
        var database = new ThreatPatternDatabase(_mockDbLogger.Object, _testDatabasePath);
        var blocker = new NetworkThreatBlocker(_mockBlockerLogger.Object);
        var monitor = new RealTimeThreatMonitor(_mockMonitorLogger.Object, database, blocker);

        var pattern = new ThreatPattern
        {
            Name = "MaliciousFile",
            FileNamePatterns = new List<string> { "malware_integration_test.exe" },
            Severity = ThreatSeverity.Critical,
            ConfidenceScore = 0.95
        };

        monitor.RegisterThreatPattern(pattern);

        // Create a temporary test file with unique name to avoid conflicts
        var testFilePath = Path.Combine(Path.GetTempPath(), "malware_integration_test.exe");
        await File.WriteAllTextAsync(testFilePath, "test content");

        try
        {
            // Act
            var assessment = await monitor.AssessFileAsync(testFilePath);

            // Assert
            Assert.True(assessment.IsThreat);
            Assert.Equal(ThreatSeverity.Critical, assessment.Severity);
            Assert.Single(assessment.MatchedPatterns);
            Assert.Equal("MaliciousFile", assessment.MatchedPatterns[0].Name);
        }
        finally
        {
            // Cleanup with retry to handle any file handle delays
            for (int i = 0; i < 3; i++)
            {
                try
                {
                    if (File.Exists(testFilePath))
                        File.Delete(testFilePath);
                    break;
                }
                catch (IOException)
                {
                    await Task.Delay(100);
                }
            }
        }
    }

    [Fact]
    public async Task AssessFileAsync_WithoutMatchingPattern_ShouldNotDetectThreat()
    {
        // Arrange
        var database = new ThreatPatternDatabase(_mockDbLogger.Object, _testDatabasePath);
        var blocker = new NetworkThreatBlocker(_mockBlockerLogger.Object);
        var monitor = new RealTimeThreatMonitor(_mockMonitorLogger.Object, database, blocker);

        var pattern = new ThreatPattern
        {
            Name = "MaliciousFile",
            FileNamePatterns = new List<string> { "malware.exe" },
            Severity = ThreatSeverity.Critical
        };

        monitor.RegisterThreatPattern(pattern);

        // Create a temporary test file with different name
        var testFilePath = Path.Combine(Path.GetTempPath(), "legitimate.txt");
        await File.WriteAllTextAsync(testFilePath, "test content");

        try
        {
            // Act
            var assessment = await monitor.AssessFileAsync(testFilePath);

            // Assert
            Assert.False(assessment.IsThreat);
            Assert.Empty(assessment.MatchedPatterns);
        }
        finally
        {
            // Cleanup
            if (File.Exists(testFilePath))
                File.Delete(testFilePath);
        }
    }

    [Fact]
    public async Task AssessNetworkConnectionAsync_WithMatchingPattern_ShouldDetectThreat()
    {
        // Arrange
        var database = new ThreatPatternDatabase(_mockDbLogger.Object, _testDatabasePath);
        var blocker = new NetworkThreatBlocker(_mockBlockerLogger.Object);
        var monitor = new RealTimeThreatMonitor(_mockMonitorLogger.Object, database, blocker);

        var pattern = new ThreatPattern
        {
            Name = "MaliciousIP",
            NetworkAddressPatterns = new List<string> { "192.168.1.100" },
            NetworkPorts = new List<int> { 4444 },
            Severity = ThreatSeverity.High,
            ConfidenceScore = 0.9
        };

        monitor.RegisterThreatPattern(pattern);

        // Act
        var assessment = await monitor.AssessNetworkConnectionAsync("192.168.1.100", 4444);

        // Assert
        Assert.True(assessment.IsThreat);
        Assert.Equal(ThreatSeverity.High, assessment.Severity);
        Assert.NotEmpty(assessment.MatchedPatterns);
    }

    [Fact]
    public async Task PersistenceTest_SaveAndLoadPatterns()
    {
        // Arrange
        var database1 = new ThreatPatternDatabase(_mockDbLogger.Object, _testDatabasePath);
        var blocker1 = new NetworkThreatBlocker(_mockBlockerLogger.Object);
        var monitor1 = new RealTimeThreatMonitor(_mockMonitorLogger.Object, database1, blocker1);

        var patterns = new List<ThreatPattern>
        {
            CreateTestPattern("Pattern1"),
            CreateTestPattern("Pattern2"),
            CreateTestPattern("Pattern3")
        };

        foreach (var pattern in patterns)
        {
            monitor1.RegisterThreatPattern(pattern);
        }

        // Act - Save
        await database1.SaveAsync();

        // Create new instances and load
        var database2 = new ThreatPatternDatabase(_mockDbLogger.Object, _testDatabasePath);
        await database2.LoadAsync();
        var blocker2 = new NetworkThreatBlocker(_mockBlockerLogger.Object);
        var monitor2 = new RealTimeThreatMonitor(_mockMonitorLogger.Object, database2, blocker2);

        var loadedPatterns = monitor2.GetThreatPatterns();

        // Assert
        Assert.Equal(3, loadedPatterns.Count);
        Assert.Contains(loadedPatterns, p => p.Name == "Pattern1");
        Assert.Contains(loadedPatterns, p => p.Name == "Pattern2");
        Assert.Contains(loadedPatterns, p => p.Name == "Pattern3");

        // Cleanup
        if (File.Exists(_testDatabasePath))
            File.Delete(_testDatabasePath);
        if (File.Exists(_testDatabasePath + ".hash"))
            File.Delete(_testDatabasePath + ".hash");
        if (File.Exists(_testDatabasePath + ".backup"))
            File.Delete(_testDatabasePath + ".backup");
    }

    [Fact]
    public void GetProtectionStatus_ShouldReflectPatternCount()
    {
        // Arrange
        var database = new ThreatPatternDatabase(_mockDbLogger.Object, _testDatabasePath);
        var blocker = new NetworkThreatBlocker(_mockBlockerLogger.Object);
        var monitor = new RealTimeThreatMonitor(_mockMonitorLogger.Object, database, blocker);

        // Act - Add patterns
        monitor.RegisterThreatPattern(CreateTestPattern("P1", confidence: 0.9));
        monitor.RegisterThreatPattern(CreateTestPattern("P2", confidence: 0.6));
        monitor.RegisterThreatPattern(CreateTestPattern("P3", confidence: 0.3));

        var status = monitor.GetProtectionStatus();

        // Assert
        Assert.Equal(3, status.TotalThreatPatterns);
        Assert.Equal(2, status.ActivePatterns); // Only patterns with confidence > 0.5
    }

    private ThreatPattern CreateTestPattern(
        string name, 
        ThreatSeverity severity = ThreatSeverity.Medium,
        double confidence = 0.8)
    {
        return new ThreatPattern
        {
            Name = name,
            Description = $"Test pattern: {name}",
            Type = ThreatPatternType.Composite,
            Severity = severity,
            ConfidenceScore = confidence,
            FileHashes = new List<string> { Guid.NewGuid().ToString() },
            FileNamePatterns = new List<string> { $"{name.ToLower()}.exe" },
            ProcessNamePatterns = new List<string> { $"{name.ToLower()}.exe" },
            NetworkAddressPatterns = new List<string> { "192.168.1.*" },
            NetworkPorts = new List<int> { 4444 }
        };
    }
}
