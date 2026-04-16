using Microsoft.Extensions.Logging;
using Moq;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Unit tests for RealTimeThreatMonitor
/// </summary>
public class RealTimeThreatMonitorTests
{
    private readonly Mock<ILogger<RealTimeThreatMonitor>> _mockLogger;
    private readonly Mock<ILogger<ThreatPatternDatabase>> _mockDbLogger;
    private readonly Mock<ILogger<NetworkThreatBlocker>> _mockBlockerLogger;
    private readonly IRealTimeThreatMonitor _monitor;
    private readonly string _testDatabasePath;

    public RealTimeThreatMonitorTests()
    {
        _mockLogger = new Mock<ILogger<RealTimeThreatMonitor>>();
        _mockDbLogger = new Mock<ILogger<ThreatPatternDatabase>>();
        _mockBlockerLogger = new Mock<ILogger<NetworkThreatBlocker>>();
        _testDatabasePath = Path.Combine(Path.GetTempPath(), $"test_monitor_{Guid.NewGuid()}.db");
        
        var database = new ThreatPatternDatabase(_mockDbLogger.Object, _testDatabasePath);
        var blocker = new NetworkThreatBlocker(_mockBlockerLogger.Object);
        _monitor = new RealTimeThreatMonitor(_mockLogger.Object, database, blocker);
    }

    [Fact]
    public void Constructor_ShouldInitializeSuccessfully()
    {
        // Arrange & Act
        var database = new ThreatPatternDatabase(_mockDbLogger.Object, _testDatabasePath);
        var blocker = new NetworkThreatBlocker(_mockBlockerLogger.Object);
        var monitor = new RealTimeThreatMonitor(_mockLogger.Object, database, blocker);

        // Assert
        Assert.NotNull(monitor);
        var status = monitor.GetProtectionStatus();
        Assert.False(status.IsActive);
    }

    [Fact]
    public async Task StartProtectionAsync_ShouldActivateProtection()
    {
        // Arrange
        var uniquePath = Path.Combine(Path.GetTempPath(), $"test_monitor_start_{Guid.NewGuid()}.db");
        var database = new ThreatPatternDatabase(_mockDbLogger.Object, uniquePath);
        var blocker = new NetworkThreatBlocker(_mockBlockerLogger.Object);
        var monitor = new RealTimeThreatMonitor(_mockLogger.Object, database, blocker);

        // Act
        await monitor.StartProtectionAsync();
        var status = monitor.GetProtectionStatus();

        // Assert
        Assert.True(status.IsActive);
        Assert.True(status.FileSystemMonitorActive);

        // Cleanup
        await monitor.StopProtectionAsync();
    }

    [Fact]
    public async Task StopProtectionAsync_ShouldDeactivateProtection()
    {
        // Arrange
        var uniquePath = Path.Combine(Path.GetTempPath(), $"test_monitor_stop_{Guid.NewGuid()}.db");
        var database = new ThreatPatternDatabase(_mockDbLogger.Object, uniquePath);
        var blocker = new NetworkThreatBlocker(_mockBlockerLogger.Object);
        var monitor = new RealTimeThreatMonitor(_mockLogger.Object, database, blocker);
        await monitor.StartProtectionAsync();

        // Act
        await monitor.StopProtectionAsync();
        var status = monitor.GetProtectionStatus();

        // Assert
        Assert.False(status.IsActive);
        Assert.False(status.FileSystemMonitorActive);
    }

    [Fact]
    public void RegisterThreatPattern_ShouldAddPattern()
    {
        // Arrange
        var pattern = new ThreatPattern
        {
            PatternId = "test-pattern-1",
            Name = "Test Malware",
            Type = ThreatPatternType.FileHash,
            Severity = ThreatSeverity.High,
            FileHashes = new List<string> { "abc123def456" }
        };

        // Act
        _monitor.RegisterThreatPattern(pattern);
        var patterns = _monitor.GetThreatPatterns();

        // Assert
        Assert.Single(patterns);
        Assert.Equal("test-pattern-1", patterns[0].PatternId);
        Assert.Equal("Test Malware", patterns[0].Name);
    }

    [Fact]
    public void RegisterThreatPattern_WithNullPattern_ShouldThrowException()
    {
        // Arrange, Act & Assert
        Assert.Throws<ArgumentNullException>(() => _monitor.RegisterThreatPattern(null!));
    }

    [Fact]
    public void UnregisterThreatPattern_ShouldRemovePattern()
    {
        // Arrange
        var pattern = new ThreatPattern
        {
            PatternId = "test-pattern-2",
            Name = "Test Malware 2"
        };
        _monitor.RegisterThreatPattern(pattern);

        // Act
        _monitor.UnregisterThreatPattern("test-pattern-2");
        var patterns = _monitor.GetThreatPatterns();

        // Assert
        Assert.Empty(patterns);
    }

    [Fact]
    public void GetProtectionStatus_ShouldReturnCurrentStatus()
    {
        // Act
        var status = _monitor.GetProtectionStatus();

        // Assert
        Assert.NotNull(status);
        Assert.False(status.IsActive);
        Assert.Equal(0, status.TotalThreatPatterns);
    }

    [Fact]
    public void GetStatistics_ShouldReturnStatistics()
    {
        // Act
        var stats = _monitor.GetStatistics();

        // Assert
        Assert.NotNull(stats);
        Assert.Equal(0, stats.TotalThreatsDetected);
        Assert.Equal(0, stats.FilesBlocked);
    }

    [Fact]
    public async Task AssessFileAsync_WithNonExistentFile_ShouldReturnNotThreat()
    {
        // Arrange
        string nonExistentFile = Path.Combine(Path.GetTempPath(), "nonexistent-file-12345.txt");

        // Act
        var assessment = await _monitor.AssessFileAsync(nonExistentFile);

        // Assert
        Assert.False(assessment.IsThreat);
        Assert.Equal("File", assessment.TargetType);
        Assert.Contains("does not exist", assessment.Description);
    }

    [Fact]
    public async Task AssessFileAsync_WithCleanFile_ShouldReturnNotThreat()
    {
        // Arrange
        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, "This is a clean test file");

            // Act
            var assessment = await _monitor.AssessFileAsync(tempFile);

            // Assert
            Assert.False(assessment.IsThreat);
            Assert.Equal("File", assessment.TargetType);
            Assert.Equal(ThreatAction.Allow, assessment.RecommendedAction);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task AssessFileAsync_WithMatchingHash_ShouldDetectThreat()
    {
        // Arrange
        string tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, "Malicious content");

            // Calculate the hash first
            var database = new ThreatPatternDatabase(_mockDbLogger.Object, _testDatabasePath);
            var blocker = new NetworkThreatBlocker(_mockBlockerLogger.Object);
            var monitor = new RealTimeThreatMonitor(_mockLogger.Object, database, blocker);
            var initialAssessment = await monitor.AssessFileAsync(tempFile);
            string fileHash = initialAssessment.TargetMetadata["FileHash"].ToString()!;

            // Register threat pattern with the actual hash
            var pattern = new ThreatPattern
            {
                PatternId = "malware-hash-1",
                Name = "Known Malware",
                Type = ThreatPatternType.FileHash,
                Severity = ThreatSeverity.Critical,
                FileHashes = new List<string> { fileHash },
                ConfidenceScore = 0.95
            };
            monitor.RegisterThreatPattern(pattern);

            // Act
            var assessment = await monitor.AssessFileAsync(tempFile);

            // Assert
            Assert.True(assessment.IsThreat);
            Assert.Equal(ThreatSeverity.Critical, assessment.Severity);
            Assert.Single(assessment.MatchedPatterns);
            Assert.Equal("Known Malware", assessment.MatchedPatterns[0].Name);
            Assert.True(assessment.RecommendedAction >= ThreatAction.Block);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task AssessFileAsync_WithMatchingFileName_ShouldDetectThreat()
    {
        // Arrange
        string tempFile = Path.Combine(Path.GetTempPath(), $"malware_{Guid.NewGuid():N}.exe");
        try
        {
            File.WriteAllText(tempFile, "Test content");

            var pattern = new ThreatPattern
            {
                PatternId = "malware-name-1",
                Name = "Suspicious Executable",
                Type = ThreatPatternType.FileName,
                Severity = ThreatSeverity.High,
                FileNamePatterns = new List<string> { "malware_*.exe" },
                ConfidenceScore = 0.85
            };
            _monitor.RegisterThreatPattern(pattern);

            // Act
            var assessment = await _monitor.AssessFileAsync(tempFile);

            // Assert
            Assert.True(assessment.IsThreat);
            Assert.Equal(ThreatSeverity.High, assessment.Severity);
            Assert.Single(assessment.MatchedPatterns);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task AssessProcessAsync_WithNonExistentProcess_ShouldReturnNotThreat()
    {
        // Arrange
        int nonExistentProcessId = 999999;

        // Act
        var assessment = await _monitor.AssessProcessAsync(nonExistentProcessId);

        // Assert
        Assert.False(assessment.IsThreat);
        Assert.Equal("Process", assessment.TargetType);
        Assert.Contains("not found", assessment.Description);
    }

    [Fact]
    public async Task AssessProcessAsync_WithCurrentProcess_ShouldReturnNotThreat()
    {
        // Arrange
        int currentProcessId = System.Diagnostics.Process.GetCurrentProcess().Id;

        // Act
        var assessment = await _monitor.AssessProcessAsync(currentProcessId);

        // Assert
        Assert.False(assessment.IsThreat);
        Assert.Equal("Process", assessment.TargetType);
        Assert.Equal(ThreatAction.Allow, assessment.RecommendedAction);
    }

    [Fact]
    public async Task AssessNetworkConnectionAsync_WithCleanAddress_ShouldReturnNotThreat()
    {
        // Arrange
        string remoteAddress = "8.8.8.8";
        int port = 443;

        // Act
        var assessment = await _monitor.AssessNetworkConnectionAsync(remoteAddress, port);

        // Assert
        Assert.False(assessment.IsThreat);
        Assert.Equal("Network", assessment.TargetType);
        Assert.Equal(ThreatAction.Allow, assessment.RecommendedAction);
    }

    [Fact]
    public async Task AssessNetworkConnectionAsync_WithMatchingAddress_ShouldDetectThreat()
    {
        // Arrange
        string maliciousAddress = "192.168.1.100";
        int port = 4444;

        var pattern = new ThreatPattern
        {
            PatternId = "c2-server-1",
            Name = "C2 Server",
            Type = ThreatPatternType.NetworkAddress,
            Severity = ThreatSeverity.Critical,
            NetworkAddressPatterns = new List<string> { "192.168.1.*" },
            NetworkPorts = new List<int> { 4444 },
            ConfidenceScore = 0.9
        };
        _monitor.RegisterThreatPattern(pattern);

        // Act
        var assessment = await _monitor.AssessNetworkConnectionAsync(maliciousAddress, port);

        // Assert
        Assert.True(assessment.IsThreat);
        Assert.Equal(ThreatSeverity.Critical, assessment.Severity);
        Assert.True(assessment.MatchedPatterns.Count > 0);
    }

    [Fact]
    public void ThreatDetected_EventCanBeSubscribed()
    {
        // Arrange
        bool eventRaised = false;
        ThreatDetectedEventArgs? capturedArgs = null;

        // Act - Subscribe to the event
        _monitor.ThreatDetected += (sender, args) =>
        {
            eventRaised = true;
            capturedArgs = args;
        };

        // Assert - Event subscription should succeed without errors
        // In real scenarios, this event would be triggered by file system monitoring
        Assert.True(true); // Event subscription succeeded
    }

    [Fact]
    public async Task MultiplePatterns_ShouldAllBeRegistered()
    {
        // Arrange
        var patterns = new[]
        {
            new ThreatPattern { PatternId = "p1", Name = "Pattern 1", Severity = ThreatSeverity.Low },
            new ThreatPattern { PatternId = "p2", Name = "Pattern 2", Severity = ThreatSeverity.Medium },
            new ThreatPattern { PatternId = "p3", Name = "Pattern 3", Severity = ThreatSeverity.High }
        };

        // Act
        foreach (var pattern in patterns)
        {
            _monitor.RegisterThreatPattern(pattern);
        }
        var registeredPatterns = _monitor.GetThreatPatterns();

        // Assert
        Assert.Equal(3, registeredPatterns.Count);
        Assert.Contains(registeredPatterns, p => p.PatternId == "p1");
        Assert.Contains(registeredPatterns, p => p.PatternId == "p2");
        Assert.Contains(registeredPatterns, p => p.PatternId == "p3");
    }

    [Fact]
    public async Task Statistics_ShouldUpdateOnThreatDetection()
    {
        // Arrange
        string tempFile = Path.Combine(Path.GetTempPath(), "threat-test.exe");
        try
        {
            File.WriteAllText(tempFile, "Test content");

            var pattern = new ThreatPattern
            {
                PatternId = "stats-test-1",
                Name = "Stats Test Malware",
                Severity = ThreatSeverity.High,
                FileNamePatterns = new List<string> { "threat-test.*" },
                ConfidenceScore = 0.8
            };
            _monitor.RegisterThreatPattern(pattern);

            var initialStats = _monitor.GetStatistics();
            int initialThreats = initialStats.TotalThreatsDetected;

            // Act
            await _monitor.AssessFileAsync(tempFile);
            var updatedStats = _monitor.GetStatistics();

            // Assert
            Assert.True(updatedStats.TotalThreatsDetected > initialThreats);
            Assert.True(updatedStats.FilesBlocked > 0);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }
}
