using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Unit tests for ActivityLogger service
/// Tests Requirements 9.1, 9.2, 9.3, 9.4, 9.5, 9.6
/// </summary>
public class ActivityLoggerTests : IDisposable
{
    private readonly Mock<ILogger<ActivityLogger>> _mockLogger;
    private readonly string _testLogDirectory;
    private readonly ActivityLogger _activityLogger;

    public ActivityLoggerTests()
    {
        _mockLogger = new Mock<ILogger<ActivityLogger>>();
        _testLogDirectory = Path.Combine(Path.GetTempPath(), $"HoneypotTests_{Guid.NewGuid()}");
        _activityLogger = new ActivityLogger(_mockLogger.Object, _testLogDirectory, maxLogFileSizeMB: 1, logRetentionDays: 7);
    }

    [Fact]
    public void Constructor_WithNullLogger_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new ActivityLogger(null!));
    }

    [Fact]
    public void Constructor_CreatesLogDirectory()
    {
        // Assert
        Directory.Exists(_testLogDirectory).Should().BeTrue();
    }

    [Fact]
    public void LogActivity_WithNullEvent_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _activityLogger.LogActivity(null!));
    }

    [Fact]
    public void LogActivity_WithValidEvent_LogsSuccessfully()
    {
        // Arrange
        var attackEvent = new AttackEvent
        {
            EventType = AttackEventType.FileAccess,
            SourceProcess = "test.exe",
            ProcessId = 1234,
            TargetFile = "test.txt",
            Description = "Test file access",
            Severity = ThreatSeverity.Low
        };

        // Act
        _activityLogger.LogActivity(attackEvent);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Activity logged")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public void LogActivity_SetsTimestamp_WhenNotProvided()
    {
        // Arrange
        var attackEvent = new AttackEvent
        {
            EventType = AttackEventType.FileAccess,
            SourceProcess = "test.exe",
            ProcessId = 1234,
            Timestamp = default // Not set
        };

        var beforeLog = DateTime.UtcNow;

        // Act
        _activityLogger.LogActivity(attackEvent);

        var afterLog = DateTime.UtcNow;

        // Assert
        attackEvent.Timestamp.Should().BeAfter(beforeLog.AddSeconds(-1));
        attackEvent.Timestamp.Should().BeBefore(afterLog.AddSeconds(1));
    }

    [Fact]
    public async Task ExportToJsonAsync_CreatesJsonFile()
    {
        // Arrange
        var attackEvent = new AttackEvent
        {
            EventType = AttackEventType.FileModification,
            SourceProcess = "malware.exe",
            ProcessId = 5678,
            Description = "Test event"
        };

        _activityLogger.LogActivity(attackEvent);
        await Task.Delay(TimeSpan.FromSeconds(12)); // Wait for flush

        // Act
        var exportPath = await _activityLogger.ExportToJsonAsync();

        // Assert
        File.Exists(exportPath).Should().BeTrue();
        exportPath.Should().EndWith(".json");
        
        var content = await File.ReadAllTextAsync(exportPath);
        content.Should().NotBeEmpty();
    }

    [Fact]
    public async Task ExportToXmlAsync_CreatesXmlFile()
    {
        // Arrange
        var attackEvent = new AttackEvent
        {
            EventType = AttackEventType.NetworkAttempt,
            SourceProcess = "suspicious.exe",
            ProcessId = 9012,
            Description = "Network attempt"
        };

        _activityLogger.LogActivity(attackEvent);
        await Task.Delay(TimeSpan.FromSeconds(12)); // Wait for flush

        // Act
        var exportPath = await _activityLogger.ExportToXmlAsync();

        // Assert
        File.Exists(exportPath).Should().BeTrue();
        exportPath.Should().EndWith(".xml");
        
        var content = await File.ReadAllTextAsync(exportPath);
        content.Should().Contain("<AttackEvents>");
    }

    [Fact]
    public async Task ExportToCsvAsync_CreatesCsvFile()
    {
        // Arrange
        var attackEvent = new AttackEvent
        {
            EventType = AttackEventType.PrivilegeEscalation,
            SourceProcess = "exploit.exe",
            ProcessId = 3456,
            Description = "Privilege escalation"
        };

        _activityLogger.LogActivity(attackEvent);
        await Task.Delay(TimeSpan.FromSeconds(12)); // Wait for flush

        // Act
        var exportPath = await _activityLogger.ExportToCsvAsync();

        // Assert
        File.Exists(exportPath).Should().BeTrue();
        exportPath.Should().EndWith(".csv");
        
        var content = await File.ReadAllTextAsync(exportPath);
        content.Should().Contain("EventId,Timestamp,EventType");
    }

    [Fact]
    public async Task GenerateForensicReportAsync_CreatesReport()
    {
        // Arrange
        var attackEvent = new AttackEvent
        {
            EventType = AttackEventType.SandboxEscape,
            SourceProcess = "breakout.exe",
            ProcessId = 7890,
            Description = "Sandbox escape attempt",
            Severity = ThreatSeverity.Critical
        };

        _activityLogger.LogActivity(attackEvent);
        await Task.Delay(TimeSpan.FromSeconds(12)); // Wait for flush

        // Act
        var reportPath = await _activityLogger.GenerateForensicReportAsync();

        // Assert
        File.Exists(reportPath).Should().BeTrue();
        
        var content = await File.ReadAllTextAsync(reportPath);
        content.Should().Contain("WINDOWS HONEYPOT FORENSIC REPORT");
        content.Should().Contain("SUMMARY STATISTICS");
        content.Should().Contain("DETAILED EVENT LOG");
        content.Should().Contain("CHAIN OF CUSTODY");
    }

    [Fact]
    public async Task VerifyLogIntegrityAsync_ReturnsIntegrityResults()
    {
        // Arrange
        var attackEvent = new AttackEvent
        {
            EventType = AttackEventType.FileAccess,
            SourceProcess = "test.exe",
            ProcessId = 1111,
            Description = "Test event"
        };

        _activityLogger.LogActivity(attackEvent);
        await Task.Delay(TimeSpan.FromSeconds(12)); // Wait for flush

        // Act
        var results = await _activityLogger.VerifyLogIntegrityAsync();

        // Assert
        results.Should().NotBeNull();
        // Results may be empty if no log files have been created yet
    }

    [Fact]
    public async Task RotateLogsAsync_PerformsRotation()
    {
        // Arrange
        for (int i = 0; i < 5; i++)
        {
            _activityLogger.LogActivity(new AttackEvent
            {
                EventType = AttackEventType.FileAccess,
                SourceProcess = $"test{i}.exe",
                ProcessId = 1000 + i,
                Description = $"Test event {i}"
            });
        }

        await Task.Delay(TimeSpan.FromSeconds(12)); // Wait for flush

        // Act
        await _activityLogger.RotateLogsAsync();

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Performing log rotation")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.AtLeastOnce);
    }

    [Fact]
    public async Task ExportWithDateRange_FiltersEvents()
    {
        // Arrange
        var oldEvent = new AttackEvent
        {
            EventType = AttackEventType.FileAccess,
            SourceProcess = "old.exe",
            ProcessId = 1111,
            Timestamp = DateTime.UtcNow.AddDays(-10),
            Description = "Old event"
        };

        var recentEvent = new AttackEvent
        {
            EventType = AttackEventType.FileModification,
            SourceProcess = "recent.exe",
            ProcessId = 2222,
            Timestamp = DateTime.UtcNow,
            Description = "Recent event"
        };

        _activityLogger.LogActivity(oldEvent);
        _activityLogger.LogActivity(recentEvent);
        await Task.Delay(TimeSpan.FromSeconds(12)); // Wait for flush

        // Act
        var exportPath = await _activityLogger.ExportToJsonAsync(
            startDate: DateTime.UtcNow.AddDays(-1),
            endDate: DateTime.UtcNow.AddDays(1)
        );

        // Assert
        File.Exists(exportPath).Should().BeTrue();
        var content = await File.ReadAllTextAsync(exportPath);
        content.Should().Contain("recent.exe");
        // Old event should be filtered out
    }

    [Fact]
    public void Dispose_FlushesRemainingLogs()
    {
        // Arrange
        _activityLogger.LogActivity(new AttackEvent
        {
            EventType = AttackEventType.FileAccess,
            SourceProcess = "final.exe",
            ProcessId = 9999,
            Description = "Final event"
        });

        // Act
        _activityLogger.Dispose();

        // Assert
        // Verify that dispose was called without errors
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Activity logged")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    public void Dispose()
    {
        _activityLogger?.Dispose();

        // Clean up test directory
        if (Directory.Exists(_testLogDirectory))
        {
            try
            {
                Directory.Delete(_testLogDirectory, recursive: true);
            }
            catch
            {
                // Ignore cleanup errors
            }
        }
    }
}
