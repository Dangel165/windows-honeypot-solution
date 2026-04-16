using Microsoft.Extensions.Logging;
using Moq;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Unit tests for the Intrusion Alert System
/// </summary>
public class IntrusionAlertSystemTests
{
    private readonly Mock<ILogger<IntrusionAlertSystem>> _mockLogger;
    private readonly IntrusionAlertSystem _alertSystem;

    public IntrusionAlertSystemTests()
    {
        _mockLogger = new Mock<ILogger<IntrusionAlertSystem>>();
        _alertSystem = new IntrusionAlertSystem(_mockLogger.Object);
    }

    [Fact]
    public void Constructor_WithNullLogger_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new IntrusionAlertSystem(null!));
    }

    [Fact]
    public void Start_SetsIsActiveToTrue()
    {
        // Act
        _alertSystem.Start();

        // Assert
        Assert.True(_alertSystem.IsActive);
    }

    [Fact]
    public void Stop_SetsIsActiveToFalse()
    {
        // Arrange
        _alertSystem.Start();

        // Act
        _alertSystem.Stop();

        // Assert
        Assert.False(_alertSystem.IsActive);
    }

    [Fact]
    public void AttackCount_InitiallyZero()
    {
        // Assert
        Assert.Equal(0, _alertSystem.AttackCount);
    }

    [Fact]
    public void TriggerAlert_WithNullEvent_ThrowsArgumentNullException()
    {
        // Arrange
        _alertSystem.Start();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _alertSystem.TriggerAlert(null!));
    }

    [Fact]
    public void TriggerAlert_WhenActive_IncreasesAttackCount()
    {
        // Arrange
        _alertSystem.Start();
        var attackEvent = new AttackEvent
        {
            EventType = AttackEventType.FileModification,
            SourceProcess = "test.exe",
            TargetFile = "test.txt",
            Description = "Test attack"
        };

        // Act
        _alertSystem.TriggerAlert(attackEvent);

        // Assert
        Assert.Equal(1, _alertSystem.AttackCount);
    }

    [Fact]
    public void TriggerAlert_WhenInactive_DoesNotIncreaseAttackCount()
    {
        // Arrange
        var attackEvent = new AttackEvent
        {
            EventType = AttackEventType.FileModification,
            SourceProcess = "test.exe",
            TargetFile = "test.txt"
        };

        // Act
        _alertSystem.TriggerAlert(attackEvent);

        // Assert
        Assert.Equal(0, _alertSystem.AttackCount);
    }

    [Fact]
    public void TriggerAlert_FiresIntrusionDetectedEvent()
    {
        // Arrange
        _alertSystem.Start();
        var eventFired = false;
        IntrusionDetectedEventArgs? capturedArgs = null;

        _alertSystem.IntrusionDetected += (sender, e) =>
        {
            eventFired = true;
            capturedArgs = e;
        };

        var attackEvent = new AttackEvent
        {
            EventType = AttackEventType.FileModification,
            SourceProcess = "test.exe",
            TargetFile = "test.txt",
            Description = "Test attack",
            Severity = ThreatSeverity.High
        };

        // Act
        _alertSystem.TriggerAlert(attackEvent);

        // Assert
        Assert.True(eventFired);
        Assert.NotNull(capturedArgs);
        Assert.Equal(attackEvent, capturedArgs.AttackEvent);
        Assert.Equal(ThreatSeverity.High, capturedArgs.Severity);
        Assert.Contains("INTRUSION DETECTED", capturedArgs.AlertMessage);
    }

    [Fact]
    public void RegisterFileMonitor_WithNullMonitor_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _alertSystem.RegisterFileMonitor(null!));
    }

    [Fact]
    public void RegisterFileMonitor_SubscribesToFileMonitorEvents()
    {
        // Arrange
        var mockFileMonitor = new Mock<IFileMonitor>();
        
        // Act
        _alertSystem.RegisterFileMonitor(mockFileMonitor.Object);

        // Assert
        mockFileMonitor.VerifyAdd(m => m.FileAccessed += It.IsAny<EventHandler<FileEventArgs>>(), Times.Once);
        mockFileMonitor.VerifyAdd(m => m.FileModified += It.IsAny<EventHandler<FileEventArgs>>(), Times.Once);
        mockFileMonitor.VerifyAdd(m => m.FileDeleted += It.IsAny<EventHandler<FileEventArgs>>(), Times.Once);
        mockFileMonitor.VerifyAdd(m => m.FileRenamed += It.IsAny<EventHandler<FileRenamedEventArgs>>(), Times.Once);
    }

    [Fact]
    public void FileMonitorEvents_WhenActive_TriggerIntrusions()
    {
        // Arrange
        _alertSystem.Start();
        var mockFileMonitor = new Mock<IFileMonitor>();
        _alertSystem.RegisterFileMonitor(mockFileMonitor.Object);

        var intrusionCount = 0;
        _alertSystem.IntrusionDetected += (sender, e) => intrusionCount++;

        // Act - Trigger file modified event
        mockFileMonitor.Raise(m => m.FileModified += null, new FileEventArgs
        {
            FilePath = "test.txt",
            ProcessName = "attacker.exe",
            ProcessId = 1234,
            EventType = AttackEventType.FileModification
        });

        // Assert
        Assert.Equal(1, intrusionCount);
        Assert.Equal(1, _alertSystem.AttackCount);
    }

    [Fact]
    public void AnalyzeAttackPatterns_WithNoAttacks_ReturnsEmptyAnalysis()
    {
        // Act
        var analysis = _alertSystem.AnalyzeAttackPatterns();

        // Assert
        Assert.Equal(0, analysis.TotalAttacks);
        Assert.Equal("No attacks detected", analysis.PatternDescription);
    }

    [Fact]
    public void AnalyzeAttackPatterns_WithMultipleAttacks_ReturnsCorrectStatistics()
    {
        // Arrange
        _alertSystem.Start();

        var attacks = new[]
        {
            new AttackEvent { EventType = AttackEventType.FileModification, TargetFile = "file1.txt", SourceProcess = "proc1.exe" },
            new AttackEvent { EventType = AttackEventType.FileModification, TargetFile = "file2.txt", SourceProcess = "proc1.exe" },
            new AttackEvent { EventType = AttackEventType.FileDeletion, TargetFile = "file3.txt", SourceProcess = "proc2.exe" }
        };

        foreach (var attack in attacks)
        {
            _alertSystem.TriggerAlert(attack);
        }

        // Act
        var analysis = _alertSystem.AnalyzeAttackPatterns();

        // Assert
        Assert.Equal(3, analysis.TotalAttacks);
        Assert.Equal(2, analysis.UniqueAttackTypes);
        Assert.Equal(AttackEventType.FileModification, analysis.MostCommonAttackType);
        Assert.Contains("proc1.exe", analysis.MostActiveProcesses);
    }

    [Fact]
    public void AnalyzeAttackPatterns_CalculatesTimeMetrics()
    {
        // Arrange
        _alertSystem.Start();

        var baseTime = DateTime.UtcNow;
        var attacks = new[]
        {
            new AttackEvent { EventType = AttackEventType.FileModification, Timestamp = baseTime },
            new AttackEvent { EventType = AttackEventType.FileDeletion, Timestamp = baseTime.AddSeconds(10) },
            new AttackEvent { EventType = AttackEventType.FileRename, Timestamp = baseTime.AddSeconds(20) }
        };

        foreach (var attack in attacks)
        {
            _alertSystem.TriggerAlert(attack);
        }

        // Act
        var analysis = _alertSystem.AnalyzeAttackPatterns();

        // Assert
        Assert.NotNull(analysis.FirstAttackTime);
        Assert.NotNull(analysis.LastAttackTime);
        Assert.Equal(baseTime, analysis.FirstAttackTime.Value);
        Assert.Equal(baseTime.AddSeconds(20), analysis.LastAttackTime.Value);
        Assert.Equal(20, analysis.AttackTimeRange.TotalSeconds);
    }

    [Fact]
    public void AnalyzeAttackPatterns_DetectsCoordinatedAttack()
    {
        // Arrange
        _alertSystem.Start();

        // Create multiple attacks from same process
        for (int i = 0; i < 5; i++)
        {
            _alertSystem.TriggerAlert(new AttackEvent
            {
                EventType = AttackEventType.FileModification,
                SourceProcess = "malware.exe",
                TargetFile = $"file{i}.txt"
            });
        }

        // Act
        var analysis = _alertSystem.AnalyzeAttackPatterns();

        // Assert
        Assert.True(analysis.CoordinatedAttackDetected);
        Assert.Contains("malware.exe", analysis.PatternDescription);
    }

    [Fact]
    public void AnalyzeAttackPatterns_AssessesOverallSeverity()
    {
        // Arrange
        _alertSystem.Start();

        // Create high severity attacks
        for (int i = 0; i < 3; i++)
        {
            _alertSystem.TriggerAlert(new AttackEvent
            {
                EventType = AttackEventType.FileDeletion,
                Severity = ThreatSeverity.High,
                TargetFile = $"file{i}.txt"
            });
        }

        // Act
        var analysis = _alertSystem.AnalyzeAttackPatterns();

        // Assert
        Assert.Equal(ThreatSeverity.Critical, analysis.OverallSeverity);
    }

    [Fact]
    public void MultipleAttacksInShortTime_TriggersAttackPatternEvent()
    {
        // Arrange
        _alertSystem.Start();
        var patternDetected = false;
        AttackPatternDetectedEventArgs? capturedArgs = null;

        _alertSystem.AttackPatternDetected += (sender, e) =>
        {
            patternDetected = true;
            capturedArgs = e;
        };

        // Act - Trigger 5 rapid attacks
        for (int i = 0; i < 5; i++)
        {
            _alertSystem.TriggerAlert(new AttackEvent
            {
                EventType = AttackEventType.FileModification,
                TargetFile = $"file{i}.txt",
                Timestamp = DateTime.UtcNow
            });
        }

        // Assert
        Assert.True(patternDetected);
        Assert.NotNull(capturedArgs);
        Assert.Contains("Rapid attack pattern", capturedArgs.PatternDescription);
    }

    [Fact]
    public void Dispose_UnsubscribesFromFileMonitor()
    {
        // Arrange
        var mockFileMonitor = new Mock<IFileMonitor>();
        _alertSystem.RegisterFileMonitor(mockFileMonitor.Object);

        // Act
        _alertSystem.Dispose();

        // Assert
        mockFileMonitor.VerifyRemove(m => m.FileAccessed -= It.IsAny<EventHandler<FileEventArgs>>(), Times.Once);
        mockFileMonitor.VerifyRemove(m => m.FileModified -= It.IsAny<EventHandler<FileEventArgs>>(), Times.Once);
        mockFileMonitor.VerifyRemove(m => m.FileDeleted -= It.IsAny<EventHandler<FileEventArgs>>(), Times.Once);
        mockFileMonitor.VerifyRemove(m => m.FileRenamed -= It.IsAny<EventHandler<FileRenamedEventArgs>>(), Times.Once);
    }

    [Fact]
    public void AttackEvents_ReturnsReadOnlyList()
    {
        // Arrange
        _alertSystem.Start();
        _alertSystem.TriggerAlert(new AttackEvent
        {
            EventType = AttackEventType.FileModification,
            TargetFile = "test.txt"
        });

        // Act
        var events = _alertSystem.AttackEvents;

        // Assert
        Assert.IsAssignableFrom<IReadOnlyList<AttackEvent>>(events);
        Assert.Single(events);
    }

    [Fact]
    public void FileDeletedEvent_CreatesCriticalSeverityAttack()
    {
        // Arrange
        _alertSystem.Start();
        var mockFileMonitor = new Mock<IFileMonitor>();
        _alertSystem.RegisterFileMonitor(mockFileMonitor.Object);

        IntrusionDetectedEventArgs? capturedArgs = null;
        _alertSystem.IntrusionDetected += (sender, e) => capturedArgs = e;

        // Act
        mockFileMonitor.Raise(m => m.FileDeleted += null, new FileEventArgs
        {
            FilePath = "important.txt",
            ProcessName = "attacker.exe",
            ProcessId = 1234,
            EventType = AttackEventType.FileDeletion
        });

        // Assert
        Assert.NotNull(capturedArgs);
        Assert.Equal(ThreatSeverity.High, capturedArgs.Severity);
        Assert.Equal(AttackEventType.FileDeletion, capturedArgs.AttackEvent.EventType);
    }

    [Fact]
    public void FileRenamedEvent_StoresOldAndNewNames()
    {
        // Arrange
        _alertSystem.Start();
        var mockFileMonitor = new Mock<IFileMonitor>();
        _alertSystem.RegisterFileMonitor(mockFileMonitor.Object);

        IntrusionDetectedEventArgs? capturedArgs = null;
        _alertSystem.IntrusionDetected += (sender, e) => capturedArgs = e;

        // Act
        mockFileMonitor.Raise(m => m.FileRenamed += null, new FileRenamedEventArgs
        {
            OldName = "document.txt",
            NewName = "encrypted.txt",
            ProcessName = "ransomware.exe",
            ProcessId = 5678
        });

        // Assert
        Assert.NotNull(capturedArgs);
        Assert.Equal(AttackEventType.FileRename, capturedArgs.AttackEvent.EventType);
        Assert.True(capturedArgs.AttackEvent.Metadata.ContainsKey("OldName"));
        Assert.True(capturedArgs.AttackEvent.Metadata.ContainsKey("NewName"));
        Assert.Equal("document.txt", capturedArgs.AttackEvent.Metadata["OldName"]);
        Assert.Equal("encrypted.txt", capturedArgs.AttackEvent.Metadata["NewName"]);
    }
}
