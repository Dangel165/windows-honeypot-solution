using FsCheck;
using FsCheck.Xunit;
using FluentAssertions;
using WindowsHoneypot.Core.Services;
using WindowsHoneypot.Core.Models;
using Microsoft.Extensions.Logging;
using Moq;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Property-based tests for IntrusionAlertSystem
/// **Feature: windows-honeypot-solution, Property 4: Intrusion Alert Generation**
/// </summary>
public class IntrusionAlertSystemPropertyTests : IDisposable
{
    private readonly IntrusionAlertSystem _alertSystem;

    public IntrusionAlertSystemPropertyTests()
    {
        var mockLogger = new Mock<ILogger<IntrusionAlertSystem>>();
        _alertSystem = new IntrusionAlertSystem(mockLogger.Object);
    }

    /// <summary>
    /// Property 4: For any detected intrusion event, the Honeypot Manager SHALL generate 
    /// an appropriate alert notification to inform security personnel.
    /// **Validates: Requirements 4.1**
    /// </summary>
    [Property(MaxTest = 100)]
    public bool IntrusionAlertSystem_WithValidAttackEvent_GeneratesAlert(int testIndex)
    {
        // Arrange
        var mockLogger = new Mock<ILogger<IntrusionAlertSystem>>();
        using var alertSystem = new IntrusionAlertSystem(mockLogger.Object);
        
        var alertTriggered = false;
        IntrusionDetectedEventArgs? capturedArgs = null;

        alertSystem.IntrusionDetected += (sender, args) =>
        {
            alertTriggered = true;
            capturedArgs = args;
        };

        alertSystem.Start();

        // Create a test attack event with deterministic values based on testIndex
        var eventTypes = new[] { AttackEventType.FileAccess, AttackEventType.FileModification, AttackEventType.FileDeletion };
        var processNames = new[] { "explorer.exe", "cmd.exe", "powershell.exe", "malware.exe" };
        var targetFiles = new[] { @"C:\BaitFolder\document.txt", @"C:\Test\data.csv", @"D:\Honeypot\config.json" };
        var severities = new[] { ThreatSeverity.Low, ThreatSeverity.Medium, ThreatSeverity.High };

        var attackEvent = new AttackEvent
        {
            EventId = Guid.NewGuid(),
            EventType = eventTypes[Math.Abs(testIndex) % eventTypes.Length],
            SourceProcess = processNames[Math.Abs(testIndex) % processNames.Length],
            ProcessId = Math.Abs(testIndex % 65535) + 1,
            TargetFile = targetFiles[Math.Abs(testIndex) % targetFiles.Length],
            Severity = severities[Math.Abs(testIndex) % severities.Length],
            Timestamp = DateTime.UtcNow,
            Description = $"Test attack {testIndex}"
        };

        // Act
        alertSystem.TriggerAlert(attackEvent);

        // Assert
        alertTriggered.Should().BeTrue("Alert should be triggered for any valid attack event");
        capturedArgs.Should().NotBeNull("Event args should be provided");
        capturedArgs!.AttackEvent.Should().BeEquivalentTo(attackEvent, "Event should match the triggered attack");
        capturedArgs.AlertMessage.Should().NotBeNullOrEmpty("Alert message should be generated");
        capturedArgs.Severity.Should().Be(attackEvent.Severity, "Severity should match the attack event");

        alertSystem.AttackCount.Should().Be(1, "Attack count should increment");
        alertSystem.AttackEvents.Should().Contain(attackEvent, "Attack event should be stored");

        return true;
    }

    /// <summary>
    /// Property 4.1: For any alert system state, starting and stopping SHALL be idempotent
    /// **Validates: Requirements 4.1**
    /// </summary>
    [Property(MaxTest = 100)]
    public bool IntrusionAlertSystem_StartStop_IsIdempotent(int cycleCount)
    {
        // Limit cycle count to reasonable range
        cycleCount = Math.Abs(cycleCount % 3) + 1;

        // Arrange
        var mockLogger = new Mock<ILogger<IntrusionAlertSystem>>();
        using var alertSystem = new IntrusionAlertSystem(mockLogger.Object);

        // Act & Assert - Multiple start/stop cycles
        for (int i = 0; i < cycleCount; i++)
        {
            // Multiple starts should be safe
            alertSystem.Start();
            alertSystem.Start(); // Second start should be safe
            alertSystem.IsActive.Should().BeTrue($"Should be active after start cycle {i + 1}");

            // Multiple stops should be safe
            alertSystem.Stop();
            alertSystem.Stop(); // Second stop should be safe
            alertSystem.IsActive.Should().BeFalse($"Should be inactive after stop cycle {i + 1}");
        }

        return true;
    }

    /// <summary>
    /// Property 4.2: For any alert system instance, disposal SHALL be safe regardless of state
    /// **Validates: Requirements 4.1**
    /// </summary>
    [Property(MaxTest = 100)]
    public bool IntrusionAlertSystem_Disposal_IsSafeInAnyState(bool shouldStart)
    {
        // Arrange
        var mockLogger = new Mock<ILogger<IntrusionAlertSystem>>();
        var alertSystem = new IntrusionAlertSystem(mockLogger.Object);

        if (shouldStart)
        {
            alertSystem.Start();
            var attackEvent = new AttackEvent
            {
                EventId = Guid.NewGuid(),
                EventType = AttackEventType.FileAccess,
                SourceProcess = "test.exe",
                ProcessId = 1234,
                TargetFile = @"C:\test.txt",
                Severity = ThreatSeverity.Low,
                Timestamp = DateTime.UtcNow,
                Description = "Test attack"
            };
            alertSystem.TriggerAlert(attackEvent);
        }

        // Act & Assert - Disposal should not throw
        Action disposeAction = () => alertSystem.Dispose();
        disposeAction.Should().NotThrow("Disposal should be safe in any state");

        // Multiple disposals should also be safe
        Action multipleDisposeAction = () =>
        {
            alertSystem.Dispose();
            alertSystem.Dispose();
        };
        multipleDisposeAction.Should().NotThrow("Multiple disposals should be safe");

        return true;
    }

    public void Dispose()
    {
        _alertSystem?.Dispose();
    }
}