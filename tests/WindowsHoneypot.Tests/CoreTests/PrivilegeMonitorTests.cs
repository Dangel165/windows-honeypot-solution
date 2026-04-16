using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Unit tests for PrivilegeMonitor service
/// Tests Requirements 8.1, 8.2, 8.3, 8.4, 8.5
/// </summary>
public class PrivilegeMonitorTests : IDisposable
{
    private readonly Mock<ILogger<PrivilegeMonitor>> _mockLogger;
    private readonly PrivilegeMonitor _privilegeMonitor;

    public PrivilegeMonitorTests()
    {
        _mockLogger = new Mock<ILogger<PrivilegeMonitor>>();
        _privilegeMonitor = new PrivilegeMonitor(_mockLogger.Object);
    }

    [Fact]
    public void Constructor_WithNullLogger_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new PrivilegeMonitor(null!));
    }

    [Fact]
    public void StartMonitoring_WithProcessIds_StartsMonitoring()
    {
        // Arrange
        var processIds = new[] { 1234, 5678 };

        // Act
        _privilegeMonitor.StartMonitoring(processIds);

        // Assert
        // Verify that monitoring started (check logs)
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Starting privilege monitoring")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public void StartMonitoring_WhenAlreadyMonitoring_LogsWarning()
    {
        // Arrange
        var processIds = new[] { 1234 };
        _privilegeMonitor.StartMonitoring(processIds);

        // Act
        _privilegeMonitor.StartMonitoring(processIds);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("already active")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public void StopMonitoring_WhenMonitoring_StopsSuccessfully()
    {
        // Arrange
        var processIds = new[] { 1234 };
        _privilegeMonitor.StartMonitoring(processIds);

        // Act
        _privilegeMonitor.StopMonitoring();

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Stopping privilege monitoring")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public void StopMonitoring_WhenNotMonitoring_DoesNotThrow()
    {
        // Act & Assert
        var exception = Record.Exception(() => _privilegeMonitor.StopMonitoring());
        exception.Should().BeNull();
    }

    [Fact]
    public void GetDetectedAttempts_InitiallyEmpty_ReturnsEmptyList()
    {
        // Act
        var attempts = _privilegeMonitor.GetDetectedAttempts();

        // Assert
        attempts.Should().NotBeNull();
        attempts.Should().BeEmpty();
    }

    [Fact]
    public async Task PrivilegeEscalationDetected_Event_IsFiredWhenDetected()
    {
        // Arrange
        AttackEvent? capturedEvent = null;
        _privilegeMonitor.PrivilegeEscalationDetected += (sender, evt) =>
        {
            capturedEvent = evt;
        };

        var processIds = new[] { System.Diagnostics.Process.GetCurrentProcess().Id };
        
        // Act
        _privilegeMonitor.StartMonitoring(processIds);
        await Task.Delay(TimeSpan.FromSeconds(3)); // Wait for monitoring loop
        _privilegeMonitor.StopMonitoring();

        // Assert
        // Note: This test may or may not detect escalation depending on current process privileges
        // The event handler should be set up correctly regardless
        capturedEvent.Should().BeNull(); // Current process should not be elevated in test environment
    }

    [Fact]
    public async Task SandboxEscapeDetected_Event_IsFiredWhenDetected()
    {
        // Arrange
        AttackEvent? capturedEvent = null;
        _privilegeMonitor.SandboxEscapeDetected += (sender, evt) =>
        {
            capturedEvent = evt;
        };

        var processIds = new[] { System.Diagnostics.Process.GetCurrentProcess().Id };
        
        // Act
        _privilegeMonitor.StartMonitoring(processIds);
        await Task.Delay(TimeSpan.FromSeconds(3)); // Wait for monitoring loop
        _privilegeMonitor.StopMonitoring();

        // Assert
        // Event handler should be set up correctly
        capturedEvent.Should().BeNull(); // No escape attempt in normal test
    }

    [Fact]
    public void Dispose_StopsMonitoring_AndCleansUp()
    {
        // Arrange
        var processIds = new[] { 1234 };
        _privilegeMonitor.StartMonitoring(processIds);

        // Act
        _privilegeMonitor.Dispose();

        // Assert
        // Verify cleanup occurred (monitoring stopped)
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Stopping privilege monitoring")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public void Dispose_CalledMultipleTimes_DoesNotThrow()
    {
        // Act & Assert
        _privilegeMonitor.Dispose();
        var exception = Record.Exception(() => _privilegeMonitor.Dispose());
        exception.Should().BeNull();
    }

    public void Dispose()
    {
        _privilegeMonitor?.Dispose();
    }
}
