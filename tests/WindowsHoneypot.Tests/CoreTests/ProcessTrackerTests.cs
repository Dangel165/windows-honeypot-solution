using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Unit tests for ProcessTracker
/// Tests specific scenarios and edge cases for process lifecycle management
/// </summary>
public class ProcessTrackerTests : IDisposable
{
    private readonly Mock<ILogger<ProcessTracker>> _mockLogger;
    private readonly ProcessTracker _tracker;
    private readonly string _testWsbPath;

    public ProcessTrackerTests()
    {
        _mockLogger = new Mock<ILogger<ProcessTracker>>();
        _tracker = new ProcessTracker(_mockLogger.Object);
        
        // Create a temporary .wsb file for testing
        _testWsbPath = Path.Combine(Path.GetTempPath(), $"test_{Guid.NewGuid()}.wsb");
    }

    public void Dispose()
    {
        _tracker.Dispose();
        
        if (File.Exists(_testWsbPath))
        {
            try
            {
                File.Delete(_testWsbPath);
            }
            catch
            {
                // Ignore cleanup errors
            }
        }
    }

    [Fact]
    public void Constructor_WithNullLogger_ThrowsArgumentNullException()
    {
        // Act & Assert
        Action act = () => new ProcessTracker(null!);
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("logger");
    }

    [Fact]
    public void SandboxProcessId_WhenNotTracking_ReturnsNull()
    {
        // Act
        var processId = _tracker.SandboxProcessId;

        // Assert
        processId.Should().BeNull();
    }

    [Fact]
    public void IsTracking_WhenNotTracking_ReturnsFalse()
    {
        // Act
        var isTracking = _tracker.IsTracking;

        // Assert
        isTracking.Should().BeFalse();
    }

    [Fact]
    public void IsProcessRunning_WhenNotTracking_ReturnsFalse()
    {
        // Act
        var isRunning = _tracker.IsProcessRunning();

        // Assert
        isRunning.Should().BeFalse();
    }

    [Fact]
    public void GetProcessInfo_WhenNotTracking_ReturnsNull()
    {
        // Act
        var processInfo = _tracker.GetProcessInfo();

        // Assert
        processInfo.Should().BeNull();
    }

    [Fact]
    public async Task StartTrackingAsync_WithNullPath_ThrowsArgumentException()
    {
        // Act
        Func<Task> act = async () => await _tracker.StartTrackingAsync(null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithParameterName("wsbFilePath");
    }

    [Fact]
    public async Task StartTrackingAsync_WithEmptyPath_ThrowsArgumentException()
    {
        // Act
        Func<Task> act = async () => await _tracker.StartTrackingAsync(string.Empty);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithParameterName("wsbFilePath");
    }

    [Fact]
    public async Task StartTrackingAsync_WithNonExistentFile_ThrowsFileNotFoundException()
    {
        // Arrange
        var nonExistentPath = Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.wsb");

        // Act
        Func<Task> act = async () => await _tracker.StartTrackingAsync(nonExistentPath);

        // Assert
        await act.Should().ThrowAsync<FileNotFoundException>();
    }

    [Fact]
    public void StartTrackingExisting_WithZeroProcessId_ThrowsArgumentException()
    {
        // Act
        Action act = () => _tracker.StartTrackingExisting(0);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithParameterName("processId");
    }

    [Fact]
    public void StartTrackingExisting_WithNegativeProcessId_ThrowsArgumentException()
    {
        // Act
        Action act = () => _tracker.StartTrackingExisting(-1);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithParameterName("processId");
    }

    [Fact]
    public void StartTrackingExisting_WithNonExistentProcessId_ReturnsFalse()
    {
        // Arrange - Use a very high process ID that's unlikely to exist
        var nonExistentPid = 999999;

        // Act
        var result = _tracker.StartTrackingExisting(nonExistentPid);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task StopTrackingAsync_WhenNotTracking_ReturnsTrue()
    {
        // Act
        var result = await _tracker.StopTrackingAsync();

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task StopTrackingAsync_WhenNotTracking_DoesNotThrow()
    {
        // Act
        Func<Task> act = async () => await _tracker.StopTrackingAsync();

        // Assert
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public void ProcessExitedEvent_WhenNotTracking_DoesNotFire()
    {
        // Arrange
        var eventFired = false;
        _tracker.ProcessExited += (sender, args) => eventFired = true;

        // Act - Wait a moment to ensure no event fires
        Thread.Sleep(100);

        // Assert
        eventFired.Should().BeFalse();
    }

    [Fact]
    public void Dispose_WhenNotTracking_DoesNotThrow()
    {
        // Act
        Action act = () => _tracker.Dispose();

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        // Act
        Action act = () =>
        {
            _tracker.Dispose();
            _tracker.Dispose();
            _tracker.Dispose();
        };

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public async Task StartTrackingAsync_TwiceWithoutStopping_ReturnsFalseOnSecondCall()
    {
        // Arrange - Create a valid .wsb file
        var generator = new SandboxConfigurationGenerator();
        var config = new SandboxConfiguration
        {
            NetworkingEnabled = false,
            MemoryInMB = 2048
        };
        await generator.SaveWsbFileAsync(config, _testWsbPath);

        // Note: This test will fail if Windows Sandbox is not available
        // We're testing the logic, not the actual sandbox launch
        var firstResult = await _tracker.StartTrackingAsync(_testWsbPath);
        
        // Only proceed if first call succeeded (sandbox available)
        if (firstResult)
        {
            // Act
            var secondResult = await _tracker.StartTrackingAsync(_testWsbPath);

            // Assert
            secondResult.Should().BeFalse();

            // Cleanup
            await _tracker.StopTrackingAsync();
        }
    }

    [Fact]
    public void StartTrackingExisting_WithCurrentProcessId_ReturnsFalse()
    {
        // Arrange - Use current process ID (which is not a Windows Sandbox process)
        var currentProcessId = System.Diagnostics.Process.GetCurrentProcess().Id;

        // Act
        var result = _tracker.StartTrackingExisting(currentProcessId);

        // Assert
        result.Should().BeFalse("current process is not a Windows Sandbox process");
    }

    [Fact]
    public async Task ProcessTracker_AfterDispose_PropertiesReturnSafeValues()
    {
        // Arrange
        var tracker = new ProcessTracker(_mockLogger.Object);

        // Act
        tracker.Dispose();

        // Assert
        tracker.SandboxProcessId.Should().BeNull();
        tracker.IsTracking.Should().BeFalse();
        tracker.IsProcessRunning().Should().BeFalse();
        tracker.GetProcessInfo().Should().BeNull();
    }
}
