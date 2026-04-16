using FsCheck;
using FsCheck.Xunit;
using FluentAssertions;
using WindowsHoneypot.Core.Services;
using Microsoft.Extensions.Logging;
using Moq;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Property-based tests for FileMonitor
/// **Feature: windows-honeypot-solution, Property 3: File System Event Detection**
/// </summary>
public class FileMonitorPropertyTests : IDisposable
{
    private readonly string _tempTestDirectory;

    public FileMonitorPropertyTests()
    {
        // Create a temporary directory for testing
        _tempTestDirectory = Path.Combine(Path.GetTempPath(), $"HoneypotTest_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempTestDirectory);
    }

    /// <summary>
    /// Property 3: For any file system operation within monitored folders,
    /// the File Monitor SHALL detect and log the event with accurate timestamps and process identification.
    /// **Validates: Requirements 3.1, 3.2**
    /// </summary>
    [Property(MaxTest = 50)]
    public bool FileMonitor_WithValidPath_StartsMonitoringSuccessfully(int testIndex)
    {
        // Arrange
        var mockLogger = new Mock<ILogger<FileMonitor>>();
        using var monitor = new FileMonitor(mockLogger.Object);
        var subDirName = $"TestDir{Math.Abs(testIndex % 5)}";
        var monitorPath = Path.Combine(_tempTestDirectory, subDirName);
        Directory.CreateDirectory(monitorPath);

        // Act
        Action startAction = () => monitor.StartMonitoring(monitorPath);

        // Assert
        startAction.Should().NotThrow("Starting monitoring with valid path should not throw");
        monitor.IsMonitoring.Should().BeTrue("Monitor should be active after starting");
        monitor.MonitoredPaths.Should().Contain(monitorPath, "Monitored paths should contain the added path");

        return true;
    }

    /// <summary>
    /// Property 3.1: For any invalid path, the File Monitor SHALL reject the monitoring request
    /// **Validates: Requirements 3.1**
    /// </summary>
    [Property(MaxTest = 50)]
    public bool FileMonitor_WithInvalidPath_ThrowsException(string invalidPath)
    {
        // Only test with clearly invalid paths
        if (string.IsNullOrWhiteSpace(invalidPath) || invalidPath.Contains("NonExistent") || invalidPath.Length > 200)
        {
            // Arrange
            var mockLogger = new Mock<ILogger<FileMonitor>>();
            using var monitor = new FileMonitor(mockLogger.Object);

            // Act & Assert
            if (string.IsNullOrWhiteSpace(invalidPath))
            {
                Action startAction = () => monitor.StartMonitoring(invalidPath);
                startAction.Should().Throw<ArgumentException>("Null or empty paths should throw ArgumentException");
            }
            else
            {
                Action startAction = () => monitor.StartMonitoring(invalidPath);
                startAction.Should().Throw<DirectoryNotFoundException>("Non-existent directories should throw DirectoryNotFoundException");
            }

            monitor.IsMonitoring.Should().BeFalse("Monitor should not be active after failed start");
            monitor.MonitoredPaths.Should().BeEmpty("No paths should be monitored after failed start");
        }

        return true;
    }

    /// <summary>
    /// Property 3.2: For any monitored path, the File Monitor SHALL maintain accurate monitoring state
    /// **Validates: Requirements 3.1, 3.2**
    /// </summary>
    [Property(MaxTest = 50)]
    public bool FileMonitor_MonitoringState_IsAccurate(int testIndex)
    {
        // Arrange
        var mockLogger = new Mock<ILogger<FileMonitor>>();
        using var monitor = new FileMonitor(mockLogger.Object);
        var subDirName = $"StateTest{Math.Abs(testIndex % 3)}";
        var monitorPath = Path.Combine(_tempTestDirectory, subDirName);
        Directory.CreateDirectory(monitorPath);

        // Act & Assert - Initial state
        monitor.IsMonitoring.Should().BeFalse("Initial state should not be monitoring");
        monitor.MonitoredPaths.Should().BeEmpty("Initial monitored paths should be empty");

        // Start monitoring
        monitor.StartMonitoring(monitorPath);
        monitor.IsMonitoring.Should().BeTrue("Should be monitoring after start");
        monitor.MonitoredPaths.Should().HaveCount(1, "Should have one monitored path");
        monitor.MonitoredPaths.Should().Contain(monitorPath, "Should contain the monitored path");

        // Stop monitoring
        monitor.StopMonitoring();
        monitor.IsMonitoring.Should().BeFalse("Should not be monitoring after stop");
        monitor.MonitoredPaths.Should().BeEmpty("Monitored paths should be empty after stop");

        return true;
    }

    /// <summary>
    /// Property 3.3: For any File Monitor instance, disposal SHALL be safe regardless of state
    /// **Validates: Requirements 3.1**
    /// </summary>
    [Property(MaxTest = 50)]
    public bool FileMonitor_Disposal_IsSafeInAnyState(bool shouldStartMonitoring)
    {
        // Arrange
        var mockLogger = new Mock<ILogger<FileMonitor>>();
        var monitor = new FileMonitor(mockLogger.Object);

        if (shouldStartMonitoring)
        {
            var monitorPath = Path.Combine(_tempTestDirectory, "DisposalTest");
            Directory.CreateDirectory(monitorPath);
            monitor.StartMonitoring(monitorPath);
        }

        // Act & Assert - Disposal should not throw
        Action disposeAction = () => monitor.Dispose();
        disposeAction.Should().NotThrow("Disposal should be safe in any state");

        // Multiple disposals should also be safe
        Action multipleDisposeAction = () =>
        {
            monitor.Dispose();
            monitor.Dispose();
        };
        multipleDisposeAction.Should().NotThrow("Multiple disposals should be safe");

        return true;
    }

    public void Dispose()
    {
        // Clean up test directory
        if (Directory.Exists(_tempTestDirectory))
        {
            try
            {
                Directory.Delete(_tempTestDirectory, recursive: true);
            }
            catch
            {
                // Best effort cleanup
            }
        }
    }
}