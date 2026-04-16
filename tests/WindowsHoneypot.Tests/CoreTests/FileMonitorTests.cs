using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Unit tests for FileMonitor
/// Tests specific scenarios and edge cases for file system monitoring
/// </summary>
public class FileMonitorTests : IDisposable
{
    private readonly Mock<ILogger<FileMonitor>> _mockLogger;
    private readonly IFileMonitor _fileMonitor;
    private readonly string _testDirectory;

    public FileMonitorTests()
    {
        _mockLogger = new Mock<ILogger<FileMonitor>>();
        _fileMonitor = new FileMonitor(_mockLogger.Object);
        
        // Create a temporary test directory
        _testDirectory = Path.Combine(Path.GetTempPath(), $"FileMonitorTest_{Guid.NewGuid()}");
        Directory.CreateDirectory(_testDirectory);
    }

    public void Dispose()
    {
        _fileMonitor.StopMonitoring();
        (_fileMonitor as IDisposable)?.Dispose();
        
        // Cleanup test directory
        if (Directory.Exists(_testDirectory))
        {
            try
            {
                Directory.Delete(_testDirectory, true);
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
        Action act = () => new FileMonitor(null!);
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("logger");
    }

    [Fact]
    public void IsMonitoring_WhenNotStarted_ReturnsFalse()
    {
        // Act
        var isMonitoring = _fileMonitor.IsMonitoring;

        // Assert
        isMonitoring.Should().BeFalse();
    }

    [Fact]
    public void MonitoredPaths_WhenNotStarted_ReturnsEmptyList()
    {
        // Act
        var paths = _fileMonitor.MonitoredPaths;

        // Assert
        paths.Should().BeEmpty();
    }

    [Fact]
    public void StartMonitoring_WithNullPath_ThrowsArgumentException()
    {
        // Act
        Action act = () => _fileMonitor.StartMonitoring(null!);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithParameterName("path");
    }

    [Fact]
    public void StartMonitoring_WithEmptyPath_ThrowsArgumentException()
    {
        // Act
        Action act = () => _fileMonitor.StartMonitoring(string.Empty);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithParameterName("path");
    }

    [Fact]
    public void StartMonitoring_WithWhitespacePath_ThrowsArgumentException()
    {
        // Act
        Action act = () => _fileMonitor.StartMonitoring("   ");

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithParameterName("path");
    }

    [Fact]
    public void StartMonitoring_WithNonExistentDirectory_ThrowsDirectoryNotFoundException()
    {
        // Arrange
        var nonExistentPath = Path.Combine(Path.GetTempPath(), $"NonExistent_{Guid.NewGuid()}");

        // Act
        Action act = () => _fileMonitor.StartMonitoring(nonExistentPath);

        // Assert
        act.Should().Throw<DirectoryNotFoundException>();
    }

    [Fact]
    public void StartMonitoring_WithValidPath_StartsMonitoring()
    {
        // Act
        _fileMonitor.StartMonitoring(_testDirectory);

        // Assert
        _fileMonitor.IsMonitoring.Should().BeTrue();
        _fileMonitor.MonitoredPaths.Should().Contain(_testDirectory);
    }

    [Fact]
    public void StartMonitoring_SamePathTwice_DoesNotAddDuplicate()
    {
        // Act
        _fileMonitor.StartMonitoring(_testDirectory);
        _fileMonitor.StartMonitoring(_testDirectory);

        // Assert
        _fileMonitor.MonitoredPaths.Should().HaveCount(1);
        _fileMonitor.MonitoredPaths.Should().Contain(_testDirectory);
    }

    [Fact]
    public void StartMonitoring_MultiplePaths_MonitorsAll()
    {
        // Arrange
        var testDirectory2 = Path.Combine(Path.GetTempPath(), $"FileMonitorTest2_{Guid.NewGuid()}");
        Directory.CreateDirectory(testDirectory2);

        try
        {
            // Act
            _fileMonitor.StartMonitoring(_testDirectory);
            _fileMonitor.StartMonitoring(testDirectory2);

            // Assert
            _fileMonitor.MonitoredPaths.Should().HaveCount(2);
            _fileMonitor.MonitoredPaths.Should().Contain(_testDirectory);
            _fileMonitor.MonitoredPaths.Should().Contain(testDirectory2);
        }
        finally
        {
            if (Directory.Exists(testDirectory2))
            {
                Directory.Delete(testDirectory2, true);
            }
        }
    }

    [Fact]
    public void StopMonitoring_WhenNotMonitoring_DoesNotThrow()
    {
        // Act
        Action act = () => _fileMonitor.StopMonitoring();

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void StopMonitoring_WhenMonitoring_StopsMonitoring()
    {
        // Arrange
        _fileMonitor.StartMonitoring(_testDirectory);

        // Act
        _fileMonitor.StopMonitoring();

        // Assert
        _fileMonitor.IsMonitoring.Should().BeFalse();
        _fileMonitor.MonitoredPaths.Should().BeEmpty();
    }

    [Fact]
    public async Task FileCreated_RaisesFileAccessedEvent()
    {
        // Arrange
        _fileMonitor.StartMonitoring(_testDirectory);
        
        FileEventArgs? capturedEvent = null;
        _fileMonitor.FileAccessed += (sender, args) => capturedEvent = args;

        // Act
        var testFile = Path.Combine(_testDirectory, "test.txt");
        await File.WriteAllTextAsync(testFile, "test content");
        
        // Wait for event to fire
        await Task.Delay(500);

        // Assert
        capturedEvent.Should().NotBeNull();
        capturedEvent!.FilePath.Should().Be(testFile);
        capturedEvent.EventType.Should().Be(AttackEventType.FileAccess);
        capturedEvent.Timestamp.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task FileModified_RaisesFileModifiedEvent()
    {
        // Arrange
        var testFile = Path.Combine(_testDirectory, "test.txt");
        await File.WriteAllTextAsync(testFile, "initial content");
        
        _fileMonitor.StartMonitoring(_testDirectory);
        
        FileEventArgs? capturedEvent = null;
        _fileMonitor.FileModified += (sender, args) => capturedEvent = args;

        // Act
        await Task.Delay(100); // Ensure watcher is ready
        await File.WriteAllTextAsync(testFile, "modified content");
        
        // Wait for event to fire
        await Task.Delay(500);

        // Assert
        capturedEvent.Should().NotBeNull();
        capturedEvent!.FilePath.Should().Be(testFile);
        capturedEvent.EventType.Should().Be(AttackEventType.FileModification);
    }

    [Fact]
    public async Task FileDeleted_RaisesFileDeletedEvent()
    {
        // Arrange
        var testFile = Path.Combine(_testDirectory, "test.txt");
        await File.WriteAllTextAsync(testFile, "test content");
        
        _fileMonitor.StartMonitoring(_testDirectory);
        
        FileEventArgs? capturedEvent = null;
        _fileMonitor.FileDeleted += (sender, args) => capturedEvent = args;

        // Act
        await Task.Delay(100); // Ensure watcher is ready
        File.Delete(testFile);
        
        // Wait for event to fire
        await Task.Delay(500);

        // Assert
        capturedEvent.Should().NotBeNull();
        capturedEvent!.FilePath.Should().Be(testFile);
        capturedEvent.EventType.Should().Be(AttackEventType.FileDeletion);
    }

    [Fact]
    public async Task FileRenamed_RaisesFileRenamedEvent()
    {
        // Arrange
        var testFile = Path.Combine(_testDirectory, "test.txt");
        var renamedFile = Path.Combine(_testDirectory, "renamed.txt");
        await File.WriteAllTextAsync(testFile, "test content");
        
        _fileMonitor.StartMonitoring(_testDirectory);
        
        FileRenamedEventArgs? capturedEvent = null;
        _fileMonitor.FileRenamed += (sender, args) => capturedEvent = args;

        // Act
        await Task.Delay(100); // Ensure watcher is ready
        File.Move(testFile, renamedFile);
        
        // Wait for event to fire
        await Task.Delay(500);

        // Assert
        capturedEvent.Should().NotBeNull();
        capturedEvent!.OldName.Should().Be(testFile);
        capturedEvent.NewName.Should().Be(renamedFile);
        capturedEvent.EventType.Should().Be(AttackEventType.FileRename);
    }

    [Fact]
    public async Task FileEvents_IncludeProcessInformation()
    {
        // Arrange
        _fileMonitor.StartMonitoring(_testDirectory);
        
        FileEventArgs? capturedEvent = null;
        _fileMonitor.FileAccessed += (sender, args) => capturedEvent = args;

        // Act
        var testFile = Path.Combine(_testDirectory, "test.txt");
        await File.WriteAllTextAsync(testFile, "test content");
        
        // Wait for event to fire
        await Task.Delay(500);

        // Assert
        capturedEvent.Should().NotBeNull();
        capturedEvent!.ProcessName.Should().NotBeNullOrEmpty();
        capturedEvent.ProcessId.Should().BeGreaterOrEqualTo(0);
    }

    [Fact]
    public async Task SubdirectoryChanges_AreDetected()
    {
        // Arrange
        var subDirectory = Path.Combine(_testDirectory, "subdir");
        Directory.CreateDirectory(subDirectory);
        
        _fileMonitor.StartMonitoring(_testDirectory);
        
        FileEventArgs? capturedEvent = null;
        _fileMonitor.FileAccessed += (sender, args) => capturedEvent = args;

        // Act
        var testFile = Path.Combine(subDirectory, "test.txt");
        await File.WriteAllTextAsync(testFile, "test content");
        
        // Wait for event to fire
        await Task.Delay(500);

        // Assert
        capturedEvent.Should().NotBeNull();
        capturedEvent!.FilePath.Should().Be(testFile);
    }

    [Fact]
    public void Dispose_StopsMonitoring()
    {
        // Arrange
        _fileMonitor.StartMonitoring(_testDirectory);

        // Act
        (_fileMonitor as IDisposable)?.Dispose();

        // Assert
        _fileMonitor.IsMonitoring.Should().BeFalse();
        _fileMonitor.MonitoredPaths.Should().BeEmpty();
    }

    [Fact]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        // Arrange
        _fileMonitor.StartMonitoring(_testDirectory);

        // Act
        Action act = () =>
        {
            (_fileMonitor as IDisposable)?.Dispose();
            (_fileMonitor as IDisposable)?.Dispose();
            (_fileMonitor as IDisposable)?.Dispose();
        };

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public async Task MultipleFileOperations_AllDetected()
    {
        // Arrange
        _fileMonitor.StartMonitoring(_testDirectory);
        
        var accessedEvents = new List<FileEventArgs>();
        var modifiedEvents = new List<FileEventArgs>();
        var deletedEvents = new List<FileEventArgs>();
        
        _fileMonitor.FileAccessed += (sender, args) => accessedEvents.Add(args);
        _fileMonitor.FileModified += (sender, args) => modifiedEvents.Add(args);
        _fileMonitor.FileDeleted += (sender, args) => deletedEvents.Add(args);

        // Act
        var testFile1 = Path.Combine(_testDirectory, "test1.txt");
        var testFile2 = Path.Combine(_testDirectory, "test2.txt");
        
        await File.WriteAllTextAsync(testFile1, "content1");
        await Task.Delay(200);
        
        await File.WriteAllTextAsync(testFile2, "content2");
        await Task.Delay(200);
        
        await File.WriteAllTextAsync(testFile1, "modified content");
        await Task.Delay(200);
        
        File.Delete(testFile2);
        await Task.Delay(500);

        // Assert
        accessedEvents.Should().HaveCountGreaterOrEqualTo(2, "at least 2 files were created");
        modifiedEvents.Should().HaveCountGreaterOrEqualTo(1, "at least 1 file was modified");
        deletedEvents.Should().HaveCount(1, "exactly 1 file was deleted");
    }
}
