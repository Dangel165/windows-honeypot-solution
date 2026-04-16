using WindowsHoneypot.Core.Services;
using WindowsHoneypot.Core.Interfaces;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Unit tests for Visual Replay Engine
/// Tests Requirements 13.1-13.5: Mouse/keyboard recording, screenshots, timeline visualization
/// </summary>
public class VisualReplayEngineTests : IDisposable
{
    private readonly VisualReplayEngine _replayEngine;

    public VisualReplayEngineTests()
    {
        _replayEngine = new VisualReplayEngine();
    }

    [Fact]
    public void StartRecording_ShouldSetIsRecordingToTrue()
    {
        // Act
        _replayEngine.StartRecording();

        // Assert
        Assert.True(_replayEngine.IsRecording);

        // Cleanup
        _replayEngine.StopRecording();
    }

    [Fact]
    public void StopRecording_ShouldSetIsRecordingToFalse()
    {
        // Arrange
        _replayEngine.StartRecording();

        // Act
        _replayEngine.StopRecording();

        // Assert
        Assert.False(_replayEngine.IsRecording);
    }

    [Fact]
    public void StartRecording_WhenAlreadyRecording_ShouldNotThrow()
    {
        // Arrange
        _replayEngine.StartRecording();

        // Act & Assert
        var exception = Record.Exception(() => _replayEngine.StartRecording());
        Assert.Null(exception);

        // Cleanup
        _replayEngine.StopRecording();
    }

    [Fact]
    public void StopRecording_WhenNotRecording_ShouldNotThrow()
    {
        // Act & Assert
        var exception = Record.Exception(() => _replayEngine.StopRecording());
        Assert.Null(exception);
    }

    [Fact]
    public async Task GenerateReplayAsync_ShouldReturnReplayData()
    {
        // Arrange
        _replayEngine.StartRecording();
        await Task.Delay(100); // Brief recording period
        _replayEngine.StopRecording();

        // Act
        var replayData = await _replayEngine.GenerateReplayAsync();

        // Assert
        Assert.NotNull(replayData);
        Assert.NotEqual(Guid.Empty, replayData.SessionId);
        Assert.True(replayData.EndTime >= replayData.StartTime);
        Assert.NotNull(replayData.Summary);
        Assert.NotEmpty(replayData.Summary);
    }

    [Fact]
    public async Task GenerateReplayAsync_ShouldIncludeRecordingDuration()
    {
        // Arrange
        _replayEngine.StartRecording();
        await Task.Delay(200); // 200ms recording
        _replayEngine.StopRecording();

        // Act
        var replayData = await _replayEngine.GenerateReplayAsync();

        // Assert
        Assert.True(replayData.Duration.TotalMilliseconds >= 100); // At least 100ms
        Assert.Contains("Duration:", replayData.Summary);
    }

    [Fact]
    public void RecordFileOperation_ShouldAddFileOperationToReplay()
    {
        // Arrange
        _replayEngine.StartRecording();

        // Act
        _replayEngine.RecordFileOperation(
            operation: "Modify",
            filePath: @"C:\test\file.txt",
            processName: "notepad.exe",
            processId: 1234,
            details: "Test file operation"
        );
        _replayEngine.StopRecording();

        // Assert
        var replayData = _replayEngine.GenerateReplayAsync().Result;
        Assert.Single(replayData.FileOperations);
        Assert.Equal("Modify", replayData.FileOperations[0].Operation);
        Assert.Equal(@"C:\test\file.txt", replayData.FileOperations[0].FilePath);
        Assert.Equal("notepad.exe", replayData.FileOperations[0].ProcessName);
        Assert.Equal(1234, replayData.FileOperations[0].ProcessId);
    }

    [Fact]
    public void RecordFileOperation_MultipleOperations_ShouldRecordAll()
    {
        // Arrange
        _replayEngine.StartRecording();

        // Act
        _replayEngine.RecordFileOperation("Create", @"C:\test\file1.txt", "explorer.exe", 100);
        _replayEngine.RecordFileOperation("Modify", @"C:\test\file2.txt", "notepad.exe", 200);
        _replayEngine.RecordFileOperation("Delete", @"C:\test\file3.txt", "cmd.exe", 300);
        _replayEngine.StopRecording();

        // Assert
        var replayData = _replayEngine.GenerateReplayAsync().Result;
        Assert.Equal(3, replayData.FileOperations.Count);
        Assert.Contains(replayData.FileOperations, op => op.Operation == "Create");
        Assert.Contains(replayData.FileOperations, op => op.Operation == "Modify");
        Assert.Contains(replayData.FileOperations, op => op.Operation == "Delete");
    }

    [Fact]
    public void RecordProcessActivity_ShouldAddProcessActivityToReplay()
    {
        // Arrange
        _replayEngine.StartRecording();

        // Act
        _replayEngine.RecordProcessActivity(
            processName: "powershell.exe",
            processId: 5678,
            activity: "Start",
            details: "Suspicious PowerShell execution"
        );
        _replayEngine.StopRecording();

        // Assert
        var replayData = _replayEngine.GenerateReplayAsync().Result;
        Assert.Single(replayData.ProcessActivities);
        Assert.Equal("powershell.exe", replayData.ProcessActivities[0].ProcessName);
        Assert.Equal(5678, replayData.ProcessActivities[0].ProcessId);
        Assert.Equal("Start", replayData.ProcessActivities[0].Activity);
    }

    [Fact]
    public void RecordFileOperation_WhenNotRecording_ShouldNotRecord()
    {
        // Act - Not starting recording
        _replayEngine.RecordFileOperation("Modify", @"C:\test\file.txt", "notepad.exe", 1234);

        // Assert
        var replayData = _replayEngine.GenerateReplayAsync().Result;
        Assert.Empty(replayData.FileOperations);
    }

    [Fact]
    public async Task ExportToPdfAsync_ShouldCreateFile()
    {
        // Arrange
        _replayEngine.StartRecording();
        _replayEngine.RecordFileOperation("Test", @"C:\test.txt", "test.exe", 123);
        await Task.Delay(100);
        _replayEngine.StopRecording();

        var tempFile = Path.Combine(Path.GetTempPath(), $"test_replay_{Guid.NewGuid()}.pdf");

        try
        {
            // Act
            await _replayEngine.ExportToPdfAsync(tempFile);

            // Assert
            Assert.True(File.Exists(tempFile));
            var fileInfo = new FileInfo(tempFile);
            Assert.True(fileInfo.Length > 0);
            
            // Verify it's a valid PDF by checking magic bytes (%PDF)
            var bytes = await File.ReadAllBytesAsync(tempFile);
            Assert.True(bytes.Length > 4);
            Assert.Equal(0x25, bytes[0]); // %
            Assert.Equal(0x50, bytes[1]); // P
            Assert.Equal(0x44, bytes[2]); // D
            Assert.Equal(0x46, bytes[3]); // F
        }
        finally
        {
            // Cleanup - retry deletion to handle any file handle delays
            for (int i = 0; i < 3; i++)
            {
                try
                {
                    if (File.Exists(tempFile))
                        File.Delete(tempFile);
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
    public async Task GenerateReplayAsync_ShouldIncludeAllEventCounts()
    {
        // Arrange
        _replayEngine.StartRecording();
        _replayEngine.RecordFileOperation("Create", @"C:\test.txt", "test.exe", 123);
        _replayEngine.RecordProcessActivity("test.exe", 123, "Start", "Test");
        await Task.Delay(100);
        _replayEngine.StopRecording();

        // Act
        var replayData = await _replayEngine.GenerateReplayAsync();

        // Assert
        Assert.Contains("File Operations:", replayData.Summary);
        Assert.Contains("Process Activities:", replayData.Summary);
        Assert.Contains("Mouse Events:", replayData.Summary);
        Assert.Contains("Keyboard Events:", replayData.Summary);
        Assert.Contains("Screenshots:", replayData.Summary);
    }

    [Fact]
    public void RecordFileOperation_ShouldIncludeTimestamp()
    {
        // Arrange
        _replayEngine.StartRecording();
        var beforeTime = DateTime.UtcNow;

        // Act
        _replayEngine.RecordFileOperation("Test", @"C:\test.txt", "test.exe", 123);
        var afterTime = DateTime.UtcNow;
        _replayEngine.StopRecording();

        // Assert
        var replayData = _replayEngine.GenerateReplayAsync().Result;
        var fileOp = replayData.FileOperations[0];
        Assert.True(fileOp.Timestamp >= beforeTime && fileOp.Timestamp <= afterTime);
    }

    [Fact]
    public void RecordProcessActivity_ShouldIncludeTimestamp()
    {
        // Arrange
        _replayEngine.StartRecording();
        var beforeTime = DateTime.UtcNow;

        // Act
        _replayEngine.RecordProcessActivity("test.exe", 123, "Start", "Test");
        var afterTime = DateTime.UtcNow;
        _replayEngine.StopRecording();

        // Assert
        var replayData = _replayEngine.GenerateReplayAsync().Result;
        var processActivity = replayData.ProcessActivities[0];
        Assert.True(processActivity.Timestamp >= beforeTime && processActivity.Timestamp <= afterTime);
    }

    [Fact]
    public async Task GenerateTimelineAsync_ShouldCreateChronologicalTimeline()
    {
        // Arrange
        _replayEngine.StartRecording();
        _replayEngine.RecordFileOperation("Create", @"C:\test1.txt", "test.exe", 123);
        await Task.Delay(50);
        _replayEngine.RecordProcessActivity("notepad.exe", 456, "Start", "Test");
        await Task.Delay(50);
        _replayEngine.RecordFileOperation("Modify", @"C:\test2.txt", "notepad.exe", 456);
        _replayEngine.StopRecording();

        // Act
        var timeline = await _replayEngine.GenerateTimelineAsync();

        // Assert
        Assert.NotNull(timeline);
        // At least 3 entries (file op, process activity, file op) plus optional synthetic screenshot
        Assert.True(timeline.Entries.Count >= 3);
        Assert.Contains(timeline.Entries, e => e.EventType == "File");
        Assert.Contains(timeline.Entries, e => e.EventType == "Process");
        
        // Verify chronological order
        for (int i = 1; i < timeline.Entries.Count; i++)
        {
            Assert.True(timeline.Entries[i].Timestamp >= timeline.Entries[i - 1].Timestamp);
        }
    }

    [Fact]
    public async Task GenerateTimelineAsync_ShouldIncludeAllEventTypes()
    {
        // Arrange
        _replayEngine.StartRecording();
        _replayEngine.RecordFileOperation("Create", @"C:\test.txt", "test.exe", 123);
        _replayEngine.RecordProcessActivity("test.exe", 123, "Start", "Test");
        await Task.Delay(100);
        _replayEngine.StopRecording();

        // Act
        var timeline = await _replayEngine.GenerateTimelineAsync();

        // Assert
        Assert.Contains(timeline.Entries, e => e.EventType == "File");
        Assert.Contains(timeline.Entries, e => e.EventType == "Process");
        Assert.Contains(timeline.Entries, e => e.EventType == "Screenshot");
    }

    [Fact]
    public async Task GenerateTimelineAsync_ShouldCalculateStatistics()
    {
        // Arrange
        _replayEngine.StartRecording();
        _replayEngine.RecordFileOperation("Create", @"C:\test1.txt", "test.exe", 123);
        _replayEngine.RecordFileOperation("Modify", @"C:\test2.txt", "test.exe", 123);
        _replayEngine.RecordProcessActivity("test.exe", 123, "Start", "Test");
        _replayEngine.RecordProcessActivity("notepad.exe", 456, "Start", "Test");
        await Task.Delay(100);
        _replayEngine.StopRecording();

        // Act
        var timeline = await _replayEngine.GenerateTimelineAsync();

        // Assert
        Assert.Equal(2, timeline.Statistics.TotalFileOperations);
        Assert.Equal(2, timeline.Statistics.TotalProcessActivities);
        Assert.True(timeline.Statistics.TotalScreenshots > 0);
        Assert.Equal(2, timeline.Statistics.AccessedFiles.Count);
        Assert.Equal(2, timeline.Statistics.LaunchedProcesses.Count);
    }

    [Fact]
    public async Task GenerateTimelineAsync_ShouldSetSeverityLevels()
    {
        // Arrange
        _replayEngine.StartRecording();
        _replayEngine.RecordFileOperation("Delete", @"C:\important.txt", "test.exe", 123);
        _replayEngine.RecordFileOperation("Modify", @"C:\data.txt", "test.exe", 123);
        _replayEngine.RecordFileOperation("Create", @"C:\new.txt", "test.exe", 123);
        _replayEngine.StopRecording();

        // Act
        var timeline = await _replayEngine.GenerateTimelineAsync();

        // Assert
        var deleteEntry = timeline.Entries.First(e => e.Description.Contains("Delete"));
        var modifyEntry = timeline.Entries.First(e => e.Description.Contains("Modify"));
        var createEntry = timeline.Entries.First(e => e.Description.Contains("Create"));

        Assert.Equal("Critical", deleteEntry.Severity);
        Assert.Equal("Warning", modifyEntry.Severity);
        Assert.Equal("Info", createEntry.Severity);
    }

    [Fact]
    public async Task ExportVideoStylePlaybackAsync_ShouldCreatePlaybackFile()
    {
        // Arrange
        _replayEngine.StartRecording();
        _replayEngine.RecordFileOperation("Create", @"C:\test.txt", "test.exe", 123);
        await Task.Delay(100);
        _replayEngine.StopRecording();

        var tempFile = Path.Combine(Path.GetTempPath(), $"playback_{Guid.NewGuid()}.txt");

        try
        {
            // Act
            await _replayEngine.ExportVideoStylePlaybackAsync(tempFile);

            // Assert
            Assert.True(File.Exists(tempFile));
            var content = await File.ReadAllTextAsync(tempFile);
            Assert.Contains("VIDEO-STYLE PLAYBACK DATA", content);
            Assert.Contains("PLAYBACK TIMELINE", content);
            Assert.Contains("PLAYBACK INSTRUCTIONS", content);
        }
        finally
        {
            // Cleanup
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Fact]
    public async Task ExportVideoStylePlaybackAsync_ShouldIncludeElapsedTime()
    {
        // Arrange
        _replayEngine.StartRecording();
        _replayEngine.RecordFileOperation("Create", @"C:\test.txt", "test.exe", 123);
        await Task.Delay(100);
        _replayEngine.RecordProcessActivity("test.exe", 123, "Start", "Test");
        _replayEngine.StopRecording();

        var tempFile = Path.Combine(Path.GetTempPath(), $"playback_{Guid.NewGuid()}.txt");

        try
        {
            // Act
            await _replayEngine.ExportVideoStylePlaybackAsync(tempFile);

            // Assert
            var content = await File.ReadAllTextAsync(tempFile);
            Assert.Contains("[0.", content); // Should have elapsed time markers
            Assert.Contains("s]", content); // Time in seconds
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Fact]
    public async Task GenerateNonTechnicalSummaryAsync_ShouldCreateUserFriendlySummary()
    {
        // Arrange
        _replayEngine.StartRecording();
        _replayEngine.RecordFileOperation("Create", @"C:\test.txt", "test.exe", 123);
        _replayEngine.RecordFileOperation("Delete", @"C:\important.txt", "test.exe", 123);
        _replayEngine.RecordProcessActivity("notepad.exe", 456, "Start", "Test");
        await Task.Delay(100);
        _replayEngine.StopRecording();

        // Act
        var summary = await _replayEngine.GenerateNonTechnicalSummaryAsync();

        // Assert
        Assert.NotNull(summary);
        Assert.Contains("ATTACK ACTIVITY SUMMARY", summary);
        Assert.Contains("What Happened?", summary);
        Assert.Contains("File Activity:", summary);
        Assert.Contains("Programs Launched:", summary);
        Assert.Contains("Risk Assessment", summary);
    }

    [Fact]
    public async Task GenerateNonTechnicalSummaryAsync_ShouldIncludeRiskLevel()
    {
        // Arrange
        _replayEngine.StartRecording();
        
        // Create high-risk scenario
        for (int i = 0; i < 15; i++)
        {
            _replayEngine.RecordFileOperation("Delete", $@"C:\file{i}.txt", "malware.exe", 999);
        }
        
        _replayEngine.StopRecording();

        // Act
        var summary = await _replayEngine.GenerateNonTechnicalSummaryAsync();

        // Assert
        Assert.Contains("Risk Level:", summary);
        Assert.Contains("RECOMMENDED ACTIONS", summary);
    }

    [Fact]
    public async Task GenerateNonTechnicalSummaryAsync_ShouldHighlightDeletions()
    {
        // Arrange
        _replayEngine.StartRecording();
        _replayEngine.RecordFileOperation("Delete", @"C:\important.txt", "test.exe", 123);
        _replayEngine.RecordFileOperation("Delete", @"C:\data.txt", "test.exe", 123);
        _replayEngine.StopRecording();

        // Act
        var summary = await _replayEngine.GenerateNonTechnicalSummaryAsync();

        // Assert
        Assert.Contains("WARNING", summary);
        Assert.Contains("deleted", summary);
    }

    [Fact]
    public async Task ExportToPdfAsync_WithQuestPDF_ShouldCreateValidPDF()
    {
        // Arrange
        _replayEngine.StartRecording();
        _replayEngine.RecordFileOperation("Create", @"C:\test.txt", "test.exe", 123);
        _replayEngine.RecordProcessActivity("test.exe", 123, "Start", "Test");
        await Task.Delay(100);
        _replayEngine.StopRecording();

        var tempFile = Path.Combine(Path.GetTempPath(), $"report_{Guid.NewGuid()}.pdf");

        try
        {
            // Act
            await _replayEngine.ExportToPdfAsync(tempFile);

            // Assert
            Assert.True(File.Exists(tempFile));
            var fileInfo = new FileInfo(tempFile);
            Assert.True(fileInfo.Length > 0);
            
            // Verify it's a PDF by checking magic bytes
            var bytes = await File.ReadAllBytesAsync(tempFile);
            Assert.True(bytes.Length > 4);
            Assert.Equal(0x25, bytes[0]); // %
            Assert.Equal(0x50, bytes[1]); // P
            Assert.Equal(0x44, bytes[2]); // D
            Assert.Equal(0x46, bytes[3]); // F
        }
        finally
        {
            // Retry deletion to handle any file handle delays from PDF generation
            for (int i = 0; i < 3; i++)
            {
                try
                {
                    if (File.Exists(tempFile))
                        File.Delete(tempFile);
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
    public async Task ExportToPdfAsync_ShouldIncludeSessionInformation()
    {
        // Arrange
        _replayEngine.StartRecording();
        _replayEngine.RecordFileOperation("Test", @"C:\test.txt", "test.exe", 123);
        await Task.Delay(100);
        _replayEngine.StopRecording();

        var tempFile = Path.Combine(Path.GetTempPath(), $"report_{Guid.NewGuid()}.pdf");

        try
        {
            // Act
            await _replayEngine.ExportToPdfAsync(tempFile);

            // Assert - PDF was created successfully
            Assert.True(File.Exists(tempFile));
            var fileInfo = new FileInfo(tempFile);
            Assert.True(fileInfo.Length > 1000); // Should have substantial content
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Fact]
    public async Task TimelineVisualization_ShouldIncludeMetadata()
    {
        // Arrange
        _replayEngine.StartRecording();
        _replayEngine.RecordFileOperation("Modify", @"C:\test.txt", "notepad.exe", 456);
        _replayEngine.StopRecording();

        // Act
        var timeline = await _replayEngine.GenerateTimelineAsync();

        // Assert
        var fileEntry = timeline.Entries.First(e => e.EventType == "File");
        Assert.NotNull(fileEntry.Metadata);
        Assert.True(fileEntry.Metadata.ContainsKey("Operation"));
        Assert.True(fileEntry.Metadata.ContainsKey("FilePath"));
        Assert.True(fileEntry.Metadata.ContainsKey("ProcessName"));
        Assert.Equal("Modify", fileEntry.Metadata["Operation"]);
    }

    public void Dispose()
    {
        _replayEngine?.Dispose();
    }
}
