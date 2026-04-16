using Microsoft.Extensions.Logging;
using Moq;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Unit tests for EmailAttachmentScanner (Task 20.1)
/// </summary>
public class EmailAttachmentScannerTests
{
    private readonly Mock<ILogger<EmailAttachmentScanner>> _mockLogger;
    private readonly IEmailAttachmentScanner _scanner;

    public EmailAttachmentScannerTests()
    {
        _mockLogger = new Mock<ILogger<EmailAttachmentScanner>>();
        _scanner = new EmailAttachmentScanner(_mockLogger.Object);
    }

    [Fact]
    public void Constructor_InitializesSuccessfully()
    {
        var scanner = new EmailAttachmentScanner(_mockLogger.Object);
        Assert.NotNull(scanner);
    }

    [Fact]
    public void GetScanHistory_ReturnsEmptyListInitially()
    {
        var history = _scanner.GetScanHistory();
        Assert.NotNull(history);
        Assert.Empty(history);
    }

    [Fact]
    public async Task ClearScanHistory_ClearsHistory()
    {
        // Add an entry by scanning a real temp file
        var tempFile = Path.GetTempFileName();
        try
        {
            await _scanner.ScanAttachmentAsync(tempFile);
            Assert.NotEmpty(_scanner.GetScanHistory());

            _scanner.ClearScanHistory();
            Assert.Empty(_scanner.GetScanHistory());
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task ScanAttachmentAsync_NonExistentFile_ReturnsFalseIsThreat()
    {
        var result = await _scanner.ScanAttachmentAsync(@"C:\nonexistent\file.txt");

        Assert.False(result.IsThreat);
        Assert.False(result.IsSafe);
        Assert.NotEmpty(result.DetectedThreats);
    }

    [Fact]
    public async Task ScanAttachmentAsync_CleanTxtFile_ReturnsSafe()
    {
        var tempFile = Path.GetTempFileName();
        // Rename to .txt
        var txtFile = Path.ChangeExtension(tempFile, ".txt");
        File.Move(tempFile, txtFile);
        try
        {
            await File.WriteAllTextAsync(txtFile, "Hello, this is a clean text file.");
            var result = await _scanner.ScanAttachmentAsync(txtFile);

            Assert.True(result.IsSafe);
            Assert.False(result.IsThreat);
        }
        finally
        {
            if (File.Exists(txtFile)) File.Delete(txtFile);
        }
    }

    [Fact]
    public async Task ScanAttachmentAsync_ExeFile_ReturnsThreatWithHighOrCriticalSeverity()
    {
        var tempFile = Path.GetTempFileName();
        var exeFile = Path.ChangeExtension(tempFile, ".exe");
        File.Move(tempFile, exeFile);
        try
        {
            await File.WriteAllBytesAsync(exeFile, new byte[] { 0x4D, 0x5A, 0x00 }); // MZ header
            var result = await _scanner.ScanAttachmentAsync(exeFile);

            Assert.True(result.IsThreat);
            Assert.True(result.Severity >= ThreatSeverity.High);
        }
        finally
        {
            if (File.Exists(exeFile)) File.Delete(exeFile);
        }
    }

    [Fact]
    public async Task ScanAttachmentAsync_DoubleExtension_ReturnsThreat()
    {
        var dir = Path.GetTempPath();
        var doubleExtFile = Path.Combine(dir, $"test_{Guid.NewGuid()}.txt.exe");
        try
        {
            await File.WriteAllBytesAsync(doubleExtFile, new byte[] { 0x4D, 0x5A });
            var result = await _scanner.ScanAttachmentAsync(doubleExtFile);

            Assert.True(result.IsThreat);
        }
        finally
        {
            if (File.Exists(doubleExtFile)) File.Delete(doubleExtFile);
        }
    }

    [Fact]
    public async Task ScanAttachmentAsync_AddsResultToScanHistory()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await _scanner.ScanAttachmentAsync(tempFile);
            var history = _scanner.GetScanHistory();
            Assert.Single(history);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task CreateSafePreviewAsync_TxtFile_ReturnsSuccessWithTextType()
    {
        var tempFile = Path.GetTempFileName();
        var txtFile = Path.ChangeExtension(tempFile, ".txt");
        File.Move(tempFile, txtFile);
        try
        {
            await File.WriteAllTextAsync(txtFile, "Preview content");
            var result = await _scanner.CreateSafePreviewAsync(txtFile);

            Assert.True(result.Success);
            Assert.Equal("text", result.PreviewType);
        }
        finally
        {
            if (File.Exists(txtFile)) File.Delete(txtFile);
        }
    }

    [Fact]
    public async Task CreateSafePreviewAsync_ExeFile_ReturnsFalse()
    {
        var tempFile = Path.GetTempFileName();
        var exeFile = Path.ChangeExtension(tempFile, ".exe");
        File.Move(tempFile, exeFile);
        try
        {
            await File.WriteAllBytesAsync(exeFile, new byte[] { 0x4D, 0x5A });
            var result = await _scanner.CreateSafePreviewAsync(exeFile);

            Assert.False(result.Success);
            Assert.NotEmpty(result.ErrorMessage);
        }
        finally
        {
            if (File.Exists(exeFile)) File.Delete(exeFile);
        }
    }

    [Fact]
    public async Task CreateSafePreviewAsync_JpgFile_ReturnsImageType()
    {
        var tempFile = Path.GetTempFileName();
        var jpgFile = Path.ChangeExtension(tempFile, ".jpg");
        File.Move(tempFile, jpgFile);
        try
        {
            await File.WriteAllBytesAsync(jpgFile, new byte[] { 0xFF, 0xD8, 0xFF }); // JPEG header
            var result = await _scanner.CreateSafePreviewAsync(jpgFile);

            Assert.True(result.Success);
            Assert.Equal("image", result.PreviewType);
        }
        finally
        {
            if (File.Exists(jpgFile)) File.Delete(jpgFile);
        }
    }

    [Fact]
    public void IsOutlookIntegrationAvailable_ReturnsBoolWithoutThrowing()
    {
        var ex = Record.Exception(() => _scanner.IsOutlookIntegrationAvailable());
        Assert.Null(ex);
    }

    [Fact]
    public void ThreatDetected_EventCanBeSubscribed()
    {
        EmailScanEventArgs? receivedArgs = null;
        _scanner.ThreatDetected += (_, args) => receivedArgs = args;

        // Just verify subscription doesn't throw
        Assert.Null(receivedArgs); // No event fired yet
    }

    [Fact]
    public async Task ScanAttachmentAsync_ExistingFile_HasNonEmptyFileHash()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, "some content");
            var result = await _scanner.ScanAttachmentAsync(tempFile);

            Assert.NotEmpty(result.FileHash);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task ScanOutlookAttachmentsAsync_ReturnsListWithoutThrowing()
    {
        var ex = await Record.ExceptionAsync(() => _scanner.ScanOutlookAttachmentsAsync());
        Assert.Null(ex);
    }
}
