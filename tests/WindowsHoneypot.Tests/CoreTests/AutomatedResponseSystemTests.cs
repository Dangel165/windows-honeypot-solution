using Microsoft.Extensions.Logging;
using Moq;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

public class AutomatedResponseSystemTests
{
    private readonly AutomatedResponseSystem _sut;

    public AutomatedResponseSystemTests()
    {
        _sut = new AutomatedResponseSystem(new Mock<ILogger<AutomatedResponseSystem>>().Object);
    }

    [Fact] public void Constructor_InitializesSuccessfully() => Assert.NotNull(_sut);
    [Fact] public void GetNotifications_ReturnsEmptyListInitially() => Assert.Empty(_sut.GetNotifications());
    [Fact] public void GetAuditLog_ReturnsEmptyListInitially() => Assert.Empty(_sut.GetAuditLog());
    [Fact] public void GetRestorePoints_ReturnsEmptyListInitially() => Assert.Empty(_sut.GetRestorePoints());

    [Fact]
    public async Task QuarantineThreatAsync_NonExistentFile_ReturnsFailure()
    {
        var result = await _sut.QuarantineThreatAsync(@"C:\nonexistent\file.exe");
        Assert.False(result.Success);
        Assert.NotEmpty(result.ErrorMessage);
    }

    [Fact]
    public async Task QuarantineThreatAsync_ExistingFile_ReturnsSuccessAndMovesFile()
    {
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, "test content");
        try
        {
            var result = await _sut.QuarantineThreatAsync(tempFile);
            Assert.True(result.Success);
            Assert.False(File.Exists(tempFile));
            Assert.True(File.Exists(result.QuarantinePath));
            if (File.Exists(result.QuarantinePath)) File.Delete(result.QuarantinePath);
        }
        finally { if (File.Exists(tempFile)) File.Delete(tempFile); }
    }

    [Fact]
    public async Task TerminateProcessAsync_InvalidProcessId_ReturnsFalse()
        => Assert.False(await _sut.TerminateProcessAsync(int.MaxValue));

    [Fact]
    public async Task CreateRestorePointAsync_ReturnsSuccessAndAddsToList()
    {
        var result = await _sut.CreateRestorePointAsync("Test restore point");
        Assert.True(result.Success);
        Assert.Single(_sut.GetRestorePoints());
    }

    [Fact]
    public async Task RollbackToRestorePointAsync_ValidId_ReturnsTrue()
    {
        var created = await _sut.CreateRestorePointAsync("Rollback test");
        Assert.True(await _sut.RollbackToRestorePointAsync(created.RestorePointId));
    }

    [Fact]
    public async Task RollbackToRestorePointAsync_InvalidId_ReturnsFalse()
        => Assert.False(await _sut.RollbackToRestorePointAsync("nonexistent-id"));

    [Fact]
    public void SendNotification_AddsToNotificationsList()
    {
        _sut.SendNotification(new ThreatNotification { Title = "Test", Message = "msg", Severity = ThreatSeverity.High });
        Assert.Single(_sut.GetNotifications());
    }

    [Fact]
    public void SendNotification_RaisesNotificationRaisedEvent()
    {
        ThreatNotification? received = null;
        _sut.NotificationRaised += (_, n) => received = n;
        _sut.SendNotification(new ThreatNotification { Title = "Event Test", Message = "Testing", Severity = ThreatSeverity.Medium });
        Assert.NotNull(received);
        Assert.Equal("Event Test", received.Title);
    }

    [Fact]
    public void ConfigureResponsePolicy_UpdatesPolicy()
    {
        _sut.ConfigureResponsePolicy(new ResponsePolicy { AutoQuarantineEnabled = false, MinimumSeverityForAutoResponse = ThreatSeverity.Critical });
        var policy = _sut.GetResponsePolicy();
        Assert.False(policy.AutoQuarantineEnabled);
        Assert.Equal(ThreatSeverity.Critical, policy.MinimumSeverityForAutoResponse);
    }

    [Fact]
    public void GetResponsePolicy_ReturnsDefaultPolicy()
    {
        var policy = _sut.GetResponsePolicy();
        Assert.True(policy.AutoQuarantineEnabled);
        Assert.Equal(ThreatSeverity.High, policy.MinimumSeverityForAutoResponse);
    }

    [Fact]
    public async Task IsolateSystemAsync_ReturnsTrueWithoutThrowing()
        => Assert.True(await _sut.IsolateSystemAsync());

    [Fact]
    public async Task AuditLog_GrowsAfterActions()
    {
        var initial = _sut.GetAuditLog().Count;
        await _sut.QuarantineThreatAsync(@"C:\nonexistent\file.exe");
        await _sut.CreateRestorePointAsync("Audit test");
        _sut.SendNotification(new ThreatNotification { Title = "Audit", Message = "Test", Severity = ThreatSeverity.Low });
        Assert.True(_sut.GetAuditLog().Count > initial);
    }
}
