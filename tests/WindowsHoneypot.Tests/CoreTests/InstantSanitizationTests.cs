using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Unit tests for InstantSanitization
/// Tests specific scenarios and edge cases for system sanitization
/// </summary>
public class InstantSanitizationTests
{
    private readonly Mock<ILogger<InstantSanitization>> _mockLogger;
    private readonly Mock<INetworkBlocker> _mockNetworkBlocker;
    private readonly Mock<IDeceptionEngine> _mockDeceptionEngine;
    private readonly IInstantSanitization _sanitization;

    public InstantSanitizationTests()
    {
        _mockLogger = new Mock<ILogger<InstantSanitization>>();
        _mockNetworkBlocker = new Mock<INetworkBlocker>();
        _mockDeceptionEngine = new Mock<IDeceptionEngine>();

        _sanitization = new InstantSanitization(
            _mockLogger.Object,
            _mockNetworkBlocker.Object,
            _mockDeceptionEngine.Object
        );
    }

    #region Constructor Tests

    [Fact]
    public void Constructor_WithNullLogger_ThrowsArgumentNullException()
    {
        // Act & Assert
        Action act = () => new InstantSanitization(
            null!,
            _mockNetworkBlocker.Object,
            _mockDeceptionEngine.Object
        );
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("logger");
    }

    [Fact]
    public void Constructor_WithNullNetworkBlocker_ThrowsArgumentNullException()
    {
        // Act & Assert
        Action act = () => new InstantSanitization(
            _mockLogger.Object,
            null!,
            _mockDeceptionEngine.Object
        );
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("networkBlocker");
    }

    [Fact]
    public void Constructor_WithNullDeceptionEngine_ThrowsArgumentNullException()
    {
        // Act & Assert
        Action act = () => new InstantSanitization(
            _mockLogger.Object,
            _mockNetworkBlocker.Object,
            null!
        );
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("deceptionEngine");
    }

    #endregion

    #region GetStatus Tests

    [Fact]
    public void GetStatus_InitialState_ReturnsIdle()
    {
        // Act
        var status = _sanitization.GetStatus();

        // Assert
        status.Should().Be(SanitizationStatus.Idle);
    }

    #endregion

    #region SanitizeAsync Tests

    [Fact]
    public async Task SanitizeAsync_WhenAlreadyRunning_ThrowsInvalidOperationException()
    {
        // Arrange
        _mockNetworkBlocker.Setup(x => x.RestoreFirewallRulesAsync())
            .Returns(async () =>
            {
                await Task.Delay(100); // Simulate long-running operation
            });

        _mockDeceptionEngine.Setup(x => x.RestoreOriginalSettingsAsync())
            .Returns(Task.CompletedTask);

        // Start first sanitization (don't await)
        var firstTask = _sanitization.SanitizeAsync();

        // Wait a bit to ensure it's running
        await Task.Delay(10);

        // Act & Assert - Try to start second sanitization
        Func<Task> act = async () => await _sanitization.SanitizeAsync();
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("Sanitization is already in progress");

        // Cleanup - wait for first task to complete
        try
        {
            await firstTask;
        }
        catch
        {
            // Ignore errors from first task
        }
    }

    [Fact]
    public async Task SanitizeAsync_WithSuccessfulOperations_ReturnsSuccessResult()
    {
        // Arrange
        _mockNetworkBlocker.Setup(x => x.GetBlockStatus())
            .Returns(NetworkBlockStatus.Inactive);
        _mockNetworkBlocker.Setup(x => x.RestoreFirewallRulesAsync())
            .Returns(Task.CompletedTask);
        _mockDeceptionEngine.Setup(x => x.RestoreOriginalSettingsAsync())
            .Returns(Task.CompletedTask);
        _mockDeceptionEngine.Setup(x => x.GetDeceptionStatus())
            .Returns(DeceptionStatus.Inactive);

        // Act
        var result = await _sanitization.SanitizeAsync();

        // Assert
        result.Should().NotBeNull();
        result.Success.Should().BeTrue();
        result.Operations.Should().HaveCount(6); // All 6 operations
        result.Operations.Should().OnlyContain(op => op.Success);
        result.VerificationReport.Should().NotBeNull();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public async Task SanitizeAsync_WithProgressReporter_ReportsProgress()
    {
        // Arrange
        _mockNetworkBlocker.Setup(x => x.GetBlockStatus())
            .Returns(NetworkBlockStatus.Inactive);
        _mockNetworkBlocker.Setup(x => x.RestoreFirewallRulesAsync())
            .Returns(Task.CompletedTask);
        _mockDeceptionEngine.Setup(x => x.RestoreOriginalSettingsAsync())
            .Returns(Task.CompletedTask);
        _mockDeceptionEngine.Setup(x => x.GetDeceptionStatus())
            .Returns(DeceptionStatus.Inactive);

        var progressReports = new List<SanitizationProgress>();
        var progress = new Progress<SanitizationProgress>(p => progressReports.Add(p));

        // Act
        var result = await _sanitization.SanitizeAsync(progress);

        // Assert
        result.Success.Should().BeTrue();
        progressReports.Should().NotBeEmpty();
        progressReports.Should().Contain(p => p.PercentComplete == 0);
        progressReports.Should().Contain(p => p.PercentComplete == 100);
        progressReports.Select(p => p.CurrentOperation).Should().Contain(SanitizationOperationType.NetworkReset);
        progressReports.Select(p => p.CurrentOperation).Should().Contain(SanitizationOperationType.FirewallRestoration);
    }

    [Fact]
    public async Task SanitizeAsync_WithCancellation_ThrowsOperationCanceledException()
    {
        // Arrange
        _mockNetworkBlocker.Setup(x => x.RestoreFirewallRulesAsync())
            .Returns(async () => await Task.Delay(1000));

        var cts = new CancellationTokenSource();
        cts.CancelAfter(50); // Cancel after 50ms

        // Act & Assert
        Func<Task> act = async () => await _sanitization.SanitizeAsync(cancellationToken: cts.Token);
        await act.Should().ThrowAsync<OperationCanceledException>();

        var status = _sanitization.GetStatus();
        status.Should().Be(SanitizationStatus.Failed);
    }

    [Fact]
    public async Task SanitizeAsync_WhenOperationFails_ReturnsFailureResult()
    {
        // Arrange
        _mockNetworkBlocker.Setup(x => x.RestoreFirewallRulesAsync())
            .ThrowsAsync(new InvalidOperationException("Firewall restoration failed"));

        // Act
        var result = await _sanitization.SanitizeAsync();

        // Assert
        result.Should().NotBeNull();
        result.Success.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().Contain(e => e.Contains("Firewall restoration failed"));
        
        var status = _sanitization.GetStatus();
        status.Should().Be(SanitizationStatus.Failed);
    }

    [Fact]
    public async Task SanitizeAsync_RecordsOperationDurations()
    {
        // Arrange
        _mockNetworkBlocker.Setup(x => x.GetBlockStatus())
            .Returns(NetworkBlockStatus.Inactive);
        _mockNetworkBlocker.Setup(x => x.RestoreFirewallRulesAsync())
            .Returns(async () => await Task.Delay(10));
        _mockDeceptionEngine.Setup(x => x.RestoreOriginalSettingsAsync())
            .Returns(async () => await Task.Delay(10));
        _mockDeceptionEngine.Setup(x => x.GetDeceptionStatus())
            .Returns(DeceptionStatus.Inactive);

        // Act
        var result = await _sanitization.SanitizeAsync();

        // Assert
        result.Success.Should().BeTrue();
        result.Duration.Should().BeGreaterThan(TimeSpan.Zero);
        result.Operations.Should().OnlyContain(op => op.Duration >= TimeSpan.Zero);
    }

    #endregion

    #region EmergencySanitizeAsync Tests

    [Fact]
    public async Task EmergencySanitizeAsync_WithSuccessfulOperations_ReturnsTrue()
    {
        // Arrange
        _mockNetworkBlocker.Setup(x => x.RestoreFirewallRulesAsync())
            .Returns(Task.CompletedTask);
        _mockDeceptionEngine.Setup(x => x.RestoreOriginalSettingsAsync())
            .Returns(Task.CompletedTask);

        // Act
        var result = await _sanitization.EmergencySanitizeAsync();

        // Assert
        result.Should().BeTrue();
        
        var status = _sanitization.GetStatus();
        status.Should().Be(SanitizationStatus.Completed);
    }

    [Fact]
    public async Task EmergencySanitizeAsync_WhenOperationFails_ReturnsFalse()
    {
        // Arrange
        _mockNetworkBlocker.Setup(x => x.RestoreFirewallRulesAsync())
            .ThrowsAsync(new InvalidOperationException("Emergency operation failed"));

        // Act
        var result = await _sanitization.EmergencySanitizeAsync();

        // Assert
        result.Should().BeFalse();
        
        var status = _sanitization.GetStatus();
        status.Should().Be(SanitizationStatus.Failed);
    }

    [Fact]
    public async Task EmergencySanitizeAsync_SetsEmergencyStatus()
    {
        // Arrange
        _mockNetworkBlocker.Setup(x => x.RestoreFirewallRulesAsync())
            .Returns(async () =>
            {
                // Check status during execution
                var status = _sanitization.GetStatus();
                status.Should().Be(SanitizationStatus.Emergency);
                await Task.CompletedTask;
            });
        _mockDeceptionEngine.Setup(x => x.RestoreOriginalSettingsAsync())
            .Returns(Task.CompletedTask);

        // Act
        await _sanitization.EmergencySanitizeAsync();

        // Assert - Status should be Completed after emergency sanitization
        var finalStatus = _sanitization.GetStatus();
        finalStatus.Should().Be(SanitizationStatus.Completed);
    }

    #endregion

    #region ValidateSystemStateAsync Tests

    [Fact]
    public async Task ValidateSystemStateAsync_ReturnsValidReport()
    {
        // Arrange
        _mockNetworkBlocker.Setup(x => x.GetBlockStatus())
            .Returns(NetworkBlockStatus.Inactive);
        _mockDeceptionEngine.Setup(x => x.GetDeceptionStatus())
            .Returns(DeceptionStatus.Inactive);

        // Act
        var report = await _sanitization.ValidateSystemStateAsync();

        // Assert
        report.Should().NotBeNull();
        report.GeneratedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
        report.SandboxStatus.Should().NotBeNull();
        report.FirewallStatus.Should().NotBeNull();
        report.RegistryStatus.Should().NotBeNull();
        report.FileSystemStatus.Should().NotBeNull();
        report.NetworkStatus.Should().NotBeNull();
    }

    [Fact]
    public async Task ValidateSystemStateAsync_WhenSystemHealthy_ReturnsHealthyStatus()
    {
        // Arrange
        _mockNetworkBlocker.Setup(x => x.GetBlockStatus())
            .Returns(NetworkBlockStatus.Inactive);
        _mockDeceptionEngine.Setup(x => x.GetDeceptionStatus())
            .Returns(DeceptionStatus.Inactive);

        // Act
        var report = await _sanitization.ValidateSystemStateAsync();

        // Assert
        report.IsHealthy.Should().BeTrue();
        report.Issues.Should().BeEmpty();
        report.Recommendations.Should().BeEmpty();
    }

    [Fact]
    public async Task ValidateSystemStateAsync_WhenRegistryNotReverted_ReturnsUnhealthyWithRecommendations()
    {
        // Arrange
        _mockNetworkBlocker.Setup(x => x.GetBlockStatus())
            .Returns(NetworkBlockStatus.Inactive);
        _mockDeceptionEngine.Setup(x => x.GetDeceptionStatus())
            .Returns(DeceptionStatus.Active); // Registry still modified

        // Act
        var report = await _sanitization.ValidateSystemStateAsync();

        // Assert
        report.IsHealthy.Should().BeFalse();
        report.Issues.Should().Contain(i => i.Contains("Registry modifications"));
        report.Recommendations.Should().NotBeEmpty();
    }

    [Fact]
    public async Task ValidateSystemStateAsync_ValidatesAllComponents()
    {
        // Arrange
        _mockNetworkBlocker.Setup(x => x.GetBlockStatus())
            .Returns(NetworkBlockStatus.Inactive);
        _mockDeceptionEngine.Setup(x => x.GetDeceptionStatus())
            .Returns(DeceptionStatus.Inactive);

        // Act
        var report = await _sanitization.ValidateSystemStateAsync();

        // Assert
        report.SandboxStatus.Should().NotBeNull();
        report.FirewallStatus.Should().NotBeNull();
        report.FirewallStatus.FirewallEnabled.Should().BeTrue();
        report.RegistryStatus.Should().NotBeNull();
        report.RegistryStatus.ModificationsReverted.Should().BeTrue();
        report.FileSystemStatus.Should().NotBeNull();
        report.NetworkStatus.Should().NotBeNull();
    }

    #endregion

    #region Edge Cases and Error Handling

    [Fact]
    public async Task SanitizeAsync_HandlesPartialFailureGracefully()
    {
        // Arrange - Make one operation fail but others succeed
        _mockNetworkBlocker.Setup(x => x.GetBlockStatus())
            .Returns(NetworkBlockStatus.Inactive);
        _mockNetworkBlocker.Setup(x => x.RestoreFirewallRulesAsync())
            .ThrowsAsync(new InvalidOperationException("Firewall error"));
        _mockDeceptionEngine.Setup(x => x.RestoreOriginalSettingsAsync())
            .Returns(Task.CompletedTask);

        // Act
        var result = await _sanitization.SanitizeAsync();

        // Assert
        result.Success.Should().BeFalse();
        result.Operations.Should().NotBeEmpty();
        result.Errors.Should().Contain(e => e.Contains("Firewall error"));
    }

    [Fact]
    public async Task SanitizeAsync_GeneratesVerificationReport()
    {
        // Arrange
        _mockNetworkBlocker.Setup(x => x.GetBlockStatus())
            .Returns(NetworkBlockStatus.Inactive);
        _mockNetworkBlocker.Setup(x => x.RestoreFirewallRulesAsync())
            .Returns(Task.CompletedTask);
        _mockDeceptionEngine.Setup(x => x.RestoreOriginalSettingsAsync())
            .Returns(Task.CompletedTask);
        _mockDeceptionEngine.Setup(x => x.GetDeceptionStatus())
            .Returns(DeceptionStatus.Inactive);

        // Act
        var result = await _sanitization.SanitizeAsync();

        // Assert
        result.VerificationReport.Should().NotBeNull();
        result.VerificationReport!.GeneratedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task SanitizeAsync_RecordsStartAndEndTimes()
    {
        // Arrange
        _mockNetworkBlocker.Setup(x => x.GetBlockStatus())
            .Returns(NetworkBlockStatus.Inactive);
        _mockNetworkBlocker.Setup(x => x.RestoreFirewallRulesAsync())
            .Returns(Task.CompletedTask);
        _mockDeceptionEngine.Setup(x => x.RestoreOriginalSettingsAsync())
            .Returns(Task.CompletedTask);
        _mockDeceptionEngine.Setup(x => x.GetDeceptionStatus())
            .Returns(DeceptionStatus.Inactive);

        var beforeStart = DateTime.UtcNow;

        // Act
        var result = await _sanitization.SanitizeAsync();

        var afterEnd = DateTime.UtcNow;

        // Assert
        result.StartTime.Should().BeOnOrAfter(beforeStart);
        result.EndTime.Should().BeOnOrBefore(afterEnd);
        result.EndTime.Should().BeOnOrAfter(result.StartTime);
        result.Duration.Should().Be(result.EndTime - result.StartTime);
    }

    #endregion
}
