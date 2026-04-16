using Microsoft.Extensions.Logging;
using Moq;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Unit tests for HardwareSecurityMonitor
/// Task 19.3: Hardware-level attack detection
/// </summary>
public class HardwareSecurityMonitorTests : IDisposable
{
    private readonly Mock<ILogger<HardwareSecurityMonitor>> _mockLogger;
    private readonly HardwareSecurityMonitor _monitor;

    public HardwareSecurityMonitorTests()
    {
        _mockLogger = new Mock<ILogger<HardwareSecurityMonitor>>();
        _monitor = new HardwareSecurityMonitor(_mockLogger.Object);
    }

    public void Dispose()
    {
        _monitor.Dispose();
    }

    [Fact]
    public void Constructor_InitializesSuccessfully()
    {
        // Arrange & Act
        var monitor = new HardwareSecurityMonitor(_mockLogger.Object);

        // Assert
        Assert.NotNull(monitor);
        monitor.Dispose();
    }

    [Fact]
    public void GetDetectedAttacks_ReturnsEmptyListInitially()
    {
        // Act
        var attacks = _monitor.GetDetectedAttacks();

        // Assert
        Assert.NotNull(attacks);
        Assert.Empty(attacks);
    }

    [Fact]
    public async Task CheckFirmwareIntegrityAsync_ReturnsValidStatus()
    {
        // Act
        var status = await _monitor.CheckFirmwareIntegrityAsync();

        // Assert
        Assert.NotNull(status);
        Assert.False(string.IsNullOrEmpty(status.FirmwareType));
    }

    [Fact]
    public async Task CheckFirmwareIntegrityAsync_FirmwareTypeIsBiosOrUefi()
    {
        // Act
        var status = await _monitor.CheckFirmwareIntegrityAsync();

        // Assert
        Assert.True(
            status.FirmwareType == "BIOS" || status.FirmwareType == "UEFI",
            $"Expected BIOS or UEFI, got: {status.FirmwareType}");
    }

    [Fact]
    public async Task CheckFirmwareIntegrityAsync_MultipleCalls_ReturnConsistentResults()
    {
        // Act
        var status1 = await _monitor.CheckFirmwareIntegrityAsync();
        var status2 = await _monitor.CheckFirmwareIntegrityAsync();

        // Assert – firmware type and hash should be stable across calls
        Assert.Equal(status1.FirmwareType, status2.FirmwareType);
        Assert.Equal(status1.ActualHash, status2.ActualHash);
        // On second call the baseline is already set, so hashes should match
        Assert.True(status2.HashMatches);
    }

    [Fact]
    public async Task ValidateSecureBootAsync_ReturnsBoolWithoutThrowing()
    {
        // Act
        var exception = await Record.ExceptionAsync(() => _monitor.ValidateSecureBootAsync());

        // Assert
        Assert.Null(exception);
    }

    [Fact]
    public async Task DetectBootkitAsync_ReturnsBoolWithoutThrowing()
    {
        // Act
        var exception = await Record.ExceptionAsync(() => _monitor.DetectBootkitAsync());

        // Assert
        Assert.Null(exception);
    }

    [Fact]
    public async Task DetectRootkitAsync_ReturnsBoolWithoutThrowing()
    {
        // Act
        var exception = await Record.ExceptionAsync(() => _monitor.DetectRootkitAsync());

        // Assert
        Assert.Null(exception);
    }

    [Fact]
    public async Task DetectDMAAttackAsync_ReturnsBoolWithoutThrowing()
    {
        // Act
        var exception = await Record.ExceptionAsync(() => _monitor.DetectDMAAttackAsync());

        // Assert
        Assert.Null(exception);
    }

    [Fact]
    public async Task DetectHardwareKeyloggerAsync_ReturnsBoolWithoutThrowing()
    {
        // Act
        var exception = await Record.ExceptionAsync(() => _monitor.DetectHardwareKeyloggerAsync());

        // Assert
        Assert.Null(exception);
    }

    [Fact]
    public void MonitorHardwareChanges_StartsWithoutThrowing()
    {
        // Act
        var exception = Record.Exception(() => _monitor.MonitorHardwareChanges());

        // Assert
        Assert.Null(exception);
    }

    [Fact]
    public void StopMonitoring_StopsWithoutThrowing()
    {
        // Arrange
        _monitor.MonitorHardwareChanges();

        // Act
        var exception = Record.Exception(() => _monitor.StopMonitoring());

        // Assert
        Assert.Null(exception);
    }

    [Fact]
    public void StopMonitoring_WithoutStarting_DoesNotThrow()
    {
        // Act
        var exception = Record.Exception(() => _monitor.StopMonitoring());

        // Assert
        Assert.Null(exception);
    }

    [Fact]
    public void HardwareAttackDetected_EventCanBeSubscribed()
    {
        // Arrange
        bool subscribed = false;

        // Act
        _monitor.HardwareAttackDetected += (_, _) => subscribed = true;

        // Assert – subscription itself should not throw
        Assert.False(subscribed); // Event not yet raised
    }

    [Fact]
    public void GetDetectedAttacks_ReturnsSnapshot_NotLiveReference()
    {
        // Act
        var list1 = _monitor.GetDetectedAttacks();
        var list2 = _monitor.GetDetectedAttacks();

        // Assert – each call returns a new list instance
        Assert.NotSame(list1, list2);
    }

    [Fact]
    public async Task CheckFirmwareIntegrityAsync_HasActualHash()
    {
        // Act
        var status = await _monitor.CheckFirmwareIntegrityAsync();

        // Assert
        Assert.False(string.IsNullOrEmpty(status.ActualHash));
    }

    [Fact]
    public async Task CheckFirmwareIntegrityAsync_HasExpectedHash()
    {
        // Act – first call establishes baseline
        await _monitor.CheckFirmwareIntegrityAsync();
        // Second call should have both hashes set
        var status = await _monitor.CheckFirmwareIntegrityAsync();

        // Assert
        Assert.False(string.IsNullOrEmpty(status.ExpectedHash));
    }
}
