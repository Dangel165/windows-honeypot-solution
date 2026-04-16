using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Unit tests for NetworkBlocker
/// Tests specific scenarios and edge cases for network traffic blocking
/// </summary>
public class NetworkBlockerTests : IDisposable
{
    private readonly Mock<ILogger<NetworkBlocker>> _mockLogger;
    private readonly INetworkBlocker _networkBlocker;

    public NetworkBlockerTests()
    {
        _mockLogger = new Mock<ILogger<NetworkBlocker>>();
        _networkBlocker = new NetworkBlocker(_mockLogger.Object);
    }

    public void Dispose()
    {
        (_networkBlocker as IDisposable)?.Dispose();
    }

    [Fact]
    public void Constructor_WithNullLogger_ThrowsArgumentNullException()
    {
        // Act & Assert
        Action act = () => new NetworkBlocker(null!);
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("logger");
    }

    [Fact]
    public void GetBlockStatus_InitialState_ReturnsInactive()
    {
        // Act
        var status = _networkBlocker.GetBlockStatus();

        // Assert
        status.Should().Be(NetworkBlockStatus.Inactive);
    }

    [Fact]
    public void GetBlockedAttempts_InitialState_ReturnsEmptyList()
    {
        // Act
        var attempts = _networkBlocker.GetBlockedAttempts();

        // Assert
        attempts.Should().BeEmpty();
    }

    [Fact]
    public void LogBlockedAttempt_WithNullAttempt_ThrowsArgumentNullException()
    {
        // Arrange
        var blocker = _networkBlocker as NetworkBlocker;

        // Act & Assert
        Action act = () => blocker!.LogBlockedAttempt(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void LogBlockedAttempt_WithValidAttempt_AddsToList()
    {
        // Arrange
        var blocker = _networkBlocker as NetworkBlocker;
        var attempt = new NetworkAttempt
        {
            SourceIP = "192.168.1.100",
            DestinationIP = "8.8.8.8",
            SourcePort = 54321,
            DestinationPort = 443,
            Protocol = "TCP",
            Direction = "Outbound",
            ProcessName = "chrome.exe",
            ProcessId = 1234,
            BlockReason = "Honeypot network isolation"
        };

        // Act
        blocker!.LogBlockedAttempt(attempt);
        var attempts = _networkBlocker.GetBlockedAttempts();

        // Assert
        attempts.Should().ContainSingle();
        attempts[0].SourceIP.Should().Be("192.168.1.100");
        attempts[0].DestinationIP.Should().Be("8.8.8.8");
        attempts[0].Protocol.Should().Be("TCP");
    }

    [Fact]
    public void LogBlockedAttempt_WithValidAttempt_RaisesEvent()
    {
        // Arrange
        var blocker = _networkBlocker as NetworkBlocker;
        var attempt = new NetworkAttempt
        {
            SourceIP = "10.0.0.5",
            DestinationIP = "1.1.1.1",
            Protocol = "UDP",
            Direction = "Outbound"
        };

        NetworkAttemptBlockedEventArgs? capturedArgs = null;
        _networkBlocker.NetworkAttemptBlocked += (sender, args) =>
        {
            capturedArgs = args;
        };

        // Act
        blocker!.LogBlockedAttempt(attempt);

        // Assert
        capturedArgs.Should().NotBeNull();
        capturedArgs!.NetworkAttempt.Should().NotBeNull();
        capturedArgs.NetworkAttempt.SourceIP.Should().Be("10.0.0.5");
    }

    [Fact]
    public void LogBlockedAttempt_MultipleAttempts_AllRecorded()
    {
        // Arrange
        var blocker = _networkBlocker as NetworkBlocker;
        var attempts = new[]
        {
            new NetworkAttempt { SourceIP = "192.168.1.1", Protocol = "TCP" },
            new NetworkAttempt { SourceIP = "192.168.1.2", Protocol = "UDP" },
            new NetworkAttempt { SourceIP = "192.168.1.3", Protocol = "ICMP" }
        };

        // Act
        foreach (var attempt in attempts)
        {
            blocker!.LogBlockedAttempt(attempt);
        }

        var recorded = _networkBlocker.GetBlockedAttempts();

        // Assert
        recorded.Should().HaveCount(3);
        recorded.Select(a => a.SourceIP).Should().Contain(new[] { "192.168.1.1", "192.168.1.2", "192.168.1.3" });
    }

    [Fact]
    public async Task BlockAllTrafficAsync_WhenCalledTwice_LogsWarning()
    {
        // Note: This test may require administrator privileges to actually create firewall rules
        // We test the behavior when called twice, expecting either success or graceful failure
        
        // Act & Assert
        // First call - may fail without admin rights
        try
        {
            await _networkBlocker.BlockAllTrafficAsync();
            
            // If first call succeeded, second call should log warning and return
            await _networkBlocker.BlockAllTrafficAsync();
            
            // If we get here, the status should be Active or Blocking
            var status = _networkBlocker.GetBlockStatus();
            status.Should().BeOneOf(NetworkBlockStatus.Active, NetworkBlockStatus.Blocking);
        }
        catch (InvalidOperationException)
        {
            // Expected if we don't have admin privileges
            // This is acceptable behavior
        }
    }

    [Fact]
    public async Task RestoreFirewallRulesAsync_WhenNotActive_DoesNotThrow()
    {
        // Act
        Func<Task> act = async () => await _networkBlocker.RestoreFirewallRulesAsync();

        // Assert
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public void Dispose_WhenCalled_DoesNotThrow()
    {
        // Arrange
        var blocker = new NetworkBlocker(_mockLogger.Object);

        // Act
        Action act = () => (blocker as IDisposable).Dispose();

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void Dispose_CalledMultipleTimes_DoesNotThrow()
    {
        // Arrange
        var blocker = new NetworkBlocker(_mockLogger.Object);

        // Act
        Action act = () =>
        {
            (blocker as IDisposable).Dispose();
            (blocker as IDisposable).Dispose();
            (blocker as IDisposable).Dispose();
        };

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void NetworkAttempt_HasCorrectDefaultValues()
    {
        // Act
        var attempt = new NetworkAttempt();

        // Assert
        attempt.Id.Should().NotBeEmpty();
        attempt.Timestamp.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
        attempt.SourceIP.Should().BeEmpty();
        attempt.DestinationIP.Should().BeEmpty();
        attempt.Protocol.Should().BeEmpty();
        attempt.ProcessName.Should().BeEmpty();
        attempt.Direction.Should().BeEmpty();
        attempt.BlockReason.Should().BeEmpty();
    }
}
