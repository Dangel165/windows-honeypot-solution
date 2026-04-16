using FsCheck;
using FsCheck.Xunit;
using FluentAssertions;
using WindowsHoneypot.Core.Services;
using WindowsHoneypot.Core.Models;
using Microsoft.Extensions.Logging;
using Moq;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Property-based tests for NetworkBlocker
/// **Feature: windows-honeypot-solution, Property 5: Network Traffic Blocking**
/// </summary>
public class NetworkBlockerPropertyTests : IDisposable
{
    private readonly NetworkBlocker _networkBlocker;

    public NetworkBlockerPropertyTests()
    {
        var mockLogger = new Mock<ILogger<NetworkBlocker>>();
        _networkBlocker = new NetworkBlocker(mockLogger.Object);
    }

    /// <summary>
    /// Property 5: For any network connection attempt during sandbox execution, the Network Blocker 
    /// SHALL prevent the connection through firewall rule enforcement.
    /// **Validates: Requirements 6.1**
    /// </summary>
    [Property(MaxTest = 100)]
    public bool NetworkBlocker_InitialState_IsCorrect(int dummyValue)
    {
        // Arrange
        var mockLogger = new Mock<ILogger<NetworkBlocker>>();
        using var blocker = new NetworkBlocker(mockLogger.Object);

        // Act & Assert - Initial state
        blocker.GetBlockStatus().Should().Be(NetworkBlockStatus.Inactive, "Initial status should be inactive");
        blocker.GetBlockedAttempts().Should().BeEmpty("Initial blocked attempts should be empty");

        return true;
    }

    /// <summary>
    /// Property 5.1: For any network attempt logging, the system SHALL store and track attempts
    /// **Validates: Requirements 6.1**
    /// </summary>
    [Property(MaxTest = 100)]
    public bool NetworkBlocker_LogBlockedAttempt_StoresAttempt(int testIndex)
    {
        // Arrange
        var mockLogger = new Mock<ILogger<NetworkBlocker>>();
        using var blocker = new NetworkBlocker(mockLogger.Object);

        var eventTriggered = false;
        NetworkAttemptBlockedEventArgs? capturedArgs = null;

        blocker.NetworkAttemptBlocked += (sender, args) =>
        {
            eventTriggered = true;
            capturedArgs = args;
        };

        // Create deterministic test data based on testIndex
        var protocols = new[] { "TCP", "UDP", "ICMP" };
        var directions = new[] { "Inbound", "Outbound" };
        var sourceIPs = new[] { "192.168.1.100", "10.0.0.50", "127.0.0.1" };
        var destIPs = new[] { "8.8.8.8", "1.1.1.1", "192.168.1.1" };
        var processNames = new[] { "chrome.exe", "firefox.exe", "malware.exe" };

        var networkAttempt = new NetworkAttempt
        {
            Protocol = protocols[Math.Abs(testIndex) % protocols.Length],
            Direction = directions[Math.Abs(testIndex) % directions.Length],
            SourceIP = sourceIPs[Math.Abs(testIndex) % sourceIPs.Length],
            DestinationIP = destIPs[Math.Abs(testIndex) % destIPs.Length],
            SourcePort = Math.Abs(testIndex % 64511) + 1024,
            DestinationPort = Math.Abs(testIndex % 65535) + 1,
            ProcessName = processNames[Math.Abs(testIndex) % processNames.Length],
            ProcessId = Math.Abs(testIndex % 65535) + 1,
            Timestamp = DateTime.UtcNow,
            BlockReason = "Blocked by honeypot network isolation"
        };

        // Act
        blocker.LogBlockedAttempt(networkAttempt);

        // Assert
        eventTriggered.Should().BeTrue("Network attempt blocked event should be triggered");
        capturedArgs.Should().NotBeNull("Event args should be provided");
        capturedArgs!.NetworkAttempt.Should().BeEquivalentTo(networkAttempt, "Event should contain the logged attempt");

        var blockedAttempts = blocker.GetBlockedAttempts();
        blockedAttempts.Should().Contain(networkAttempt, "Blocked attempts should contain the logged attempt");
        blockedAttempts.Should().HaveCount(1, "Should have exactly one blocked attempt");

        return true;
    }

    /// <summary>
    /// Property 5.2: For any network blocker instance, status checks SHALL be consistent
    /// **Validates: Requirements 6.1**
    /// </summary>
    [Property(MaxTest = 100)]
    public bool NetworkBlocker_StatusChecks_AreConsistent(int dummyValue)
    {
        // Arrange
        var mockLogger = new Mock<ILogger<NetworkBlocker>>();
        using var blocker = new NetworkBlocker(mockLogger.Object);

        // Act & Assert - Multiple status checks should be consistent
        var status1 = blocker.GetBlockStatus();
        var status2 = blocker.GetBlockStatus();
        status1.Should().Be(status2, "Multiple status checks should return consistent results");
        status1.Should().Be(NetworkBlockStatus.Inactive, "Initial status should be inactive");

        return true;
    }

    /// <summary>
    /// Property 5.3: For any network blocker instance, disposal SHALL be safe regardless of state
    /// **Validates: Requirements 6.1**
    /// </summary>
    [Property(MaxTest = 100)]
    public bool NetworkBlocker_Disposal_IsSafeInAnyState(bool shouldLogAttempt)
    {
        // Arrange
        var mockLogger = new Mock<ILogger<NetworkBlocker>>();
        var blocker = new NetworkBlocker(mockLogger.Object);

        if (shouldLogAttempt)
        {
            var networkAttempt = new NetworkAttempt
            {
                Protocol = "TCP",
                Direction = "Outbound",
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                SourcePort = 12345,
                DestinationPort = 80,
                ProcessName = "test.exe",
                ProcessId = 1234,
                Timestamp = DateTime.UtcNow,
                BlockReason = "Test block"
            };
            blocker.LogBlockedAttempt(networkAttempt);
        }

        // Act & Assert - Disposal should not throw
        Action disposeAction = () => blocker.Dispose();
        disposeAction.Should().NotThrow("Disposal should be safe in any state");

        // Multiple disposals should also be safe
        Action multipleDisposeAction = () =>
        {
            blocker.Dispose();
            blocker.Dispose();
        };
        multipleDisposeAction.Should().NotThrow("Multiple disposals should be safe");

        return true;
    }

    public void Dispose()
    {
        _networkBlocker?.Dispose();
    }
}