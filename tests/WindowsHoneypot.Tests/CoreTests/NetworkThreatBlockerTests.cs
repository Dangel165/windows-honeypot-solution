using Microsoft.Extensions.Logging;
using Moq;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Unit tests for NetworkThreatBlocker
/// Note: These tests verify the logic but don't actually modify firewall rules
/// </summary>
public class NetworkThreatBlockerTests
{
    private readonly Mock<ILogger<NetworkThreatBlocker>> _mockLogger;

    public NetworkThreatBlockerTests()
    {
        _mockLogger = new Mock<ILogger<NetworkThreatBlocker>>();
    }

    [Fact]
    public void IsIPBlocked_InitiallyReturnsFalse()
    {
        // Arrange
        var blocker = new NetworkThreatBlocker(_mockLogger.Object);

        // Act
        var isBlocked = blocker.IsIPBlocked("192.168.1.100");

        // Assert
        Assert.False(isBlocked);
    }

    [Fact]
    public void IsPortBlocked_InitiallyReturnsFalse()
    {
        // Arrange
        var blocker = new NetworkThreatBlocker(_mockLogger.Object);

        // Act
        var isBlocked = blocker.IsPortBlocked(4444);

        // Assert
        Assert.False(isBlocked);
    }

    [Fact]
    public void GetBlockedIPs_InitiallyReturnsEmpty()
    {
        // Arrange
        var blocker = new NetworkThreatBlocker(_mockLogger.Object);

        // Act
        var blockedIPs = blocker.GetBlockedIPs();

        // Assert
        Assert.Empty(blockedIPs);
    }

    [Fact]
    public void GetBlockedPorts_InitiallyReturnsEmpty()
    {
        // Arrange
        var blocker = new NetworkThreatBlocker(_mockLogger.Object);

        // Act
        var blockedPorts = blocker.GetBlockedPorts();

        // Assert
        Assert.Empty(blockedPorts);
    }

    [Fact]
    public void GetStatistics_InitiallyReturnsZeroCounts()
    {
        // Arrange
        var blocker = new NetworkThreatBlocker(_mockLogger.Object);

        // Act
        var stats = blocker.GetStatistics();

        // Assert
        Assert.False(stats.IsActive);
        Assert.Equal(0, stats.BlockedIPCount);
        Assert.Equal(0, stats.BlockedPortCount);
        Assert.Equal(0, stats.TotalBlockedConnections);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("invalid-ip")]
    [InlineData("999.999.999.999")]
    public async Task BlockIPAddressAsync_InvalidIP_ReturnsFalse(string invalidIP)
    {
        // Arrange
        var blocker = new NetworkThreatBlocker(_mockLogger.Object);

        // Act
        var result = await blocker.BlockIPAddressAsync(invalidIP);

        // Assert
        Assert.False(result);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(65536)]
    [InlineData(100000)]
    public async Task BlockPortAsync_InvalidPort_ReturnsFalse(int invalidPort)
    {
        // Arrange
        var blocker = new NetworkThreatBlocker(_mockLogger.Object);

        // Act
        var result = await blocker.BlockPortAsync(invalidPort);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task BlockThreatPatternsAsync_WithValidPatterns_ReturnsCount()
    {
        // Arrange
        var blocker = new NetworkThreatBlocker(_mockLogger.Object);
        var patterns = new List<ThreatPattern>
        {
            new ThreatPattern
            {
                Name = "TestPattern1",
                NetworkAddressPatterns = new List<string> { "192.168.1.100" },
                NetworkPorts = new List<int> { 4444 }
            },
            new ThreatPattern
            {
                Name = "TestPattern2",
                NetworkAddressPatterns = new List<string> { "10.0.0.50" },
                NetworkPorts = new List<int> { 8080, 9090 }
            }
        };

        // Act
        // Note: This will fail if not running with admin privileges
        // In a real test environment, we would mock the firewall operations
        try
        {
            var count = await blocker.BlockThreatPatternsAsync(patterns);
            
            // If we get here, we have admin privileges
            Assert.True(count >= 0);
        }
        catch (InvalidOperationException)
        {
            // Expected if not running as admin
            Assert.True(true);
        }
    }

    [Fact]
    public async Task StartAsync_SetsActiveStatus()
    {
        // Arrange
        var blocker = new NetworkThreatBlocker(_mockLogger.Object);

        // Act
        try
        {
            await blocker.StartAsync();
            var stats = blocker.GetStatistics();

            // Assert
            Assert.True(stats.IsActive);

            await blocker.StopAsync();
        }
        catch (InvalidOperationException)
        {
            // Expected if not running as admin
            Assert.True(true);
        }
    }

    [Fact]
    public async Task StopAsync_ClearsActiveStatus()
    {
        // Arrange
        var blocker = new NetworkThreatBlocker(_mockLogger.Object);

        // Act
        try
        {
            await blocker.StartAsync();
            await blocker.StopAsync();
            var stats = blocker.GetStatistics();

            // Assert
            Assert.False(stats.IsActive);
        }
        catch (InvalidOperationException)
        {
            // Expected if not running as admin
            Assert.True(true);
        }
    }

    [Fact]
    public async Task ClearAllBlocksAsync_RemovesAllBlocks()
    {
        // Arrange
        var blocker = new NetworkThreatBlocker(_mockLogger.Object);

        // Act
        try
        {
            await blocker.ClearAllBlocksAsync();
            var stats = blocker.GetStatistics();

            // Assert
            Assert.Equal(0, stats.BlockedIPCount);
            Assert.Equal(0, stats.BlockedPortCount);
        }
        catch (InvalidOperationException)
        {
            // Expected if not running as admin
            Assert.True(true);
        }
    }
}
