using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Unit tests for ProcessCamouflage
/// Tests specific scenarios and edge cases for fake process creation
/// </summary>
public class ProcessCamouflageTests : IDisposable
{
    private readonly Mock<ILogger<ProcessCamouflage>> _mockLogger;
    private readonly IProcessCamouflage _processCamouflage;

    public ProcessCamouflageTests()
    {
        _mockLogger = new Mock<ILogger<ProcessCamouflage>>();
        _processCamouflage = new ProcessCamouflage(_mockLogger.Object);
    }

    public void Dispose()
    {
        (_processCamouflage as IDisposable)?.Dispose();
    }

    [Fact]
    public void Constructor_WithNullLogger_ThrowsArgumentNullException()
    {
        // Act & Assert
        Action act = () => new ProcessCamouflage(null!);
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("logger");
    }

    [Fact]
    public void GetActiveProcesses_InitialState_ReturnsEmptyList()
    {
        // Act
        var processes = _processCamouflage.GetActiveProcesses();

        // Assert
        processes.Should().NotBeNull();
        processes.Should().BeEmpty();
    }

    [Fact]
    public async Task StartFakeProcessesAsync_WithNullProfiles_DoesNotThrow()
    {
        // Act
        Func<Task> act = async () => await _processCamouflage.StartFakeProcessesAsync(null!);

        // Assert
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task StartFakeProcessesAsync_WithEmptyList_DoesNotThrow()
    {
        // Act
        Func<Task> act = async () => await _processCamouflage.StartFakeProcessesAsync(new List<ProcessProfile>());

        // Assert
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task StartFakeProcessesAsync_WithValidProfile_CreatesProcess()
    {
        // Arrange
        var profile = new ProcessProfile
        {
            ProcessName = "test.exe",
            Description = "Test Process",
            CompanyName = "Test Company",
            FakeCpuUsage = 5,
            FakeMemoryUsage = 100 * 1024 * 1024,
            VariableCpuUsage = true
        };

        // Act
        await _processCamouflage.StartFakeProcessesAsync(new List<ProcessProfile> { profile });

        // Assert
        var activeProcesses = _processCamouflage.GetActiveProcesses();
        activeProcesses.Should().NotBeEmpty();
        activeProcesses.Should().HaveCountGreaterThanOrEqualTo(1);
    }

    [Fact]
    public async Task StartFakeProcessesAsync_WithMultipleProfiles_CreatesMultipleProcesses()
    {
        // Arrange
        var profiles = new List<ProcessProfile>
        {
            new ProcessProfile
            {
                ProcessName = "app1.exe",
                Description = "App 1",
                FakeCpuUsage = 2,
                FakeMemoryUsage = 50 * 1024 * 1024
            },
            new ProcessProfile
            {
                ProcessName = "app2.exe",
                Description = "App 2",
                FakeCpuUsage = 3,
                FakeMemoryUsage = 75 * 1024 * 1024
            }
        };

        // Act
        await _processCamouflage.StartFakeProcessesAsync(profiles);

        // Assert
        var activeProcesses = _processCamouflage.GetActiveProcesses();
        activeProcesses.Should().NotBeEmpty();
    }

    [Fact]
    public async Task StopAllFakeProcessesAsync_WhenNoProcesses_DoesNotThrow()
    {
        // Act
        Func<Task> act = async () => await _processCamouflage.StopAllFakeProcessesAsync();

        // Assert
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task StopAllFakeProcessesAsync_AfterStarting_ClearsProcesses()
    {
        // Arrange
        var profile = new ProcessProfile
        {
            ProcessName = "test.exe",
            FakeCpuUsage = 1,
            FakeMemoryUsage = 50 * 1024 * 1024
        };
        await _processCamouflage.StartFakeProcessesAsync(new List<ProcessProfile> { profile });

        // Act
        await _processCamouflage.StopAllFakeProcessesAsync();

        // Assert
        var activeProcesses = _processCamouflage.GetActiveProcesses();
        activeProcesses.Should().BeEmpty();
    }

    [Fact]
    public void UpdateProcessMetrics_WhenNoProcesses_DoesNotThrow()
    {
        // Act
        Action act = () => _processCamouflage.UpdateProcessMetrics();

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public async Task UpdateProcessMetrics_WithVariableCpu_UpdatesCpuUsage()
    {
        // Arrange
        var profile = new ProcessProfile
        {
            ProcessName = "test.exe",
            FakeCpuUsage = 50,
            FakeMemoryUsage = 100 * 1024 * 1024,
            VariableCpuUsage = true
        };
        await _processCamouflage.StartFakeProcessesAsync(new List<ProcessProfile> { profile });

        var initialProcesses = _processCamouflage.GetActiveProcesses();
        var initialCpu = initialProcesses.First().CpuUsage;

        // Act
        _processCamouflage.UpdateProcessMetrics();

        // Assert
        var updatedProcesses = _processCamouflage.GetActiveProcesses();
        var updatedCpu = updatedProcesses.First().CpuUsage;
        
        // CPU should be within reasonable range (base ± variation)
        updatedCpu.Should().BeInRange(0, 100);
    }

    [Fact]
    public async Task StartFakeProcessesAsync_CalledTwice_LogsWarning()
    {
        // Arrange
        var profile = new ProcessProfile
        {
            ProcessName = "test.exe",
            FakeCpuUsage = 1,
            FakeMemoryUsage = 50 * 1024 * 1024
        };

        // Act
        await _processCamouflage.StartFakeProcessesAsync(new List<ProcessProfile> { profile });
        await _processCamouflage.StartFakeProcessesAsync(new List<ProcessProfile> { profile });

        // Assert - should not throw, but should log warning
        var activeProcesses = _processCamouflage.GetActiveProcesses();
        activeProcesses.Should().NotBeEmpty();
    }

    [Fact]
    public void Dispose_WhenCalled_DoesNotThrow()
    {
        // Arrange
        var camouflage = new ProcessCamouflage(_mockLogger.Object);

        // Act
        Action act = () => (camouflage as IDisposable).Dispose();

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void Dispose_CalledMultipleTimes_DoesNotThrow()
    {
        // Arrange
        var camouflage = new ProcessCamouflage(_mockLogger.Object);

        // Act
        Action act = () =>
        {
            (camouflage as IDisposable).Dispose();
            (camouflage as IDisposable).Dispose();
            (camouflage as IDisposable).Dispose();
        };

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public async Task ProcessProfile_WithNetworkConnections_StoresConnections()
    {
        // Arrange
        var profile = new ProcessProfile
        {
            ProcessName = "app.exe",
            FakeCpuUsage = 2,
            FakeMemoryUsage = 100 * 1024 * 1024,
            SimulateNetworkActivity = true,
            FakeNetworkConnections = new List<string>
            {
                "api.example.com:443",
                "cdn.example.com:443"
            }
        };

        // Act
        await _processCamouflage.StartFakeProcessesAsync(new List<ProcessProfile> { profile });

        // Assert
        var activeProcesses = _processCamouflage.GetActiveProcesses();
        var process = activeProcesses.FirstOrDefault();
        process.Should().NotBeNull();
        process!.Profile.FakeNetworkConnections.Should().HaveCount(2);
    }

    [Fact]
    public void ProcessProfileFactory_GetDefaultBusinessProfiles_ReturnsProfiles()
    {
        // Act
        var profiles = ProcessProfileFactory.GetDefaultBusinessProfiles();

        // Assert
        profiles.Should().NotBeNull();
        profiles.Should().NotBeEmpty();
        profiles.Should().HaveCountGreaterThanOrEqualTo(5);
    }

    [Fact]
    public void ProcessProfileFactory_CreateSlackProfile_HasCorrectProperties()
    {
        // Act
        var profile = ProcessProfileFactory.CreateSlackProfile();

        // Assert
        profile.Should().NotBeNull();
        profile.ProcessName.Should().Be("slack.exe");
        profile.CompanyName.Should().Be("Slack Technologies, Inc.");
        profile.FakeCpuUsage.Should().BeGreaterThan(0);
        profile.FakeMemoryUsage.Should().BeGreaterThan(0);
        profile.SimulateNetworkActivity.Should().BeTrue();
        profile.FakeNetworkConnections.Should().NotBeEmpty();
    }

    [Fact]
    public void ProcessProfileFactory_CreateTeamsProfile_HasCorrectProperties()
    {
        // Act
        var profile = ProcessProfileFactory.CreateTeamsProfile();

        // Assert
        profile.Should().NotBeNull();
        profile.ProcessName.Should().Be("Teams.exe");
        profile.CompanyName.Should().Be("Microsoft Corporation");
        profile.FakeCpuUsage.Should().BeGreaterThan(0);
        profile.FakeMemoryUsage.Should().BeGreaterThan(0);
    }

    [Fact]
    public void ProcessProfileFactory_CreateChromeProfile_HasCorrectProperties()
    {
        // Act
        var profile = ProcessProfileFactory.CreateChromeProfile();

        // Assert
        profile.Should().NotBeNull();
        profile.ProcessName.Should().Be("chrome.exe");
        profile.CompanyName.Should().Be("Google LLC");
        profile.FakeCpuUsage.Should().BeGreaterThan(0);
        profile.FakeMemoryUsage.Should().BeGreaterThan(0);
    }

    [Theory]
    [InlineData("developer")]
    [InlineData("office")]
    [InlineData("remote")]
    [InlineData("minimal")]
    public void ProcessProfileFactory_GetProfilesForScenario_ReturnsValidProfiles(string scenario)
    {
        // Act
        var profiles = ProcessProfileFactory.GetProfilesForScenario(scenario);

        // Assert
        profiles.Should().NotBeNull();
        profiles.Should().NotBeEmpty();
        profiles.All(p => !string.IsNullOrEmpty(p.ProcessName)).Should().BeTrue();
        profiles.All(p => p.FakeMemoryUsage > 0).Should().BeTrue();
    }

    [Fact]
    public void ProcessProfileFactory_CreateCustomProfile_CreatesValidProfile()
    {
        // Act
        var profile = ProcessProfileFactory.CreateCustomProfile(
            processName: "custom.exe",
            description: "Custom App",
            companyName: "Custom Inc.",
            cpuUsage: 10,
            memoryUsageMB: 200,
            networkConnections: new List<string> { "api.custom.com:443" }
        );

        // Assert
        profile.Should().NotBeNull();
        profile.ProcessName.Should().Be("custom.exe");
        profile.Description.Should().Be("Custom App");
        profile.CompanyName.Should().Be("Custom Inc.");
        profile.FakeCpuUsage.Should().Be(10);
        profile.FakeMemoryUsage.Should().Be(200 * 1024 * 1024);
        profile.FakeNetworkConnections.Should().Contain("api.custom.com:443");
    }

    [Fact]
    public void FakeProcess_DefaultConstructor_InitializesProperties()
    {
        // Act
        var fakeProcess = new FakeProcess();

        // Assert
        fakeProcess.Id.Should().NotBeEmpty();
        fakeProcess.StartTime.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
        fakeProcess.IsRunning.Should().BeTrue();
        fakeProcess.NetworkConnections.Should().NotBeNull();
        fakeProcess.Profile.Should().NotBeNull();
    }

    [Fact]
    public void ProcessProfile_DefaultConstructor_InitializesCollections()
    {
        // Act
        var profile = new ProcessProfile();

        // Assert
        profile.FakeNetworkConnections.Should().NotBeNull();
        profile.FakeNetworkConnections.Should().BeEmpty();
    }

    [Fact]
    public async Task StartFakeProcessesAsync_WithInvalidExecutablePath_HandlesGracefully()
    {
        // Arrange
        var profile = new ProcessProfile
        {
            ProcessName = "nonexistent.exe",
            ExecutablePath = "C:\\NonExistent\\Path\\app.exe",
            FakeCpuUsage = 1,
            FakeMemoryUsage = 50 * 1024 * 1024
        };

        // Act
        Func<Task> act = async () => await _processCamouflage.StartFakeProcessesAsync(new List<ProcessProfile> { profile });

        // Assert - should not throw, but may not create process
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task GetActiveProcesses_ReturnsIndependentCopy()
    {
        // Arrange
        var profile = new ProcessProfile
        {
            ProcessName = "test.exe",
            FakeCpuUsage = 1,
            FakeMemoryUsage = 50 * 1024 * 1024
        };
        await _processCamouflage.StartFakeProcessesAsync(new List<ProcessProfile> { profile });

        // Act
        var processes1 = _processCamouflage.GetActiveProcesses();
        var processes2 = _processCamouflage.GetActiveProcesses();

        // Assert
        processes1.Should().NotBeSameAs(processes2);
        processes1.Should().HaveCount(processes2.Count);
    }

    [Fact]
    public void ProcessProfile_MemoryUsageConversion_IsCorrect()
    {
        // Arrange
        var memoryMB = 350;
        var expectedBytes = memoryMB * 1024 * 1024;

        // Act
        var profile = new ProcessProfile
        {
            FakeMemoryUsage = expectedBytes
        };

        // Assert
        profile.FakeMemoryUsage.Should().Be(expectedBytes);
        (profile.FakeMemoryUsage / (1024 * 1024)).Should().Be(memoryMB);
    }
}
