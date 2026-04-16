using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Unit tests for BehavioralAnalysisEngine
/// Tests Task 19.1: Time-delayed malware detection system
/// </summary>
public class BehavioralAnalysisEngineTests
{
    private readonly BehavioralAnalysisEngine _engine;

    public BehavioralAnalysisEngineTests()
    {
        _engine = new BehavioralAnalysisEngine();
    }

    [Fact]
    public async Task AnalyzeScheduledTasksAsync_ReturnsIndicators()
    {
        // Act
        var indicators = await _engine.AnalyzeScheduledTasksAsync();

        // Assert
        Assert.NotNull(indicators);
        // Note: May be empty if no suspicious tasks exist
    }

    [Fact]
    public async Task AnalyzeRegistryPersistenceAsync_ReturnsIndicators()
    {
        // Act
        var indicators = await _engine.AnalyzeRegistryPersistenceAsync();

        // Assert
        Assert.NotNull(indicators);
        // Note: May be empty if no suspicious registry entries exist
    }

    [Fact]
    public async Task DetectTimeDelayedThreatAsync_WithNonExistentFile_ReturnsFalse()
    {
        // Arrange
        var nonExistentFile = "C:\\NonExistent\\File.exe";

        // Act
        var result = await _engine.DetectTimeDelayedThreatAsync(nonExistentFile);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task DetectVMAwareMalwareAsync_WithNonExistentFile_ReturnsFalse()
    {
        // Arrange
        var nonExistentFile = "C:\\NonExistent\\File.exe";

        // Act
        var result = await _engine.DetectVMAwareMalwareAsync(nonExistentFile);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task DetectHardwareAttackAsync_ReturnsBoolean()
    {
        // Act
        var result = await _engine.DetectHardwareAttackAsync();

        // Assert
        // Should return false in normal conditions
        Assert.False(result);
    }

    [Fact]
    public void GetSuspiciousActivities_InitiallyEmpty()
    {
        // Act
        var activities = _engine.GetSuspiciousActivities();

        // Assert
        Assert.NotNull(activities);
        Assert.Empty(activities);
    }

    [Fact]
    public void UpdateBehavioralModel_AddsTrainingData()
    {
        // Arrange
        var trainingData = new ThreatData
        {
            ThreatId = "test-threat-1",
            AttackerIP = "192.168.1.100",
            Severity = ThreatSeverity.High
        };

        // Act
        _engine.UpdateBehavioralModel(trainingData);

        // Assert - No exception thrown
        Assert.True(true);
    }

    [Fact]
    public async Task AnalyzeFileBehaviorAsync_WithShortDuration_CompletesSuccessfully()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, "Test content");
        var monitoringPeriod = TimeSpan.FromMilliseconds(100);

        try
        {
            // Act
            var result = await _engine.AnalyzeFileBehaviorAsync(tempFile, monitoringPeriod);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(tempFile, result.TargetPath);
            Assert.True(result.AnalysisDuration >= monitoringPeriod);
        }
        finally
        {
            // Cleanup
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task DetectTimeDelayedThreatAsync_WithFileContainingDelayPatterns_DetectsThreat()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, "Thread.Sleep(5000); // Delay execution");

        try
        {
            // Act
            var result = await _engine.DetectTimeDelayedThreatAsync(tempFile);

            // Assert
            Assert.True(result);
            
            // Verify indicator was added
            var activities = _engine.GetSuspiciousActivities();
            Assert.NotEmpty(activities);
            Assert.Contains(activities, a => a.Type == BehavioralIndicatorType.TimeDelayedExecution);
        }
        finally
        {
            // Cleanup
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task DetectVMAwareMalwareAsync_WithFileContainingVMStrings_DetectsThreat()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, "Checking for VMware and VirtualBox");

        try
        {
            // Act
            var result = await _engine.DetectVMAwareMalwareAsync(tempFile);

            // Assert
            Assert.True(result);
            
            // Verify indicator was added
            var activities = _engine.GetSuspiciousActivities();
            Assert.NotEmpty(activities);
            Assert.Contains(activities, a => a.Type == BehavioralIndicatorType.VMDetectionAttempt);
        }
        finally
        {
            // Cleanup
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task SuspiciousBehaviorDetected_EventRaisedWhenThreatDetected()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, "Task.Delay(10000);");
        var eventRaised = false;
        BehavioralIndicatorEventArgs? eventArgs = null;

        _engine.SuspiciousBehaviorDetected += (sender, args) =>
        {
            eventRaised = true;
            eventArgs = args;
        };

        try
        {
            // Act
            await _engine.DetectTimeDelayedThreatAsync(tempFile);

            // Assert
            Assert.True(eventRaised);
            Assert.NotNull(eventArgs);
            Assert.NotNull(eventArgs.Indicator);
            Assert.Equal(BehavioralIndicatorType.TimeDelayedExecution, eventArgs.Indicator.Type);
        }
        finally
        {
            // Cleanup
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task AnalyzeProcessAsync_WithInvalidProcessId_ReturnsNonThreatAssessment()
    {
        // Arrange
        var invalidProcessId = 999999;

        // Act
        var assessment = await _engine.AnalyzeProcessAsync(invalidProcessId);

        // Assert
        Assert.NotNull(assessment);
        Assert.False(assessment.IsThreat);
    }

    [Fact]
    public async Task DetectSandboxEvasionAsync_WithInvalidProcessId_ReturnsFalse()
    {
        // Arrange
        var invalidProcessId = 999999;

        // Act
        var result = await _engine.DetectSandboxEvasionAsync(invalidProcessId);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task AnalyzeFileBehaviorAsync_CalculatesSuspicionScore()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, "Normal file content");
        var monitoringPeriod = TimeSpan.FromMilliseconds(50);

        try
        {
            // Act
            var result = await _engine.AnalyzeFileBehaviorAsync(tempFile, monitoringPeriod);

            // Assert
            Assert.NotNull(result);
            Assert.True(result.SuspicionScore >= 0.0 && result.SuspicionScore <= 1.0);
            Assert.NotNull(result.Recommendation);
        }
        finally
        {
            // Cleanup
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    #region Task 19.2: VM-Aware Malware Detection Tests

    [Fact]
    public async Task DetectVMAwareMalwareAsync_WithCPUIDInstructions_DetectsThreat()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, "__cpuid(cpuInfo, 0x40000000); // Check hypervisor");

        try
        {
            // Act
            var result = await _engine.DetectVMAwareMalwareAsync(tempFile);

            // Assert
            Assert.True(result);
            
            var activities = _engine.GetSuspiciousActivities();
            var vmIndicator = activities.FirstOrDefault(a => a.Type == BehavioralIndicatorType.VMDetectionAttempt);
            Assert.NotNull(vmIndicator);
            Assert.True(vmIndicator.UsesVMDetection);
            Assert.Contains("CPUID", vmIndicator.Description, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task DetectVMAwareMalwareAsync_WithTimingBasedDetection_DetectsThreat()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, 
            "RDTSC before; QueryPerformanceCounter(&start); // Timing-based VM detection");

        try
        {
            // Act
            var result = await _engine.DetectVMAwareMalwareAsync(tempFile);

            // Assert
            Assert.True(result);
            
            var activities = _engine.GetSuspiciousActivities();
            var vmIndicator = activities.FirstOrDefault(a => 
                a.Type == BehavioralIndicatorType.VMDetectionAttempt &&
                a.FilePath == tempFile);
            Assert.NotNull(vmIndicator);
            Assert.Contains("timing", vmIndicator.Description, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task DetectVMAwareMalwareAsync_WithHardwareFingerprinting_DetectsThreat()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, 
            "GetSystemInfo(&si); SMBIOS data; UUID check; SerialNumber verification;");

        try
        {
            // Act
            var result = await _engine.DetectVMAwareMalwareAsync(tempFile);

            // Assert
            Assert.True(result);
            
            var activities = _engine.GetSuspiciousActivities();
            var vmIndicator = activities.LastOrDefault(a => 
                a.Type == BehavioralIndicatorType.VMDetectionAttempt);
            Assert.NotNull(vmIndicator);
            Assert.Contains("fingerprint", vmIndicator.Description, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task DetectVMAwareMalwareAsync_WithRegistryVMDetection_DetectsThreat()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, 
            @"RegOpenKey(HKEY_LOCAL_MACHINE, ""HARDWARE\DESCRIPTION\System\BIOS"", &hKey); " +
            @"RegQueryValue(hKey, ""SystemManufacturer"", buffer, &size);");

        try
        {
            // Act
            var result = await _engine.DetectVMAwareMalwareAsync(tempFile);

            // Assert
            Assert.True(result);
            
            var activities = _engine.GetSuspiciousActivities();
            var vmIndicator = activities.LastOrDefault(a => 
                a.Type == BehavioralIndicatorType.VMDetectionAttempt);
            Assert.NotNull(vmIndicator);
            Assert.Contains("registry", vmIndicator.Description, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task DetectVMAwareMalwareAsync_WithWMIVMDetection_DetectsThreat()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, 
            "ManagementObjectSearcher searcher = new ManagementObjectSearcher(" +
            "\"SELECT * FROM Win32_ComputerSystem\"); " +
            "Win32_BIOS bios; Win32_BaseBoard board;");

        try
        {
            // Act
            var result = await _engine.DetectVMAwareMalwareAsync(tempFile);

            // Assert
            Assert.True(result);
            
            var activities = _engine.GetSuspiciousActivities();
            var vmIndicator = activities.LastOrDefault(a => 
                a.Type == BehavioralIndicatorType.VMDetectionAttempt);
            Assert.NotNull(vmIndicator);
            Assert.Contains("WMI", vmIndicator.Description, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task DetectVMAwareMalwareAsync_WithMACAddressDetection_DetectsThreat()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, 
            "GetAdaptersInfo(&pAdapterInfo, &ulOutBufLen); " +
            "if (MAC starts with 00:05:69 || 00:0C:29) { /* VMware detected */ }");

        try
        {
            // Act
            var result = await _engine.DetectVMAwareMalwareAsync(tempFile);

            // Assert
            Assert.True(result);
            
            var activities = _engine.GetSuspiciousActivities();
            var vmIndicator = activities.LastOrDefault(a => 
                a.Type == BehavioralIndicatorType.VMDetectionAttempt);
            Assert.NotNull(vmIndicator);
            Assert.Contains("MAC", vmIndicator.Description, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task DetectVMAwareMalwareAsync_WithProcessServiceDetection_DetectsThreat()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, 
            "Process.GetProcesses().Any(p => p.ProcessName == \"vmtoolsd\" || " +
            "p.ProcessName == \"VBoxService\");");

        try
        {
            // Act
            var result = await _engine.DetectVMAwareMalwareAsync(tempFile);

            // Assert
            Assert.True(result);
            
            var activities = _engine.GetSuspiciousActivities();
            var vmIndicator = activities.LastOrDefault(a => 
                a.Type == BehavioralIndicatorType.VMDetectionAttempt);
            Assert.NotNull(vmIndicator);
            Assert.Contains("process", vmIndicator.Description, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task DetectVMAwareMalwareAsync_WithMultipleDetectionTechniques_DetectsAllTechniques()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, 
            "// Multi-technique VM detection\n" +
            "__cpuid(cpuInfo, 0x40000000);\n" +
            "RDTSC timing check;\n" +
            "GetSystemInfo(&si); SMBIOS check;\n" +
            @"RegOpenKey(HKEY_LOCAL_MACHINE, ""SOFTWARE\VMware"", &hKey);" + "\n" +
            "ManagementObjectSearcher(\"SELECT * FROM Win32_ComputerSystem\");\n" +
            "Check MAC address 00:0C:29;\n" +
            "Process.GetProcesses() check for vmtoolsd;");

        try
        {
            // Act
            var result = await _engine.DetectVMAwareMalwareAsync(tempFile);

            // Assert
            Assert.True(result);
            
            var activities = _engine.GetSuspiciousActivities();
            var vmIndicator = activities.LastOrDefault(a => 
                a.Type == BehavioralIndicatorType.VMDetectionAttempt);
            Assert.NotNull(vmIndicator);
            Assert.NotEmpty(vmIndicator.ObservedActions);
            Assert.True(vmIndicator.ObservedActions.Count >= 5, 
                $"Expected at least 5 detection techniques, found {vmIndicator.ObservedActions.Count}");
            Assert.Contains(vmIndicator.BehaviorMetadata, kvp => 
                kvp.Key == "VMDetectionTechniques");
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task DetectVMAwareMalwareAsync_WithCleanFile_DoesNotDetectThreat()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, 
            "// Normal application code\n" +
            "Console.WriteLine(\"Hello World\");\n" +
            "int result = Calculate(5, 10);\n" +
            "return result;");

        try
        {
            // Act
            var result = await _engine.DetectVMAwareMalwareAsync(tempFile);

            // Assert
            Assert.False(result);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task DetectVMAwareMalwareAsync_StoresMetadataCorrectly()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, 
            "VMware detection; VirtualBox check; CPUID instruction;");

        try
        {
            // Act
            var result = await _engine.DetectVMAwareMalwareAsync(tempFile);

            // Assert
            Assert.True(result);
            
            var activities = _engine.GetSuspiciousActivities();
            var vmIndicator = activities.LastOrDefault(a => 
                a.Type == BehavioralIndicatorType.VMDetectionAttempt);
            
            Assert.NotNull(vmIndicator);
            Assert.Equal(tempFile, vmIndicator.FilePath);
            Assert.True(vmIndicator.UsesVMDetection);
            Assert.Equal(ThreatSeverity.High, vmIndicator.Severity);
            Assert.Contains(vmIndicator.BehaviorMetadata, kvp => 
                kvp.Key == "DetectionMethods");
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    #endregion
}
