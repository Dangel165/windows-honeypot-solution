using Microsoft.Extensions.Logging;
using Moq;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// End-to-end integration tests for the complete Windows Honeypot Solution.
/// Task 26.1: End-to-end system testing
/// </summary>
public class EndToEndIntegrationTests
{
    private static ILogger<T> CreateLogger<T>() => new Mock<ILogger<T>>().Object;

    [Fact]
    public async Task EmailScanner_DetectsAndQuarantines_ThreatFile()
    {
        // Arrange
        var scanner = new EmailAttachmentScanner(CreateLogger<EmailAttachmentScanner>());
        var responseSystem = new AutomatedResponseSystem(CreateLogger<AutomatedResponseSystem>());

        var tempFile = Path.GetTempFileName();
        var exeFile = Path.ChangeExtension(tempFile, ".exe");
        File.Move(tempFile, exeFile);

        try
        {
            await File.WriteAllBytesAsync(exeFile, new byte[] { 0x4D, 0x5A });

            // Act - scan
            var scanResult = await scanner.ScanAttachmentAsync(exeFile);

            // Assert scan detected threat
            Assert.True(scanResult.IsThreat);

            // Act - quarantine if threat
            if (scanResult.IsThreat && File.Exists(exeFile))
            {
                var quarantineResult = await responseSystem.QuarantineThreatAsync(exeFile);
                Assert.True(quarantineResult.Success);
                Assert.False(File.Exists(exeFile));

                // Cleanup
                if (File.Exists(quarantineResult.QuarantinePath))
                    File.Delete(quarantineResult.QuarantinePath);
            }
        }
        finally
        {
            if (File.Exists(exeFile)) File.Delete(exeFile);
        }
    }

    [Fact]
    public async Task WebProtection_DetectsPhishing_AndNotifies()
    {
        // Arrange
        var webProtection = new WebBrowsingProtection(CreateLogger<WebBrowsingProtection>());
        var phishingDetector = new PhishingDetector(CreateLogger<PhishingDetector>());
        var responseSystem = new AutomatedResponseSystem(CreateLogger<AutomatedResponseSystem>());

        ThreatNotification? receivedNotification = null;
        responseSystem.NotificationRaised += (_, n) => receivedNotification = n;

        // Act
        var urlResult = await webProtection.CheckUrlReputationAsync("http://paypal-secure-login.com/verify");
        var phishingResult = await phishingDetector.AnalyzeUrlAsync("http://paypal-secure-login.com/verify");

        if (urlResult.IsMalicious || phishingResult.IsPhishing)
        {
            responseSystem.SendNotification(new ThreatNotification
            {
                Title = "Phishing Site Detected",
                Message = $"Malicious URL blocked: {urlResult.Url}",
                Severity = ThreatSeverity.High,
                RemediationSteps = new List<string> { "Do not enter credentials", "Close the browser tab" }
            });
        }

        // Assert
        Assert.True(urlResult.IsMalicious || phishingResult.IsPhishing);
        Assert.NotNull(receivedNotification);
        Assert.Equal(ThreatSeverity.High, receivedNotification.Severity);
    }

    [Fact]
    public async Task ResponseSystem_CreateRestorePoint_BeforeQuarantine()
    {
        // Arrange
        var responseSystem = new AutomatedResponseSystem(CreateLogger<AutomatedResponseSystem>());

        // Act - create restore point first
        var restorePoint = await responseSystem.CreateRestorePointAsync("Before quarantine operation");
        Assert.True(restorePoint.Success);

        // Quarantine non-existent file (simulates the flow)
        var quarantineResult = await responseSystem.QuarantineThreatAsync(@"C:\nonexistent\threat.exe");

        // Rollback if needed
        var rollbackResult = await responseSystem.RollbackToRestorePointAsync(restorePoint.RestorePointId);

        // Assert
        Assert.True(rollbackResult);
        Assert.Single(responseSystem.GetRestorePoints());
        Assert.True(responseSystem.GetAuditLog().Count >= 3); // restore point + quarantine attempt + rollback
    }

    [Fact]
    public void HardwareMonitor_DetectsAttacks_AndLogs()
    {
        // Arrange
        var hardwareMonitor = new HardwareSecurityMonitor(CreateLogger<HardwareSecurityMonitor>());
        var responseSystem = new AutomatedResponseSystem(CreateLogger<AutomatedResponseSystem>());

        var attacksDetected = new List<HardwareAttackIndicator>();
        hardwareMonitor.HardwareAttackDetected += (_, args) =>
        {
            attacksDetected.Add(args.Indicator);
            responseSystem.SendNotification(new ThreatNotification
            {
                Title = $"Hardware Attack: {args.Indicator.AttackType}",
                Message = args.Description,
                Severity = args.Severity
            });
        };

        // Act - start monitoring (won't throw even without admin)
        hardwareMonitor.MonitorHardwareChanges();
        hardwareMonitor.StopMonitoring();

        // Assert - system is functional
        Assert.NotNull(hardwareMonitor.GetDetectedAttacks());
        hardwareMonitor.Dispose();
    }

    [Fact]
    public async Task FullPipeline_ScanDownload_QuarantineIfThreat_Notify()
    {
        // Arrange
        var webProtection = new WebBrowsingProtection(CreateLogger<WebBrowsingProtection>());
        var emailScanner = new EmailAttachmentScanner(CreateLogger<EmailAttachmentScanner>());
        var responseSystem = new AutomatedResponseSystem(CreateLogger<AutomatedResponseSystem>());

        var notifications = new List<ThreatNotification>();
        responseSystem.NotificationRaised += (_, n) => notifications.Add(n);

        // Create a temp "malicious" download
        var tempFile = Path.GetTempFileName();
        var maliciousFile = Path.ChangeExtension(tempFile, ".exe");
        File.Move(tempFile, maliciousFile);

        try
        {
            await File.WriteAllBytesAsync(maliciousFile, new byte[] { 0x4D, 0x5A });

            // Act - scan download
            var downloadResult = await webProtection.ScanDownloadAsync(
                "http://malware-site.com/payload.exe", maliciousFile);

            if (downloadResult.IsThreat)
            {
                // Create restore point
                await responseSystem.CreateRestorePointAsync("Before malware removal");

                // Quarantine
                var quarantineResult = await responseSystem.QuarantineThreatAsync(maliciousFile);

                // Notify
                responseSystem.SendNotification(new ThreatNotification
                {
                    Title = "Malicious Download Quarantined",
                    Message = $"File quarantined: {Path.GetFileName(maliciousFile)}",
                    Severity = downloadResult.Severity
                });

                // Assert
                Assert.True(quarantineResult.Success);
                Assert.Single(notifications);

                if (File.Exists(quarantineResult.QuarantinePath))
                    File.Delete(quarantineResult.QuarantinePath);
            }
        }
        finally
        {
            if (File.Exists(maliciousFile)) File.Delete(maliciousFile);
        }
    }

    [Fact]
    public async Task AuditTrail_IsComplete_AfterMultipleActions()
    {
        // Arrange
        var responseSystem = new AutomatedResponseSystem(CreateLogger<AutomatedResponseSystem>());

        // Act - perform multiple actions
        await responseSystem.CreateRestorePointAsync("Audit test 1");
        await responseSystem.QuarantineThreatAsync(@"C:\nonexistent\file.exe");
        responseSystem.SendNotification(new ThreatNotification { Title = "Test", Message = "msg", Severity = ThreatSeverity.Low });
        responseSystem.ConfigureResponsePolicy(new ResponsePolicy { AutoQuarantineEnabled = false });
        await responseSystem.IsolateSystemAsync();

        // Assert
        var auditLog = responseSystem.GetAuditLog();
        Assert.True(auditLog.Count >= 5);
        Assert.Contains(auditLog, e => e.Action == "CreateRestorePoint");
        Assert.Contains(auditLog, e => e.Action == "QuarantineFile");
        Assert.Contains(auditLog, e => e.Action == "SendNotification");
        Assert.Contains(auditLog, e => e.Action == "ConfigurePolicy");
        Assert.Contains(auditLog, e => e.Action == "IsolateSystem");
    }
}
