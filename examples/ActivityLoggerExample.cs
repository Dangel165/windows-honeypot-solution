using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;

namespace WindowsHoneypot.Examples;

/// <summary>
/// Example demonstrating the use of ActivityLogger for comprehensive logging
/// </summary>
public class ActivityLoggerExample
{
    public static async Task RunExampleAsync()
    {
        // Set up logging
        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Debug);
        });

        var logger = loggerFactory.CreateLogger<ActivityLogger>();

        // Create activity logger with custom settings
        var logDirectory = Path.Combine(Path.GetTempPath(), "HoneypotLogs");
        using var activityLogger = new ActivityLogger(
            logger,
            logDirectory: logDirectory,
            maxLogFileSizeMB: 50,
            logRetentionDays: 30
        );

        Console.WriteLine($"Activity logger initialized. Log directory: {logDirectory}");

        // Log various attack events
        Console.WriteLine("\nLogging attack events...");

        // File access event
        activityLogger.LogActivity(new AttackEvent
        {
            EventType = AttackEventType.FileAccess,
            SourceProcess = "malware.exe",
            ProcessId = 1234,
            TargetFile = @"C:\Users\Admin\Documents\sensitive.docx",
            Description = "Unauthorized file access attempt",
            Severity = ThreatSeverity.Medium,
            Metadata = new Dictionary<string, object>
            {
                ["AccessType"] = "Read",
                ["FileSize"] = 1024000
            }
        });

        // Privilege escalation event
        activityLogger.LogActivity(new AttackEvent
        {
            EventType = AttackEventType.PrivilegeEscalation,
            SourceProcess = "exploit.exe",
            ProcessId = 5678,
            Description = "Attempted privilege escalation using UAC bypass",
            Severity = ThreatSeverity.High,
            Metadata = new Dictionary<string, object>
            {
                ["Method"] = "UAC Bypass",
                ["TargetPrivilege"] = "SeDebugPrivilege"
            }
        });

        // Sandbox escape event
        activityLogger.LogActivity(new AttackEvent
        {
            EventType = AttackEventType.SandboxEscape,
            SourceProcess = "breakout.exe",
            ProcessId = 9012,
            Description = "Sandbox escape attempt via named pipe",
            Severity = ThreatSeverity.Critical,
            Metadata = new Dictionary<string, object>
            {
                ["Method"] = "Named Pipe",
                ["TargetPipe"] = @"\\.\pipe\host_communication"
            }
        });

        // Wait for logs to flush
        Console.WriteLine("Waiting for logs to flush...");
        await Task.Delay(TimeSpan.FromSeconds(15));

        // Export logs to different formats
        Console.WriteLine("\nExporting logs...");

        var jsonPath = await activityLogger.ExportToJsonAsync();
        Console.WriteLine($"  JSON export: {jsonPath}");

        var xmlPath = await activityLogger.ExportToXmlAsync();
        Console.WriteLine($"  XML export: {xmlPath}");

        var csvPath = await activityLogger.ExportToCsvAsync();
        Console.WriteLine($"  CSV export: {csvPath}");

        // Generate forensic report
        Console.WriteLine("\nGenerating forensic report...");
        var reportPath = await activityLogger.GenerateForensicReportAsync();
        Console.WriteLine($"  Forensic report: {reportPath}");

        // Display report content
        if (File.Exists(reportPath))
        {
            Console.WriteLine("\n--- Forensic Report Preview ---");
            var reportLines = await File.ReadAllLinesAsync(reportPath);
            foreach (var line in reportLines.Take(30))
            {
                Console.WriteLine(line);
            }
            Console.WriteLine("...");
        }

        // Verify log integrity
        Console.WriteLine("\nVerifying log integrity...");
        var integrityResults = await activityLogger.VerifyLogIntegrityAsync();
        
        foreach (var result in integrityResults)
        {
            var status = result.Value ? "✓ VALID" : "✗ INVALID";
            Console.WriteLine($"  {status}: {Path.GetFileName(result.Key)}");
        }

        // Perform log rotation
        Console.WriteLine("\nPerforming log rotation...");
        await activityLogger.RotateLogsAsync();
        Console.WriteLine("Log rotation completed.");

        Console.WriteLine("\nActivity logger example completed successfully!");
    }
}
