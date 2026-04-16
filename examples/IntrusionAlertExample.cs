using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;

namespace WindowsHoneypot.Examples;

/// <summary>
/// Example demonstrating the Intrusion Alert System integration with File Monitor
/// </summary>
public class IntrusionAlertExample
{
    public static async Task RunExample()
    {
        // Setup dependency injection
        var services = new ServiceCollection();
        services.AddHoneypotCore();
        var serviceProvider = services.BuildServiceProvider();

        // Get services
        var fileMonitor = serviceProvider.GetRequiredService<IFileMonitor>();
        var alertSystem = serviceProvider.GetRequiredService<IIntrusionAlertSystem>();
        var logger = serviceProvider.GetRequiredService<ILogger<IntrusionAlertExample>>();

        logger.LogInformation("=== Intrusion Alert System Example ===");

        // Subscribe to intrusion events
        alertSystem.IntrusionDetected += (sender, e) =>
        {
            Console.WriteLine("\n🚨 INTRUSION ALERT 🚨");
            Console.WriteLine(e.AlertMessage);
            Console.WriteLine($"Severity: {e.Severity}");
            Console.WriteLine(new string('-', 50));
        };

        alertSystem.AttackPatternDetected += (sender, e) =>
        {
            Console.WriteLine("\n⚠️ ATTACK PATTERN DETECTED ⚠️");
            Console.WriteLine(e.PatternDescription);
            Console.WriteLine($"Total Attacks: {e.Analysis.TotalAttacks}");
            Console.WriteLine($"Overall Severity: {e.Analysis.OverallSeverity}");
            Console.WriteLine(new string('=', 50));
        };

        // Create a test directory
        var testDir = Path.Combine(Path.GetTempPath(), "HoneypotTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDir);
        logger.LogInformation("Created test directory: {TestDir}", testDir);

        try
        {
            // Start the alert system
            alertSystem.Start();
            logger.LogInformation("Alert system started");

            // Register file monitor with alert system
            alertSystem.RegisterFileMonitor(fileMonitor);
            logger.LogInformation("File monitor registered with alert system");

            // Start monitoring
            fileMonitor.StartMonitoring(testDir);
            logger.LogInformation("File monitoring started on: {TestDir}", testDir);

            Console.WriteLine("\n📁 Monitoring directory for intrusions...");
            Console.WriteLine($"Directory: {testDir}");
            Console.WriteLine("\nSimulating attacker activities...\n");

            // Simulate various attack scenarios
            await SimulateAttacks(testDir);

            // Wait a bit for events to process
            await Task.Delay(1000);

            // Display attack statistics
            DisplayStatistics(alertSystem, logger);

            // Analyze attack patterns
            var analysis = alertSystem.AnalyzeAttackPatterns();
            DisplayAnalysis(analysis, logger);

            Console.WriteLine("\n✅ Example completed. Press any key to cleanup...");
            Console.ReadKey();
        }
        finally
        {
            // Cleanup
            fileMonitor.StopMonitoring();
            alertSystem.Stop();
            
            if (Directory.Exists(testDir))
            {
                Directory.Delete(testDir, true);
                logger.LogInformation("Cleaned up test directory");
            }

            (alertSystem as IDisposable)?.Dispose();
            (fileMonitor as IDisposable)?.Dispose();
        }
    }

    private static async Task SimulateAttacks(string testDir)
    {
        // Simulate file access
        var file1 = Path.Combine(testDir, "document.txt");
        await File.WriteAllTextAsync(file1, "Sensitive data");
        Console.WriteLine("✓ Created file: document.txt");
        await Task.Delay(500);

        // Simulate file modification
        await File.AppendAllTextAsync(file1, "\nModified by attacker");
        Console.WriteLine("✓ Modified file: document.txt");
        await Task.Delay(500);

        // Simulate multiple file creations (rapid attack)
        for (int i = 1; i <= 3; i++)
        {
            var file = Path.Combine(testDir, $"malware_{i}.exe");
            await File.WriteAllTextAsync(file, "Malicious content");
            Console.WriteLine($"✓ Created file: malware_{i}.exe");
            await Task.Delay(200);
        }

        // Simulate file rename
        var oldPath = Path.Combine(testDir, "document.txt");
        var newPath = Path.Combine(testDir, "encrypted.txt");
        File.Move(oldPath, newPath);
        Console.WriteLine("✓ Renamed file: document.txt -> encrypted.txt");
        await Task.Delay(500);

        // Simulate file deletion
        File.Delete(newPath);
        Console.WriteLine("✓ Deleted file: encrypted.txt");
        await Task.Delay(500);
    }

    private static void DisplayStatistics(IIntrusionAlertSystem alertSystem, ILogger logger)
    {
        Console.WriteLine("\n" + new string('=', 50));
        Console.WriteLine("📊 ATTACK STATISTICS");
        Console.WriteLine(new string('=', 50));
        Console.WriteLine($"Total Attacks Detected: {alertSystem.AttackCount}");
        Console.WriteLine($"Active Monitoring: {(alertSystem.IsActive ? "Yes" : "No")}");
        
        var events = alertSystem.AttackEvents;
        if (events.Any())
        {
            Console.WriteLine("\nRecent Attack Events:");
            foreach (var evt in events.TakeLast(5))
            {
                Console.WriteLine($"  • {evt.Timestamp:HH:mm:ss} - {evt.EventType}: {Path.GetFileName(evt.TargetFile)}");
            }
        }
    }

    private static void DisplayAnalysis(AttackPatternAnalysis analysis, ILogger logger)
    {
        Console.WriteLine("\n" + new string('=', 50));
        Console.WriteLine("🔍 ATTACK PATTERN ANALYSIS");
        Console.WriteLine(new string('=', 50));
        Console.WriteLine($"Total Attacks: {analysis.TotalAttacks}");
        Console.WriteLine($"Unique Attack Types: {analysis.UniqueAttackTypes}");
        Console.WriteLine($"Most Common Attack: {analysis.MostCommonAttackType}");
        Console.WriteLine($"Overall Severity: {analysis.OverallSeverity}");
        
        if (analysis.FirstAttackTime.HasValue && analysis.LastAttackTime.HasValue)
        {
            Console.WriteLine($"Attack Duration: {analysis.AttackTimeRange.TotalSeconds:F1} seconds");
            Console.WriteLine($"First Attack: {analysis.FirstAttackTime:HH:mm:ss}");
            Console.WriteLine($"Last Attack: {analysis.LastAttackTime:HH:mm:ss}");
        }

        if (analysis.AverageTimeBetweenAttacks.TotalSeconds > 0)
        {
            Console.WriteLine($"Avg Time Between Attacks: {analysis.AverageTimeBetweenAttacks.TotalSeconds:F1} seconds");
        }

        if (analysis.AttacksByType.Any())
        {
            Console.WriteLine("\nAttacks by Type:");
            foreach (var kvp in analysis.AttacksByType.OrderByDescending(x => x.Value))
            {
                Console.WriteLine($"  • {kvp.Key}: {kvp.Value}");
            }
        }

        if (analysis.MostTargetedFiles.Any())
        {
            Console.WriteLine("\nMost Targeted Files:");
            foreach (var file in analysis.MostTargetedFiles)
            {
                Console.WriteLine($"  • {Path.GetFileName(file)}");
            }
        }

        if (analysis.CoordinatedAttackDetected)
        {
            Console.WriteLine($"\n⚠️ COORDINATED ATTACK DETECTED");
            Console.WriteLine($"Pattern: {analysis.PatternDescription}");
        }
    }
}
