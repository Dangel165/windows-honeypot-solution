using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;

namespace WindowsHoneypot.Examples;

/// <summary>
/// Example demonstrating the use of PrivilegeMonitor for sandbox security
/// </summary>
public class PrivilegeMonitorExample
{
    public static async Task RunExampleAsync()
    {
        // Set up logging
        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Debug);
        });

        var logger = loggerFactory.CreateLogger<PrivilegeMonitor>();

        // Create privilege monitor
        using var privilegeMonitor = new PrivilegeMonitor(logger);

        // Subscribe to events
        privilegeMonitor.PrivilegeEscalationDetected += (sender, attackEvent) =>
        {
            Console.WriteLine($"[ALERT] Privilege Escalation Detected!");
            Console.WriteLine($"  Process: {attackEvent.SourceProcess} (PID: {attackEvent.ProcessId})");
            Console.WriteLine($"  Description: {attackEvent.Description}");
            Console.WriteLine($"  Severity: {attackEvent.Severity}");
        };

        privilegeMonitor.SandboxEscapeDetected += (sender, attackEvent) =>
        {
            Console.WriteLine($"[CRITICAL] Sandbox Escape Attempt Detected!");
            Console.WriteLine($"  Process: {attackEvent.SourceProcess} (PID: {attackEvent.ProcessId})");
            Console.WriteLine($"  Description: {attackEvent.Description}");
            Console.WriteLine($"  Severity: {attackEvent.Severity}");
        };

        // Simulate monitoring sandbox processes
        var sandboxProcessIds = new[] { 1234, 5678 }; // Example process IDs
        
        Console.WriteLine("Starting privilege monitoring...");
        privilegeMonitor.StartMonitoring(sandboxProcessIds);

        // Monitor for 30 seconds
        Console.WriteLine("Monitoring for privilege escalation and sandbox escape attempts...");
        await Task.Delay(TimeSpan.FromSeconds(30));

        // Stop monitoring
        Console.WriteLine("Stopping privilege monitoring...");
        privilegeMonitor.StopMonitoring();

        // Get detected attempts
        var detectedAttempts = privilegeMonitor.GetDetectedAttempts();
        Console.WriteLine($"\nTotal detected attempts: {detectedAttempts.Count}");

        foreach (var attempt in detectedAttempts)
        {
            Console.WriteLine($"  - {attempt.EventType}: {attempt.Description}");
        }
    }
}
