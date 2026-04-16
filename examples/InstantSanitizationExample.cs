using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;

namespace WindowsHoneypot.Examples;

/// <summary>
/// Example demonstrating the Instant Sanitization system
/// </summary>
public class InstantSanitizationExample
{
    public static async Task Main(string[] args)
    {
        // Setup dependency injection
        var services = new ServiceCollection();
        services.AddHoneypotCore();
        var serviceProvider = services.BuildServiceProvider();

        // Get the sanitization service
        var sanitization = serviceProvider.GetRequiredService<IInstantSanitization>();
        var logger = serviceProvider.GetRequiredService<ILogger<InstantSanitizationExample>>();

        logger.LogInformation("=== Instant Sanitization Example ===\n");

        // Example 1: Normal sanitization with progress reporting
        await NormalSanitizationExample(sanitization, logger);

        // Example 2: Emergency sanitization
        await EmergencySanitizationExample(sanitization, logger);

        // Example 3: System state validation
        await SystemStateValidationExample(sanitization, logger);

        logger.LogInformation("\n=== Example completed ===");
    }

    private static async Task NormalSanitizationExample(IInstantSanitization sanitization, ILogger logger)
    {
        logger.LogInformation("\n--- Example 1: Normal Sanitization with Progress ---");

        // Create progress reporter
        var progress = new Progress<SanitizationProgress>(p =>
        {
            logger.LogInformation(
                "[{Percent}%] {Operation}: {Message}",
                p.PercentComplete,
                p.CurrentOperation,
                p.StatusMessage
            );

            if (p.TotalItems > 0)
            {
                logger.LogInformation("  → {Processed}/{Total} items processed", p.ItemsProcessed, p.TotalItems);
            }
        });

        try
        {
            // Perform sanitization
            var result = await sanitization.SanitizeAsync(progress);

            // Display results
            logger.LogInformation("\nSanitization Result:");
            logger.LogInformation("  Success: {Success}", result.Success);
            logger.LogInformation("  Duration: {Duration}ms", result.Duration.TotalMilliseconds);
            logger.LogInformation("  Operations: {Count}", result.Operations.Count);

            foreach (var operation in result.Operations)
            {
                logger.LogInformation(
                    "    - {Type}: {Success} ({Duration}ms)",
                    operation.Type,
                    operation.Success ? "✓" : "✗",
                    operation.Duration.TotalMilliseconds
                );
                
                if (!string.IsNullOrEmpty(operation.Details))
                {
                    logger.LogInformation("      {Details}", operation.Details);
                }
            }

            if (result.Errors.Any())
            {
                logger.LogWarning("\n  Errors:");
                foreach (var error in result.Errors)
                {
                    logger.LogWarning("    - {Error}", error);
                }
            }

            if (result.VerificationReport != null)
            {
                DisplayVerificationReport(result.VerificationReport, logger);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Sanitization failed");
        }
    }

    private static async Task EmergencySanitizationExample(IInstantSanitization sanitization, ILogger logger)
    {
        logger.LogInformation("\n--- Example 2: Emergency Sanitization ---");

        try
        {
            // Simulate emergency situation
            logger.LogWarning("⚠️  Emergency situation detected! Initiating emergency sanitization...");

            var success = await sanitization.EmergencySanitizeAsync();

            if (success)
            {
                logger.LogInformation("✓ Emergency sanitization completed successfully");
            }
            else
            {
                logger.LogError("✗ Emergency sanitization failed");
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Emergency sanitization failed");
        }
    }

    private static async Task SystemStateValidationExample(IInstantSanitization sanitization, ILogger logger)
    {
        logger.LogInformation("\n--- Example 3: System State Validation ---");

        try
        {
            var report = await sanitization.ValidateSystemStateAsync();
            DisplayVerificationReport(report, logger);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "System state validation failed");
        }
    }

    private static void DisplayVerificationReport(SystemStateReport report, ILogger logger)
    {
        logger.LogInformation("\nSystem State Verification Report:");
        logger.LogInformation("  Generated: {Time}", report.GeneratedAt);
        logger.LogInformation("  Overall Health: {Health}", report.IsHealthy ? "✓ Healthy" : "✗ Issues Found");

        logger.LogInformation("\n  Sandbox Status:");
        logger.LogInformation("    Process Running: {Running}", report.SandboxStatus.SandboxProcessRunning ? "Yes" : "No");
        logger.LogInformation("    Active Processes: {Count}", report.SandboxStatus.ActiveHoneypotProcesses);

        logger.LogInformation("\n  Firewall Status:");
        logger.LogInformation("    Rules Removed: {Removed}", report.FirewallStatus.CustomRulesRemoved ? "Yes" : "No");
        logger.LogInformation("    Remaining Rules: {Count}", report.FirewallStatus.RemainingHoneypotRules);
        logger.LogInformation("    Firewall Enabled: {Enabled}", report.FirewallStatus.FirewallEnabled ? "Yes" : "No");

        logger.LogInformation("\n  Registry Status:");
        logger.LogInformation("    Modifications Reverted: {Reverted}", report.RegistryStatus.ModificationsReverted ? "Yes" : "No");
        logger.LogInformation("    Remaining Modifications: {Count}", report.RegistryStatus.RemainingModifications);

        logger.LogInformation("\n  File System Status:");
        logger.LogInformation("    Sandbox Data Deleted: {Deleted}", report.FileSystemStatus.SandboxDataDeleted ? "Yes" : "No");
        logger.LogInformation("    Temporary Files Cleared: {Cleared}", report.FileSystemStatus.TemporaryFilesCleared ? "Yes" : "No");
        logger.LogInformation("    Remaining Data Size: {Size} bytes", report.FileSystemStatus.RemainingDataSize);

        logger.LogInformation("\n  Network Status:");
        logger.LogInformation("    Network Reset: {Reset}", report.NetworkStatus.NetworkReset ? "Yes" : "No");
        logger.LogInformation("    Active Connections: {Count}", report.NetworkStatus.ActiveConnections);
        logger.LogInformation("    Internet Accessible: {Accessible}", report.NetworkStatus.InternetAccessible ? "Yes" : "No");

        if (report.Issues.Any())
        {
            logger.LogWarning("\n  Issues Found:");
            foreach (var issue in report.Issues)
            {
                logger.LogWarning("    - {Issue}", issue);
            }
        }

        if (report.Recommendations.Any())
        {
            logger.LogInformation("\n  Recommendations:");
            foreach (var recommendation in report.Recommendations)
            {
                logger.LogInformation("    - {Recommendation}", recommendation);
            }
        }
    }
}
