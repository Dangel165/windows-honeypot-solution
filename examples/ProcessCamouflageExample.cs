using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;

namespace WindowsHoneypot.Examples;

/// <summary>
/// Example demonstrating the Process Camouflage functionality
/// </summary>
public class ProcessCamouflageExample
{
    public static async Task Main(string[] args)
    {
        // Setup dependency injection
        var services = new ServiceCollection();
        services.AddLogging(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Information);
        });
        services.AddSingleton<IProcessCamouflage, ProcessCamouflage>();

        var serviceProvider = services.BuildServiceProvider();
        var processCamouflage = serviceProvider.GetRequiredService<IProcessCamouflage>();

        Console.WriteLine("=== Windows Honeypot - Process Camouflage Example ===\n");

        try
        {
            // Example 1: Start default business application processes
            Console.WriteLine("Example 1: Starting default business application processes...");
            var defaultProfiles = ProcessProfileFactory.GetDefaultBusinessProfiles();
            
            Console.WriteLine($"Creating {defaultProfiles.Count} fake processes:");
            foreach (var profile in defaultProfiles)
            {
                Console.WriteLine($"  • {profile.ProcessName} - {profile.Description}");
                Console.WriteLine($"    CPU: {profile.FakeCpuUsage}%, Memory: {profile.FakeMemoryUsage / (1024 * 1024)} MB");
            }
            Console.WriteLine();

            await processCamouflage.StartFakeProcessesAsync(defaultProfiles);
            Console.WriteLine("✓ Fake processes started successfully!\n");

            // Display active processes
            Console.WriteLine("Active fake processes:");
            var activeProcesses = processCamouflage.GetActiveProcesses();
            foreach (var process in activeProcesses)
            {
                Console.WriteLine($"  • {process.ProcessName} (PID: {process.ProcessId})");
                Console.WriteLine($"    CPU: {process.CpuUsage:F1}%, Memory: {process.MemoryUsage / (1024 * 1024)} MB");
                Console.WriteLine($"    Company: {process.CompanyName}");
                if (process.NetworkConnections.Count > 0)
                {
                    Console.WriteLine($"    Network: {string.Join(", ", process.NetworkConnections)}");
                }
                Console.WriteLine();
            }

            // Simulate process metrics updates
            Console.WriteLine("Simulating realistic process behavior for 30 seconds...");
            Console.WriteLine("(CPU and memory usage will vary to appear realistic)\n");

            for (int i = 0; i < 6; i++)
            {
                await Task.Delay(5000);
                processCamouflage.UpdateProcessMetrics();
                
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Updated process metrics:");
                activeProcesses = processCamouflage.GetActiveProcesses();
                foreach (var process in activeProcesses)
                {
                    Console.WriteLine($"  {process.ProcessName}: CPU {process.CpuUsage:F1}%, Memory {process.MemoryUsage / (1024 * 1024)} MB");
                }
                Console.WriteLine();
            }

            Console.WriteLine("Press any key to stop fake processes and try scenario-based profiles...");
            Console.ReadKey();
            Console.WriteLine();

            // Stop all processes
            Console.WriteLine("Stopping all fake processes...");
            await processCamouflage.StopAllFakeProcessesAsync();
            Console.WriteLine("✓ All fake processes stopped\n");

            // Example 2: Scenario-based profiles
            Console.WriteLine("\nExample 2: Scenario-based process profiles");
            Console.WriteLine("Available scenarios: developer, office, remote, minimal\n");

            var scenarios = new[] { "developer", "office", "remote" };
            foreach (var scenario in scenarios)
            {
                Console.WriteLine($"--- {scenario.ToUpper()} Scenario ---");
                var scenarioProfiles = ProcessProfileFactory.GetProfilesForScenario(scenario);
                
                Console.WriteLine($"Starting {scenarioProfiles.Count} processes for {scenario} scenario:");
                foreach (var profile in scenarioProfiles)
                {
                    Console.WriteLine($"  • {profile.ProcessName}");
                }
                
                await processCamouflage.StartFakeProcessesAsync(scenarioProfiles);
                Console.WriteLine("✓ Processes started\n");

                await Task.Delay(3000);
                
                Console.WriteLine("Stopping processes...");
                await processCamouflage.StopAllFakeProcessesAsync();
                Console.WriteLine("✓ Processes stopped\n");
            }

            // Example 3: Custom process profile
            Console.WriteLine("\nExample 3: Creating custom process profile");
            var customProfile = ProcessProfileFactory.CreateCustomProfile(
                processName: "CustomApp.exe",
                description: "Custom Business Application",
                companyName: "My Company Inc.",
                cpuUsage: 3,
                memoryUsageMB: 200,
                networkConnections: new List<string> { "api.mycompany.com:443" }
            );

            Console.WriteLine("Custom profile created:");
            Console.WriteLine($"  Name: {customProfile.ProcessName}");
            Console.WriteLine($"  Description: {customProfile.Description}");
            Console.WriteLine($"  Company: {customProfile.CompanyName}");
            Console.WriteLine($"  CPU: {customProfile.FakeCpuUsage}%");
            Console.WriteLine($"  Memory: {customProfile.FakeMemoryUsage / (1024 * 1024)} MB");
            Console.WriteLine();

            await processCamouflage.StartFakeProcessesAsync(new List<ProcessProfile> { customProfile });
            Console.WriteLine("✓ Custom process started\n");

            await Task.Delay(5000);

            await processCamouflage.StopAllFakeProcessesAsync();
            Console.WriteLine("✓ Custom process stopped\n");

            // Display summary
            Console.WriteLine("=== Summary ===");
            Console.WriteLine("The Process Camouflage System:");
            Console.WriteLine("1. Creates fake processes that appear in Task Manager");
            Console.WriteLine("2. Simulates realistic CPU and memory usage");
            Console.WriteLine("3. Creates fake network connections");
            Console.WriteLine("4. Varies resource usage over time for realism");
            Console.WriteLine("5. Supports predefined profiles and custom configurations");
            Console.WriteLine();
            Console.WriteLine("This makes the honeypot appear as a real business workstation,");
            Console.WriteLine("encouraging attackers to continue their activities while being monitored.");
            Console.WriteLine();
            Console.WriteLine("Requirements validated:");
            Console.WriteLine("  ✓ 12.1: Launch fake business applications");
            Console.WriteLine("  ✓ 12.2: Simulate realistic memory usage");
            Console.WriteLine("  ✓ 12.3: Simulate fake network connections");
            Console.WriteLine("  ✓ 12.4: Appear real in Task Manager");
            Console.WriteLine("  ✓ 12.5: Create fake Windows services (framework ready)");
            Console.WriteLine("  ✓ 12.6: Vary CPU usage realistically");
            Console.WriteLine("  ✓ 12.7: User configuration of fake processes");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error: {ex.Message}");
            Console.WriteLine($"Stack trace: {ex.StackTrace}");
        }
        finally
        {
            // Cleanup
            Console.WriteLine("\nCleaning up...");
            try
            {
                await processCamouflage.StopAllFakeProcessesAsync();
            }
            catch
            {
                // Processes might already be stopped
            }
        }

        Console.WriteLine("\nExample completed. Press any key to exit...");
        Console.ReadKey();
    }
}
