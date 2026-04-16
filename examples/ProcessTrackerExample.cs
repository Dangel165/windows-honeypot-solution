using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;

namespace WindowsHoneypot.Examples;

/// <summary>
/// Example demonstrating ProcessTracker usage for sandbox lifecycle management
/// </summary>
public class ProcessTrackerExample
{
    public static async Task Main(string[] args)
    {
        // Setup dependency injection
        var services = new ServiceCollection();
        services.AddHoneypotCore();
        var serviceProvider = services.BuildServiceProvider();

        // Get required services
        var logger = serviceProvider.GetRequiredService<ILogger<ProcessTracker>>();
        var configGenerator = serviceProvider.GetRequiredService<SandboxConfigurationGenerator>();

        // Create ProcessTracker
        using var tracker = new ProcessTracker(logger);

        // Subscribe to process exit event
        tracker.ProcessExited += (sender, args) =>
        {
            Console.WriteLine($"[EVENT] Sandbox process (PID: {args.ProcessId}) exited at {args.ExitTime}");
        };

        // Example 1: Create and track a new sandbox
        Console.WriteLine("=== Example 1: Create and Track New Sandbox ===");
        await CreateAndTrackNewSandbox(tracker, configGenerator);

        Console.WriteLine("\nPress any key to continue to Example 2...");
        Console.ReadKey();

        // Example 2: Track an existing sandbox process
        Console.WriteLine("\n=== Example 2: Track Existing Sandbox Process ===");
        TrackExistingSandbox(tracker);

        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey();
    }

    /// <summary>
    /// Example 1: Create a new sandbox and track its lifecycle
    /// </summary>
    private static async Task CreateAndTrackNewSandbox(ProcessTracker tracker, SandboxConfigurationGenerator generator)
    {
        try
        {
            // Create sandbox configuration
            var config = new SandboxConfiguration
            {
                NetworkingEnabled = false, // Disabled for security
                MemoryInMB = 4096,
                VGpuEnabled = true,
                BaitFolderPath = @"C:\BaitFolder", // Replace with actual path
                ProtectedClientEnabled = true
            };

            // Validate configuration
            var validationResult = generator.ValidateConfiguration(config);
            if (!validationResult.IsValid)
            {
                Console.WriteLine("Configuration validation failed:");
                foreach (var error in validationResult.Errors)
                {
                    Console.WriteLine($"  - {error}");
                }
                return;
            }

            // Generate .wsb file
            var wsbPath = Path.Combine(Path.GetTempPath(), "honeypot_sandbox.wsb");
            await generator.SaveWsbFileAsync(config, wsbPath);
            Console.WriteLine($"Generated .wsb file: {wsbPath}");

            // Start tracking the sandbox
            Console.WriteLine("Starting Windows Sandbox...");
            var started = await tracker.StartTrackingAsync(wsbPath);

            if (started)
            {
                Console.WriteLine($"✓ Sandbox started successfully!");
                Console.WriteLine($"  Process ID: {tracker.SandboxProcessId}");
                Console.WriteLine($"  Is Tracking: {tracker.IsTracking}");

                // Get process information
                var processInfo = tracker.GetProcessInfo();
                if (processInfo != null)
                {
                    Console.WriteLine($"  Process Name: {processInfo.ProcessName}");
                    Console.WriteLine($"  Start Time: {processInfo.StartTime}");
                    Console.WriteLine($"  Is Running: {processInfo.IsRunning}");
                }

                // Monitor the process for a while
                Console.WriteLine("\nMonitoring sandbox process...");
                for (int i = 0; i < 10; i++)
                {
                    await Task.Delay(1000);
                    var isRunning = tracker.IsProcessRunning();
                    Console.WriteLine($"  [{i + 1}s] Process running: {isRunning}");

                    if (!isRunning)
                    {
                        Console.WriteLine("  Process has exited!");
                        break;
                    }
                }

                // Stop tracking and cleanup
                Console.WriteLine("\nStopping sandbox...");
                var stopped = await tracker.StopTrackingAsync();
                Console.WriteLine(stopped ? "✓ Sandbox stopped successfully" : "✗ Failed to stop sandbox");
            }
            else
            {
                Console.WriteLine("✗ Failed to start sandbox");
                Console.WriteLine("  Note: Windows Sandbox must be enabled on your system");
            }

            // Cleanup .wsb file
            if (File.Exists(wsbPath))
            {
                File.Delete(wsbPath);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    /// <summary>
    /// Example 2: Track an existing Windows Sandbox process
    /// </summary>
    private static void TrackExistingSandbox(ProcessTracker tracker)
    {
        try
        {
            // Find running Windows Sandbox processes
            var sandboxProcesses = System.Diagnostics.Process.GetProcessesByName("WindowsSandbox");

            if (sandboxProcesses.Length == 0)
            {
                Console.WriteLine("No running Windows Sandbox processes found.");
                Console.WriteLine("Please start a Windows Sandbox manually and try again.");
                return;
            }

            // Track the first found process
            var processId = sandboxProcesses[0].Id;
            Console.WriteLine($"Found Windows Sandbox process (PID: {processId})");

            var started = tracker.StartTrackingExisting(processId);

            if (started)
            {
                Console.WriteLine($"✓ Started tracking existing sandbox");
                Console.WriteLine($"  Process ID: {tracker.SandboxProcessId}");
                Console.WriteLine($"  Is Tracking: {tracker.IsTracking}");

                // Get process information
                var processInfo = tracker.GetProcessInfo();
                if (processInfo != null)
                {
                    Console.WriteLine($"  Process Name: {processInfo.ProcessName}");
                    Console.WriteLine($"  Start Time: {processInfo.StartTime}");
                    Console.WriteLine($"  Is Running: {processInfo.IsRunning}");
                }

                // Monitor for a short time
                Console.WriteLine("\nMonitoring for 5 seconds...");
                for (int i = 0; i < 5; i++)
                {
                    Thread.Sleep(1000);
                    var isRunning = tracker.IsProcessRunning();
                    Console.WriteLine($"  [{i + 1}s] Process running: {isRunning}");
                }

                Console.WriteLine("\nNote: The sandbox will continue running after this example exits.");
                Console.WriteLine("Use Task Manager to close it manually if needed.");
            }
            else
            {
                Console.WriteLine("✗ Failed to track existing sandbox");
            }

            // Cleanup
            foreach (var process in sandboxProcesses)
            {
                process.Dispose();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    /// <summary>
    /// Example 3: Automatic cleanup on program exit
    /// </summary>
    public static async Task AutomaticCleanupExample()
    {
        var services = new ServiceCollection();
        services.AddHoneypotCore();
        var serviceProvider = services.BuildServiceProvider();

        var logger = serviceProvider.GetRequiredService<ILogger<ProcessTracker>>();
        var configGenerator = serviceProvider.GetRequiredService<SandboxConfigurationGenerator>();

        // Using 'using' statement ensures automatic cleanup
        using (var tracker = new ProcessTracker(logger))
        {
            var config = new SandboxConfiguration
            {
                NetworkingEnabled = false,
                MemoryInMB = 2048
            };

            var wsbPath = Path.Combine(Path.GetTempPath(), "temp_sandbox.wsb");
            await configGenerator.SaveWsbFileAsync(config, wsbPath);

            await tracker.StartTrackingAsync(wsbPath);

            Console.WriteLine("Sandbox is running...");
            await Task.Delay(5000);

            // When this block exits, Dispose() is called automatically
            // which stops the sandbox process
        } // <- Automatic cleanup happens here

        Console.WriteLine("Sandbox has been automatically cleaned up");
    }
}
