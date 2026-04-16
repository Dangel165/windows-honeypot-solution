using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;

namespace WindowsHoneypot.Examples;

/// <summary>
/// Example demonstrating FileMonitor usage for real-time file system monitoring
/// </summary>
public class FileMonitorExample
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
        services.AddSingleton<IFileMonitor, FileMonitor>();

        var serviceProvider = services.BuildServiceProvider();
        var fileMonitor = serviceProvider.GetRequiredService<IFileMonitor>();

        // Subscribe to file events
        fileMonitor.FileAccessed += OnFileAccessed;
        fileMonitor.FileModified += OnFileModified;
        fileMonitor.FileDeleted += OnFileDeleted;
        fileMonitor.FileRenamed += OnFileRenamed;

        // Create a test directory to monitor
        var testDirectory = Path.Combine(Path.GetTempPath(), "HoneypotTest");
        Directory.CreateDirectory(testDirectory);

        Console.WriteLine($"Starting file monitoring on: {testDirectory}");
        Console.WriteLine("Press any key to stop monitoring...\n");

        // Start monitoring
        fileMonitor.StartMonitoring(testDirectory);

        // Simulate some file operations for demonstration
        await SimulateFileOperations(testDirectory);

        // Wait for user input
        Console.ReadKey();

        // Stop monitoring
        fileMonitor.StopMonitoring();
        Console.WriteLine("\nMonitoring stopped.");

        // Cleanup
        if (Directory.Exists(testDirectory))
        {
            Directory.Delete(testDirectory, true);
        }
    }

    private static async Task SimulateFileOperations(string directory)
    {
        Console.WriteLine("Simulating file operations...\n");

        // Create a file
        var testFile = Path.Combine(directory, "test.txt");
        await File.WriteAllTextAsync(testFile, "Initial content");
        await Task.Delay(500);

        // Modify the file
        await File.WriteAllTextAsync(testFile, "Modified content");
        await Task.Delay(500);

        // Rename the file
        var renamedFile = Path.Combine(directory, "renamed.txt");
        File.Move(testFile, renamedFile);
        await Task.Delay(500);

        // Delete the file
        File.Delete(renamedFile);
        await Task.Delay(500);

        Console.WriteLine("File operations completed.\n");
    }

    private static void OnFileAccessed(object? sender, FileEventArgs e)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[FILE ACCESSED] {e.FilePath}");
        Console.WriteLine($"  Process: {e.ProcessName} (PID: {e.ProcessId})");
        Console.WriteLine($"  Time: {e.Timestamp:yyyy-MM-dd HH:mm:ss}");
        Console.ResetColor();
        Console.WriteLine();
    }

    private static void OnFileModified(object? sender, FileEventArgs e)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"[FILE MODIFIED] {e.FilePath}");
        Console.WriteLine($"  Process: {e.ProcessName} (PID: {e.ProcessId})");
        Console.WriteLine($"  Time: {e.Timestamp:yyyy-MM-dd HH:mm:ss}");
        Console.ResetColor();
        Console.WriteLine();
    }

    private static void OnFileDeleted(object? sender, FileEventArgs e)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"[FILE DELETED] {e.FilePath}");
        Console.WriteLine($"  Process: {e.ProcessName} (PID: {e.ProcessId})");
        Console.WriteLine($"  Time: {e.Timestamp:yyyy-MM-dd HH:mm:ss}");
        Console.ResetColor();
        Console.WriteLine();
    }

    private static void OnFileRenamed(object? sender, FileRenamedEventArgs e)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"[FILE RENAMED]");
        Console.WriteLine($"  Old: {e.OldName}");
        Console.WriteLine($"  New: {e.NewName}");
        Console.WriteLine($"  Process: {e.ProcessName} (PID: {e.ProcessId})");
        Console.WriteLine($"  Time: {e.Timestamp:yyyy-MM-dd HH:mm:ss}");
        Console.ResetColor();
        Console.WriteLine();
    }
}
