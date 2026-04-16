using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Services;

namespace WindowsHoneypot.Examples;

/// <summary>
/// Example demonstrating the Visual Replay Engine functionality
/// Shows how to record attacker activities and generate forensic reports
/// </summary>
public class VisualReplayEngineExample
{
    public static async Task RunExample()
    {
        Console.WriteLine("=== Visual Replay Engine Example ===\n");

        // Create the Visual Replay Engine
        using var replayEngine = new VisualReplayEngine();

        Console.WriteLine("Starting activity recording...");
        replayEngine.StartRecording();

        Console.WriteLine("Recording is active. The engine is now capturing:");
        Console.WriteLine("  - Mouse movements and clicks");
        Console.WriteLine("  - Keyboard inputs");
        Console.WriteLine("  - Automatic screenshots every 5 seconds");
        Console.WriteLine("  - File operations");
        Console.WriteLine("  - Process activities");
        Console.WriteLine("\nPress any key to stop recording...");
        Console.ReadKey();

        Console.WriteLine("\nStopping recording...");
        replayEngine.StopRecording();

        // Generate replay data
        Console.WriteLine("\nGenerating replay data...");
        var replayData = await replayEngine.GenerateReplayAsync();

        Console.WriteLine("\n=== Recording Summary ===");
        Console.WriteLine(replayData.Summary);

        // Export to PDF (text format for MVP)
        var pdfPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            $"AttackerActivity_{DateTime.Now:yyyyMMdd_HHmmss}.pdf"
        );

        Console.WriteLine($"\nExporting report to: {pdfPath}");
        await replayEngine.ExportToPdfAsync(pdfPath);

        Console.WriteLine("\n=== Timeline Preview (First 10 Events) ===");
        var allEvents = new List<(DateTime time, string description)>();

        // Add mouse clicks
        foreach (var mouseEvent in replayData.MouseEvents.Where(e => e.EventType == "Click").Take(5))
        {
            allEvents.Add((mouseEvent.Timestamp, 
                $"Mouse {mouseEvent.Button} click at ({mouseEvent.X}, {mouseEvent.Y})"));
        }

        // Add keyboard events
        foreach (var keyEvent in replayData.KeyboardEvents.Where(e => e.EventType == "KeyDown").Take(5))
        {
            allEvents.Add((keyEvent.Timestamp, $"Key pressed: {keyEvent.Key}"));
        }

        // Sort and display
        allEvents.Sort((a, b) => a.time.CompareTo(b.time));
        foreach (var (time, description) in allEvents.Take(10))
        {
            Console.WriteLine($"[{time:HH:mm:ss.fff}] {description}");
        }

        Console.WriteLine("\n=== Screenshots Captured ===");
        Console.WriteLine($"Total screenshots: {replayData.Screenshots.Count}");
        foreach (var screenshot in replayData.Screenshots.Take(3))
        {
            Console.WriteLine($"  [{screenshot.Timestamp:HH:mm:ss}] {screenshot.FilePath}");
        }

        Console.WriteLine("\nExample completed. Check the exported PDF for full details.");
    }

    /// <summary>
    /// Example showing how to integrate with file monitoring
    /// </summary>
    public static void IntegrationExample()
    {
        using var replayEngine = new VisualReplayEngine();
        replayEngine.StartRecording();

        // Simulate file operations being recorded
        replayEngine.RecordFileOperation(
            operation: "Modify",
            filePath: @"C:\BaitFolder\sensitive_document.docx",
            processName: "notepad.exe",
            processId: 1234,
            details: "File content changed"
        );

        replayEngine.RecordFileOperation(
            operation: "Delete",
            filePath: @"C:\BaitFolder\passwords.txt",
            processName: "cmd.exe",
            processId: 5678,
            details: "File deleted by attacker"
        );

        // Simulate process activities
        replayEngine.RecordProcessActivity(
            processName: "powershell.exe",
            processId: 9012,
            activity: "Start",
            details: "Suspicious PowerShell execution detected"
        );

        replayEngine.RecordProcessActivity(
            processName: "mimikatz.exe",
            processId: 3456,
            activity: "Start",
            details: "Credential dumping tool detected"
        );

        Console.WriteLine("File operations and process activities recorded.");
        Console.WriteLine("These will appear in the timeline when replay is generated.");
    }
}
