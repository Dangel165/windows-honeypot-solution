namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Data structure for visual replay of attacker activities
/// </summary>
public class ReplayData
{
    /// <summary>
    /// Unique identifier for the replay session
    /// </summary>
    public Guid SessionId { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Start time of the recording
    /// </summary>
    public DateTime StartTime { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// End time of the recording
    /// </summary>
    public DateTime EndTime { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Total duration of the recording
    /// </summary>
    public TimeSpan Duration => EndTime - StartTime;

    /// <summary>
    /// List of mouse events recorded
    /// </summary>
    public List<MouseEvent> MouseEvents { get; set; } = new();

    /// <summary>
    /// List of keyboard events recorded
    /// </summary>
    public List<KeyboardEvent> KeyboardEvents { get; set; } = new();

    /// <summary>
    /// List of screenshots taken during the session
    /// </summary>
    public List<Screenshot> Screenshots { get; set; } = new();

    /// <summary>
    /// List of file operations performed
    /// </summary>
    public List<FileOperation> FileOperations { get; set; } = new();

    /// <summary>
    /// List of process activities
    /// </summary>
    public List<ProcessActivity> ProcessActivities { get; set; } = new();

    /// <summary>
    /// Summary of the attack session
    /// </summary>
    public string Summary { get; set; } = string.Empty;
}

/// <summary>
/// Mouse event data
/// </summary>
public class MouseEvent
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public int X { get; set; }
    public int Y { get; set; }
    public string EventType { get; set; } = string.Empty; // Click, Move, Scroll
    public string Button { get; set; } = string.Empty; // Left, Right, Middle
}

/// <summary>
/// Keyboard event data
/// </summary>
public class KeyboardEvent
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string Key { get; set; } = string.Empty;
    public string EventType { get; set; } = string.Empty; // KeyDown, KeyUp
    public bool IsSpecialKey { get; set; } = false;
    public string Context { get; set; } = string.Empty; // Window or application context
}

/// <summary>
/// Screenshot data
/// </summary>
public class Screenshot
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string FilePath { get; set; } = string.Empty;
    public byte[] ImageData { get; set; } = Array.Empty<byte>();
    public int Width { get; set; }
    public int Height { get; set; }
    public string Description { get; set; } = string.Empty;
}

/// <summary>
/// File operation data
/// </summary>
public class FileOperation
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string Operation { get; set; } = string.Empty; // Create, Modify, Delete, Rename
    public string FilePath { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string Details { get; set; } = string.Empty;
}

/// <summary>
/// Process activity data
/// </summary>
public class ProcessActivity
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string Activity { get; set; } = string.Empty; // Start, Stop, Network, Registry
    public string Details { get; set; } = string.Empty;
}

/// <summary>
/// Timeline visualization data for replay
/// </summary>
public class TimelineVisualization
{
    /// <summary>
    /// Session identifier
    /// </summary>
    public Guid SessionId { get; set; }

    /// <summary>
    /// Timeline entries sorted chronologically
    /// </summary>
    public List<TimelineEntry> Entries { get; set; } = new();

    /// <summary>
    /// Start time of the timeline
    /// </summary>
    public DateTime StartTime { get; set; }

    /// <summary>
    /// End time of the timeline
    /// </summary>
    public DateTime EndTime { get; set; }

    /// <summary>
    /// Total duration
    /// </summary>
    public TimeSpan Duration => EndTime - StartTime;

    /// <summary>
    /// Summary statistics
    /// </summary>
    public TimelineStatistics Statistics { get; set; } = new();
}

/// <summary>
/// Individual timeline entry
/// </summary>
public class TimelineEntry
{
    public DateTime Timestamp { get; set; }
    public string EventType { get; set; } = string.Empty; // Mouse, Keyboard, File, Process, Screenshot
    public string Description { get; set; } = string.Empty;
    public string Icon { get; set; } = string.Empty; // Icon identifier for UI
    public string Severity { get; set; } = "Info"; // Info, Warning, Critical
    public Dictionary<string, object> Metadata { get; set; } = new();
}

/// <summary>
/// Timeline statistics
/// </summary>
public class TimelineStatistics
{
    public int TotalMouseClicks { get; set; }
    public int TotalKeystrokes { get; set; }
    public int TotalFileOperations { get; set; }
    public int TotalProcessActivities { get; set; }
    public int TotalScreenshots { get; set; }
    public List<string> AccessedFiles { get; set; } = new();
    public List<string> LaunchedProcesses { get; set; } = new();
    public TimeSpan MostActiveTimeWindow { get; set; }
}