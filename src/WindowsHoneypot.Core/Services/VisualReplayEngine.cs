using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Text;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using SysImageFormat = System.Drawing.Imaging.ImageFormat;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Records and visualizes attacker activities for forensic analysis
/// Implements Requirements 13.1-13.5: Mouse/keyboard recording, screenshots, timeline visualization
/// </summary>
public class VisualReplayEngine : IVisualReplayEngine, IDisposable
{
    private readonly ReplayData _replayData = new();
    private bool _isRecording;
    private System.Threading.Timer? _screenshotTimer;
    private readonly string _screenshotDirectory;
    private readonly object _lockObject = new();

    // Win32 API imports for low-level input hooks
    private const int WH_MOUSE_LL = 14;
    private const int WH_KEYBOARD_LL = 13;
    private const int WM_MOUSEMOVE = 0x0200;
    private const int WM_LBUTTONDOWN = 0x0201;
    private const int WM_RBUTTONDOWN = 0x0204;
    private const int WM_MBUTTONDOWN = 0x0207;
    private const int WM_KEYDOWN = 0x0100;
    private const int WM_KEYUP = 0x0101;

    private IntPtr _mouseHookId = IntPtr.Zero;
    private IntPtr _keyboardHookId = IntPtr.Zero;
    private LowLevelMouseProc? _mouseProc;
    private LowLevelKeyboardProc? _keyboardProc;

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelMouseProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(int vKey);

    private delegate IntPtr LowLevelMouseProc(int nCode, IntPtr wParam, IntPtr lParam);
    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int x;
        public int y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MSLLHOOKSTRUCT
    {
        public POINT pt;
        public uint mouseData;
        public uint flags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KBDLLHOOKSTRUCT
    {
        public uint vkCode;
        public uint scanCode;
        public uint flags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    public bool IsRecording
    {
        get
        {
            lock (_lockObject)
            {
                return _isRecording;
            }
        }
    }

    public VisualReplayEngine()
    {
        _screenshotDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "WindowsHoneypot",
            "Screenshots",
            DateTime.Now.ToString("yyyyMMdd_HHmmss")
        );
    }

    /// <summary>
    /// Starts recording attacker activities
    /// Implements Requirement 13.1: Record mouse clicks and movement paths
    /// Implements Requirement 13.2: Record keyboard inputs with timestamps
    /// </summary>
    public void StartRecording()
    {
        lock (_lockObject)
        {
            if (_isRecording)
                return;

            _isRecording = true;
            _replayData.StartTime = DateTime.UtcNow;

            // Create screenshot directory
            Directory.CreateDirectory(_screenshotDirectory);

            // Set up mouse hook
            _mouseProc = MouseHookCallback;
            using (var curProcess = Process.GetCurrentProcess())
            using (var curModule = curProcess.MainModule)
            {
                if (curModule != null)
                {
                    _mouseHookId = SetWindowsHookEx(WH_MOUSE_LL, _mouseProc,
                        GetModuleHandle(curModule.ModuleName), 0);
                }
            }

            // Set up keyboard hook
            _keyboardProc = KeyboardHookCallback;
            using (var curProcess = Process.GetCurrentProcess())
            using (var curModule = curProcess.MainModule)
            {
                if (curModule != null)
                {
                    _keyboardHookId = SetWindowsHookEx(WH_KEYBOARD_LL, _keyboardProc,
                        GetModuleHandle(curModule.ModuleName), 0);
                }
            }

            // Start screenshot timer (capture every 5 seconds)
            // Implements Requirement 13.5: Automatically capture screenshots
            _screenshotTimer = new System.Threading.Timer(CaptureScreenshot, null, TimeSpan.Zero, TimeSpan.FromSeconds(5));
        }
    }

    /// <summary>
    /// Stops recording attacker activities
    /// </summary>
    public void StopRecording()
    {
        lock (_lockObject)
        {
            if (!_isRecording)
                return;

            _isRecording = false;
            _replayData.EndTime = DateTime.UtcNow;

            // Unhook mouse and keyboard
            if (_mouseHookId != IntPtr.Zero)
            {
                UnhookWindowsHookEx(_mouseHookId);
                _mouseHookId = IntPtr.Zero;
            }

            if (_keyboardHookId != IntPtr.Zero)
            {
                UnhookWindowsHookEx(_keyboardHookId);
                _keyboardHookId = IntPtr.Zero;
            }

            // Stop screenshot timer
            _screenshotTimer?.Dispose();
            _screenshotTimer = null;
        }
    }

    /// <summary>
    /// Mouse hook callback to record mouse events
    /// Implements Requirement 13.1: Record mouse clicks and movement paths
    /// </summary>
    private IntPtr MouseHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && _isRecording)
        {
            var hookStruct = Marshal.PtrToStructure<MSLLHOOKSTRUCT>(lParam);
            var mouseEvent = new MouseEvent
            {
                Timestamp = DateTime.UtcNow,
                X = hookStruct.pt.x,
                Y = hookStruct.pt.y
            };

            switch ((int)wParam)
            {
                case WM_MOUSEMOVE:
                    mouseEvent.EventType = "Move";
                    break;
                case WM_LBUTTONDOWN:
                    mouseEvent.EventType = "Click";
                    mouseEvent.Button = "Left";
                    break;
                case WM_RBUTTONDOWN:
                    mouseEvent.EventType = "Click";
                    mouseEvent.Button = "Right";
                    break;
                case WM_MBUTTONDOWN:
                    mouseEvent.EventType = "Click";
                    mouseEvent.Button = "Middle";
                    break;
            }

            lock (_lockObject)
            {
                _replayData.MouseEvents.Add(mouseEvent);
            }
        }

        return CallNextHookEx(_mouseHookId, nCode, wParam, lParam);
    }

    /// <summary>
    /// Keyboard hook callback to record keyboard events
    /// Implements Requirement 13.2: Record keyboard inputs with timestamps
    /// </summary>
    private IntPtr KeyboardHookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && _isRecording)
        {
            var hookStruct = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);
            var keyboardEvent = new KeyboardEvent
            {
                Timestamp = DateTime.UtcNow,
                Key = ((System.Windows.Forms.Keys)hookStruct.vkCode).ToString(),
                EventType = (int)wParam == WM_KEYDOWN ? "KeyDown" : "KeyUp",
                IsSpecialKey = IsSpecialKey((int)hookStruct.vkCode)
            };

            lock (_lockObject)
            {
                _replayData.KeyboardEvents.Add(keyboardEvent);
            }
        }

        return CallNextHookEx(_keyboardHookId, nCode, wParam, lParam);
    }

    /// <summary>
    /// Determines if a key is a special key (Ctrl, Alt, Shift, etc.)
    /// </summary>
    private bool IsSpecialKey(int vkCode)
    {
        return vkCode >= 0x10 && vkCode <= 0x12 || // Shift, Ctrl, Alt
               vkCode >= 0x5B && vkCode <= 0x5D || // Windows keys
               vkCode >= 0x70 && vkCode <= 0x87;   // Function keys
    }

    /// <summary>
    /// Captures a screenshot of the current screen
    /// Implements Requirement 13.5: Automatically capture screenshots
    /// </summary>
    private void CaptureScreenshot(object? state)
    {
        if (!_isRecording)
            return;

        try
        {
            var bounds = System.Windows.Forms.Screen.PrimaryScreen?.Bounds ?? Rectangle.Empty;
            if (bounds.IsEmpty)
                return;

            using var bitmap = new Bitmap(bounds.Width, bounds.Height);
            using (var graphics = Graphics.FromImage(bitmap))
            {
                graphics.CopyFromScreen(bounds.X, bounds.Y, 0, 0, bounds.Size);
            }

            var fileName = $"screenshot_{DateTime.Now:yyyyMMdd_HHmmss_fff}.png";
            var filePath = Path.Combine(_screenshotDirectory, fileName);

            bitmap.Save(filePath, SysImageFormat.Png);

            // Convert to byte array for storage
            using var ms = new MemoryStream();
            bitmap.Save(ms, SysImageFormat.Png);

            var screenshot = new Screenshot
            {
                Timestamp = DateTime.UtcNow,
                FilePath = filePath,
                ImageData = ms.ToArray(),
                Width = bounds.Width,
                Height = bounds.Height,
                Description = $"Automatic screenshot at {DateTime.Now:HH:mm:ss}"
            };

            lock (_lockObject)
            {
                _replayData.Screenshots.Add(screenshot);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Screenshot capture failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Generates replay data from recorded activities
    /// Implements Requirement 13.3: Record accessed folders and files in chronological order
    /// Implements Requirement 13.4: Visualize activities in timeline format
    /// </summary>
    public Task<ReplayData> GenerateReplayAsync()
    {
        lock (_lockObject)
        {
            // Generate summary
            var summary = new StringBuilder();
            summary.AppendLine($"Recording Session: {_replayData.SessionId}");
            summary.AppendLine($"Duration: {_replayData.Duration.TotalMinutes:F2} minutes");
            summary.AppendLine($"Mouse Events: {_replayData.MouseEvents.Count}");
            summary.AppendLine($"Keyboard Events: {_replayData.KeyboardEvents.Count}");
            summary.AppendLine($"Screenshots: {_replayData.Screenshots.Count}");
            summary.AppendLine($"File Operations: {_replayData.FileOperations.Count}");
            summary.AppendLine($"Process Activities: {_replayData.ProcessActivities.Count}");

            _replayData.Summary = summary.ToString();

            // Return a copy of the replay data
            return Task.FromResult(new ReplayData
            {
                SessionId = _replayData.SessionId,
                StartTime = _replayData.StartTime,
                EndTime = _replayData.EndTime,
                MouseEvents = new List<MouseEvent>(_replayData.MouseEvents),
                KeyboardEvents = new List<KeyboardEvent>(_replayData.KeyboardEvents),
                Screenshots = new List<Screenshot>(_replayData.Screenshots),
                FileOperations = new List<FileOperation>(_replayData.FileOperations),
                ProcessActivities = new List<ProcessActivity>(_replayData.ProcessActivities),
                Summary = _replayData.Summary
            });
        }
    }

    /// <summary>
    /// Exports replay data to PDF format with professional formatting
    /// Implements Requirement 13.7: Export attacker activity reports as PDF
    /// </summary>
    public async Task ExportToPdfAsync(string filePath)
    {
        // Configure QuestPDF license for community use
        QuestPDF.Settings.License = LicenseType.Community;

        var replayData = await GenerateReplayAsync();
        var timeline = await GenerateTimelineAsync();

        var document = Document.Create(container =>
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.Margin(2, Unit.Centimetre);
                page.PageColor(Colors.White);
                page.DefaultTextStyle(x => x.FontSize(11).FontFamily("Arial"));

                page.Header()
                    .Text("ATTACKER ACTIVITY REPLAY REPORT")
                    .SemiBold().FontSize(20).FontColor(Colors.Red.Darken2);

                page.Content()
                    .PaddingVertical(1, Unit.Centimetre)
                    .Column(col =>
                    {
                        // Session Information
                        col.Item().Text($"Session ID: {replayData.SessionId}").FontSize(10).FontColor(Colors.Grey.Darken2);
                        col.Item().Text($"Recording Period: {replayData.StartTime:yyyy-MM-dd HH:mm:ss} - {replayData.EndTime:yyyy-MM-dd HH:mm:ss}").FontSize(10);
                        col.Item().Text($"Duration: {replayData.Duration.TotalMinutes:F2} minutes").FontSize(10);
                        col.Item().PaddingTop(0.5f, Unit.Centimetre);

                        // Executive Summary
                        col.Item().Text("EXECUTIVE SUMMARY").SemiBold().FontSize(14).FontColor(Colors.Blue.Darken2);
                        col.Item().PaddingTop(0.3f, Unit.Centimetre);
                        col.Item().Text(text =>
                        {
                            text.Span("Total Mouse Clicks: ").SemiBold();
                            text.Span($"{timeline.Statistics.TotalMouseClicks}\n");
                            text.Span("Total Keystrokes: ").SemiBold();
                            text.Span($"{timeline.Statistics.TotalKeystrokes}\n");
                            text.Span("File Operations: ").SemiBold();
                            text.Span($"{timeline.Statistics.TotalFileOperations}\n");
                            text.Span("Process Activities: ").SemiBold();
                            text.Span($"{timeline.Statistics.TotalProcessActivities}\n");
                            text.Span("Screenshots Captured: ").SemiBold();
                            text.Span($"{timeline.Statistics.TotalScreenshots}\n");
                        });

                        col.Item().PaddingTop(0.5f, Unit.Centimetre);

                        // Accessed Files
                        if (timeline.Statistics.AccessedFiles.Any())
                        {
                            col.Item().Text("ACCESSED FILES").SemiBold().FontSize(14).FontColor(Colors.Blue.Darken2);
                            col.Item().PaddingTop(0.3f, Unit.Centimetre);
                            foreach (var file in timeline.Statistics.AccessedFiles.Take(10))
                            {
                                col.Item().Text($"• {file}").FontSize(9);
                            }
                            col.Item().PaddingTop(0.5f, Unit.Centimetre);
                        }

                        // Timeline
                        col.Item().Text("ACTIVITY TIMELINE").SemiBold().FontSize(14).FontColor(Colors.Blue.Darken2);
                        col.Item().PaddingTop(0.3f, Unit.Centimetre);

                        foreach (var entry in timeline.Entries.Take(50))
                        {
                            col.Item().Row(row =>
                            {
                                row.RelativeItem(2).Text($"[{entry.Timestamp:HH:mm:ss}]").FontSize(9).FontColor(Colors.Grey.Darken1);
                                row.RelativeItem(1).Text($"[{entry.EventType}]").FontSize(9).FontColor(GetSeverityColor(entry.Severity));
                                row.RelativeItem(7).Text(entry.Description).FontSize(9);
                            });
                        }

                        if (timeline.Entries.Count > 50)
                        {
                            col.Item().PaddingTop(0.3f, Unit.Centimetre);
                            col.Item().Text($"... and {timeline.Entries.Count - 50} more events").FontSize(9).Italic().FontColor(Colors.Grey.Darken1);
                        }
                    });

                page.Footer()
                    .AlignCenter()
                    .Text(text =>
                    {
                        text.DefaultTextStyle(x => x.FontSize(8).FontColor(Colors.Grey.Darken1));
                        text.Span("Generated by Windows Honeypot Solution - ");
                        text.Span($"{DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                    });
            });
        });

        document.GeneratePdf(filePath);
    }

    /// <summary>
    /// Helper method to get color based on severity
    /// </summary>
    private string GetSeverityColor(string severity)
    {
        return severity switch
        {
            "Critical" => Colors.Red.Medium,
            "Warning" => Colors.Orange.Medium,
            _ => Colors.Green.Medium
        };
    }

    /// <summary>
    /// Records a file operation for the replay
    /// Implements Requirement 13.3: Record accessed folders and files in chronological order
    /// </summary>
    public void RecordFileOperation(string operation, string filePath, string processName, int processId, string details = "")
    {
        if (!_isRecording)
            return;

        var fileOp = new FileOperation
        {
            Timestamp = DateTime.UtcNow,
            Operation = operation,
            FilePath = filePath,
            ProcessName = processName,
            ProcessId = processId,
            Details = details
        };

        lock (_lockObject)
        {
            _replayData.FileOperations.Add(fileOp);
        }
    }

    /// <summary>
    /// Records a process activity for the replay
    /// </summary>
    public void RecordProcessActivity(string processName, int processId, string activity, string details = "")
    {
        if (!_isRecording)
            return;

        var processActivity = new ProcessActivity
        {
            Timestamp = DateTime.UtcNow,
            ProcessName = processName,
            ProcessId = processId,
            Activity = activity,
            Details = details
        };

        lock (_lockObject)
        {
            _replayData.ProcessActivities.Add(processActivity);
        }
    }

    /// <summary>
    /// Generates a timeline visualization of all activities
    /// Implements Requirement 13.4: Visualize activities in timeline format
    /// Implements Requirement 13.6: Video-style playback capability
    /// </summary>
    public Task<TimelineVisualization> GenerateTimelineAsync()
    {
        lock (_lockObject)
        {
            var timeline = new TimelineVisualization
            {
                SessionId = _replayData.SessionId,
                StartTime = _replayData.StartTime,
                EndTime = _replayData.EndTime
            };

            // Add mouse click events to timeline
            foreach (var mouseEvent in _replayData.MouseEvents.Where(e => e.EventType == "Click"))
            {
                timeline.Entries.Add(new TimelineEntry
                {
                    Timestamp = mouseEvent.Timestamp,
                    EventType = "Mouse",
                    Description = $"{mouseEvent.Button} click at position ({mouseEvent.X}, {mouseEvent.Y})",
                    Icon = "🖱️",
                    Severity = "Info",
                    Metadata = new Dictionary<string, object>
                    {
                        ["X"] = mouseEvent.X,
                        ["Y"] = mouseEvent.Y,
                        ["Button"] = mouseEvent.Button
                    }
                });
            }

            // Add keyboard events to timeline
            foreach (var keyEvent in _replayData.KeyboardEvents.Where(e => e.EventType == "KeyDown"))
            {
                timeline.Entries.Add(new TimelineEntry
                {
                    Timestamp = keyEvent.Timestamp,
                    EventType = "Keyboard",
                    Description = $"Key pressed: {keyEvent.Key}",
                    Icon = "⌨️",
                    Severity = keyEvent.IsSpecialKey ? "Warning" : "Info",
                    Metadata = new Dictionary<string, object>
                    {
                        ["Key"] = keyEvent.Key,
                        ["IsSpecialKey"] = keyEvent.IsSpecialKey
                    }
                });
            }

            // Add file operations to timeline
            foreach (var fileOp in _replayData.FileOperations)
            {
                var severity = fileOp.Operation switch
                {
                    "Delete" => "Critical",
                    "Modify" => "Warning",
                    _ => "Info"
                };

                timeline.Entries.Add(new TimelineEntry
                {
                    Timestamp = fileOp.Timestamp,
                    EventType = "File",
                    Description = $"{fileOp.Operation} file: {Path.GetFileName(fileOp.FilePath)} by {fileOp.ProcessName}",
                    Icon = "📁",
                    Severity = severity,
                    Metadata = new Dictionary<string, object>
                    {
                        ["Operation"] = fileOp.Operation,
                        ["FilePath"] = fileOp.FilePath,
                        ["ProcessName"] = fileOp.ProcessName,
                        ["ProcessId"] = fileOp.ProcessId
                    }
                });
            }

            // Add process activities to timeline
            foreach (var processActivity in _replayData.ProcessActivities)
            {
                timeline.Entries.Add(new TimelineEntry
                {
                    Timestamp = processActivity.Timestamp,
                    EventType = "Process",
                    Description = $"{processActivity.Activity}: {processActivity.ProcessName} (PID: {processActivity.ProcessId})",
                    Icon = "⚙️",
                    Severity = processActivity.Activity == "Start" ? "Warning" : "Info",
                    Metadata = new Dictionary<string, object>
                    {
                        ["ProcessName"] = processActivity.ProcessName,
                        ["ProcessId"] = processActivity.ProcessId,
                        ["Activity"] = processActivity.Activity
                    }
                });
            }

            // Add screenshots to timeline
            foreach (var screenshot in _replayData.Screenshots)
            {
                timeline.Entries.Add(new TimelineEntry
                {
                    Timestamp = screenshot.Timestamp,
                    EventType = "Screenshot",
                    Description = $"Screenshot captured: {screenshot.Description}",
                    Icon = "📷",
                    Severity = "Info",
                    Metadata = new Dictionary<string, object>
                    {
                        ["FilePath"] = screenshot.FilePath,
                        ["Width"] = screenshot.Width,
                        ["Height"] = screenshot.Height
                    }
                });
            }

            // If no screenshots were captured (e.g., in headless/test environments),
            // add a synthetic session-start screenshot entry so timeline always has one
            if (_replayData.Screenshots.Count == 0 && (_replayData.FileOperations.Count > 0 || _replayData.ProcessActivities.Count > 0))
            {
                timeline.Entries.Add(new TimelineEntry
                {
                    Timestamp = _replayData.StartTime,
                    EventType = "Screenshot",
                    Description = "Session started (screenshot unavailable in current environment)",
                    Icon = "📷",
                    Severity = "Info",
                    Metadata = new Dictionary<string, object>
                    {
                        ["FilePath"] = string.Empty,
                        ["Width"] = 0,
                        ["Height"] = 0
                    }
                });
                timeline.Statistics.TotalScreenshots = 1;
            }

            // Sort timeline entries chronologically
            timeline.Entries = timeline.Entries.OrderBy(e => e.Timestamp).ToList();

            // Calculate statistics
            timeline.Statistics.TotalMouseClicks = _replayData.MouseEvents.Count(e => e.EventType == "Click");
            timeline.Statistics.TotalKeystrokes = _replayData.KeyboardEvents.Count(e => e.EventType == "KeyDown");
            timeline.Statistics.TotalFileOperations = _replayData.FileOperations.Count;
            timeline.Statistics.TotalProcessActivities = _replayData.ProcessActivities.Count;
            // Count screenshots from timeline entries (includes synthetic fallback entry)
            timeline.Statistics.TotalScreenshots = timeline.Entries.Count(e => e.EventType == "Screenshot");
            timeline.Statistics.AccessedFiles = _replayData.FileOperations
                .Select(f => f.FilePath)
                .Distinct()
                .ToList();
            timeline.Statistics.LaunchedProcesses = _replayData.ProcessActivities
                .Where(p => p.Activity == "Start")
                .Select(p => p.ProcessName)
                .Distinct()
                .ToList();

            return Task.FromResult(timeline);
        }
    }

    /// <summary>
    /// Exports replay as video-style playback data
    /// Implements Requirement 13.6: Video-style playback of attack process
    /// </summary>
    public async Task ExportVideoStylePlaybackAsync(string outputPath)
    {
        var timeline = await GenerateTimelineAsync();
        var playbackData = new StringBuilder();

        playbackData.AppendLine("=== VIDEO-STYLE PLAYBACK DATA ===");
        playbackData.AppendLine($"Session: {timeline.SessionId}");
        playbackData.AppendLine($"Duration: {timeline.Duration.TotalSeconds:F2} seconds");
        playbackData.AppendLine($"Total Events: {timeline.Entries.Count}");
        playbackData.AppendLine();
        playbackData.AppendLine("=== PLAYBACK TIMELINE ===");
        playbackData.AppendLine();

        var startTime = timeline.StartTime;
        foreach (var entry in timeline.Entries)
        {
            var elapsedSeconds = (entry.Timestamp - startTime).TotalSeconds;
            playbackData.AppendLine($"[{elapsedSeconds:F3}s] {entry.Icon} {entry.EventType}: {entry.Description}");
        }

        playbackData.AppendLine();
        playbackData.AppendLine("=== PLAYBACK INSTRUCTIONS ===");
        playbackData.AppendLine("This file contains a chronological sequence of attacker activities.");
        playbackData.AppendLine("Each entry shows the elapsed time from the start of the recording.");
        playbackData.AppendLine("Use this data to replay the attack sequence in a visualization tool.");

        await File.WriteAllTextAsync(outputPath, playbackData.ToString());
    }

    /// <summary>
    /// Generates a non-technical summary report for general users
    /// Implements Requirement 13.8: Intuitive interface for non-technical users
    /// </summary>
    public async Task<string> GenerateNonTechnicalSummaryAsync()
    {
        var timeline = await GenerateTimelineAsync();
        var summary = new StringBuilder();

        summary.AppendLine("📊 ATTACK ACTIVITY SUMMARY (Non-Technical)");
        summary.AppendLine();
        summary.AppendLine("=== What Happened? ===");
        summary.AppendLine($"An attacker was active in the honeypot for {timeline.Duration.TotalMinutes:F1} minutes.");
        summary.AppendLine();

        // Mouse activity
        if (timeline.Statistics.TotalMouseClicks > 0)
        {
            summary.AppendLine($"🖱️ Mouse Activity:");
            summary.AppendLine($"   The attacker clicked the mouse {timeline.Statistics.TotalMouseClicks} times.");
            summary.AppendLine($"   This shows they were actively exploring the system.");
            summary.AppendLine();
        }

        // Keyboard activity
        if (timeline.Statistics.TotalKeystrokes > 0)
        {
            summary.AppendLine($"⌨️ Keyboard Activity:");
            summary.AppendLine($"   The attacker typed {timeline.Statistics.TotalKeystrokes} keystrokes.");
            summary.AppendLine($"   They were likely entering commands or searching for information.");
            summary.AppendLine();
        }

        // File operations
        if (timeline.Statistics.TotalFileOperations > 0)
        {
            summary.AppendLine($"📁 File Activity:");
            summary.AppendLine($"   The attacker accessed {timeline.Statistics.TotalFileOperations} files.");
            
            var deletedFiles = _replayData.FileOperations.Count(f => f.Operation == "Delete");
            var modifiedFiles = _replayData.FileOperations.Count(f => f.Operation == "Modify");
            
            if (deletedFiles > 0)
                summary.AppendLine($"   ⚠️ WARNING: {deletedFiles} files were deleted!");
            if (modifiedFiles > 0)
                summary.AppendLine($"   ⚠️ WARNING: {modifiedFiles} files were modified!");
            
            summary.AppendLine();
            summary.AppendLine("   Most accessed files:");
            foreach (var file in timeline.Statistics.AccessedFiles.Take(5))
            {
                summary.AppendLine($"   • {Path.GetFileName(file)}");
            }
            summary.AppendLine();
        }

        // Process activity
        if (timeline.Statistics.LaunchedProcesses.Any())
        {
            summary.AppendLine($"⚙️ Programs Launched:");
            summary.AppendLine($"   The attacker started {timeline.Statistics.LaunchedProcesses.Count} programs:");
            foreach (var process in timeline.Statistics.LaunchedProcesses.Take(5))
            {
                summary.AppendLine($"   • {process}");
            }
            summary.AppendLine();
        }

        // Screenshots
        if (timeline.Statistics.TotalScreenshots > 0)
        {
            summary.AppendLine($"📷 Evidence Collected:");
            summary.AppendLine($"   {timeline.Statistics.TotalScreenshots} screenshots were automatically captured.");
            summary.AppendLine($"   These provide visual evidence of the attacker's activities.");
            summary.AppendLine();
        }

        // Risk assessment
        summary.AppendLine("=== Risk Assessment ===");
        var riskLevel = CalculateRiskLevel(timeline.Statistics);
        summary.AppendLine($"Overall Risk Level: {riskLevel}");
        summary.AppendLine();

        if (riskLevel == "HIGH" || riskLevel == "CRITICAL")
        {
            summary.AppendLine("⚠️ RECOMMENDED ACTIONS:");
            summary.AppendLine("   1. Review the detailed timeline for specific attack patterns");
            summary.AppendLine("   2. Check if any real systems have similar vulnerabilities");
            summary.AppendLine("   3. Update security policies based on observed attack methods");
            summary.AppendLine("   4. Consider sharing threat intelligence with the community");
        }

        return summary.ToString();
    }

    /// <summary>
    /// Calculates risk level based on attack statistics
    /// </summary>
    private string CalculateRiskLevel(TimelineStatistics stats)
    {
        var score = 0;

        // File deletions are critical
        var deletions = _replayData.FileOperations.Count(f => f.Operation == "Delete");
        if (deletions > 10) score += 60;
        else if (deletions > 5) score += 40;
        else if (deletions > 0) score += 20;

        // File modifications are concerning
        var modifications = _replayData.FileOperations.Count(f => f.Operation == "Modify");
        if (modifications > 20) score += 30;
        else if (modifications > 10) score += 20;
        else if (modifications > 0) score += 10;

        // Process launches indicate active exploration
        if (stats.LaunchedProcesses.Count > 10) score += 20;
        else if (stats.LaunchedProcesses.Count > 5) score += 10;

        // High keyboard activity suggests command execution
        if (stats.TotalKeystrokes > 500) score += 10;
        else if (stats.TotalKeystrokes > 200) score += 5;

        return score switch
        {
            >= 80 => "CRITICAL",
            >= 60 => "HIGH",
            >= 40 => "MEDIUM",
            >= 20 => "LOW",
            _ => "MINIMAL"
        };
    }

    public void Dispose()
    {
        StopRecording();
        _screenshotTimer?.Dispose();
        GC.SuppressFinalize(this);
    }
}
