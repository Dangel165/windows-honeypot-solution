using System.Collections.ObjectModel;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;
using Microsoft.Win32;

namespace WindowsHoneypot.UI.ViewModels;

/// <summary>
/// ViewModel for the Visual Replay interface
/// Implements Requirements 13.6, 13.7, 13.8: Video-style playback, PDF export, non-technical UI
/// </summary>
public partial class ReplayViewModel : ObservableObject
{
    private readonly IVisualReplayEngine _replayEngine;
    
    [ObservableProperty]
    private ObservableCollection<TimelineEntryViewModel> _timelineEntries = new();
    
    [ObservableProperty]
    private TimelineEntryViewModel? _currentEntry;
    
    [ObservableProperty]
    private bool _isPlaying;
    
    [ObservableProperty]
    private double _playbackSpeed = 1.0;
    
    [ObservableProperty]
    private int _currentPosition;
    
    [ObservableProperty]
    private int _totalEntries;
    
    [ObservableProperty]
    private string _sessionSummary = string.Empty;
    
    [ObservableProperty]
    private string _riskLevel = "UNKNOWN";
    
    [ObservableProperty]
    private int _totalMouseClicks;
    
    [ObservableProperty]
    private int _totalKeystrokes;
    
    [ObservableProperty]
    private int _totalFileOperations;
    
    [ObservableProperty]
    private int _totalScreenshots;
    
    [ObservableProperty]
    private TimeSpan _sessionDuration;
    
    private System.Threading.Timer? _playbackTimer;
    private TimelineVisualization? _timeline;

    public ReplayViewModel(IVisualReplayEngine replayEngine)
    {
        _replayEngine = replayEngine;
    }

    /// <summary>
    /// Loads replay data from the Visual Replay Engine
    /// </summary>
    [RelayCommand]
    private async Task LoadReplayDataAsync()
    {
        try
        {
            _timeline = await _replayEngine.GenerateTimelineAsync();
            
            TimelineEntries.Clear();
            foreach (var entry in _timeline.Entries)
            {
                TimelineEntries.Add(new TimelineEntryViewModel(entry));
            }
            
            TotalEntries = TimelineEntries.Count;
            CurrentPosition = 0;
            
            // Update statistics
            TotalMouseClicks = _timeline.Statistics.TotalMouseClicks;
            TotalKeystrokes = _timeline.Statistics.TotalKeystrokes;
            TotalFileOperations = _timeline.Statistics.TotalFileOperations;
            TotalScreenshots = _timeline.Statistics.TotalScreenshots;
            SessionDuration = _timeline.Duration;
            
            // Generate non-technical summary
            SessionSummary = await _replayEngine.GenerateNonTechnicalSummaryAsync();
            
            // Extract risk level from summary
            ExtractRiskLevel();
        }
        catch (Exception ex)
        {
            SessionSummary = $"Error loading replay data: {ex.Message}";
        }
    }

    /// <summary>
    /// Starts video-style playback of the attack timeline
    /// Implements Requirement 13.6: Video-style playback capability
    /// </summary>
    [RelayCommand]
    private void Play()
    {
        if (TimelineEntries.Count == 0)
            return;
        
        IsPlaying = true;
        
        // Calculate delay based on playback speed
        var baseDelay = 1000; // 1 second per entry at 1x speed
        var delay = (int)(baseDelay / PlaybackSpeed);
        
        _playbackTimer = new System.Threading.Timer(PlaybackTick, null, 0, delay);
    }

    /// <summary>
    /// Pauses video-style playback
    /// </summary>
    [RelayCommand]
    private void Pause()
    {
        IsPlaying = false;
        _playbackTimer?.Dispose();
        _playbackTimer = null;
    }

    /// <summary>
    /// Stops playback and resets to beginning
    /// </summary>
    [RelayCommand]
    private void Stop()
    {
        IsPlaying = false;
        _playbackTimer?.Dispose();
        _playbackTimer = null;
        CurrentPosition = 0;
        CurrentEntry = TimelineEntries.FirstOrDefault();
    }

    /// <summary>
    /// Moves to the next timeline entry
    /// </summary>
    [RelayCommand]
    private void NextEntry()
    {
        if (CurrentPosition < TotalEntries - 1)
        {
            CurrentPosition++;
            CurrentEntry = TimelineEntries[CurrentPosition];
        }
    }

    /// <summary>
    /// Moves to the previous timeline entry
    /// </summary>
    [RelayCommand]
    private void PreviousEntry()
    {
        if (CurrentPosition > 0)
        {
            CurrentPosition--;
            CurrentEntry = TimelineEntries[CurrentPosition];
        }
    }

    /// <summary>
    /// Increases playback speed
    /// </summary>
    [RelayCommand]
    private void IncreaseSpeed()
    {
        if (PlaybackSpeed < 4.0)
        {
            PlaybackSpeed += 0.5;
            if (IsPlaying)
            {
                Pause();
                Play();
            }
        }
    }

    /// <summary>
    /// Decreases playback speed
    /// </summary>
    [RelayCommand]
    private void DecreaseSpeed()
    {
        if (PlaybackSpeed > 0.5)
        {
            PlaybackSpeed -= 0.5;
            if (IsPlaying)
            {
                Pause();
                Play();
            }
        }
    }

    /// <summary>
    /// Exports the replay to PDF format
    /// Implements Requirement 13.7: Export attack process reports to PDF format
    /// </summary>
    [RelayCommand]
    private async Task ExportToPdfAsync()
    {
        try
        {
            var saveDialog = new SaveFileDialog
            {
                Filter = "PDF Files (*.pdf)|*.pdf",
                DefaultExt = "pdf",
                FileName = $"AttackReport_{DateTime.Now:yyyyMMdd_HHmmss}.pdf"
            };

            if (saveDialog.ShowDialog() == true)
            {
                await _replayEngine.ExportToPdfAsync(saveDialog.FileName);
                SessionSummary += $"\n\n✅ PDF report exported successfully to:\n{saveDialog.FileName}";
            }
        }
        catch (Exception ex)
        {
            SessionSummary += $"\n\n❌ Error exporting PDF: {ex.Message}";
        }
    }

    /// <summary>
    /// Exports video-style playback data
    /// </summary>
    [RelayCommand]
    private async Task ExportPlaybackDataAsync()
    {
        try
        {
            var saveDialog = new SaveFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt",
                DefaultExt = "txt",
                FileName = $"PlaybackData_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
            };

            if (saveDialog.ShowDialog() == true)
            {
                await _replayEngine.ExportVideoStylePlaybackAsync(saveDialog.FileName);
                SessionSummary += $"\n\n✅ Playback data exported successfully to:\n{saveDialog.FileName}";
            }
        }
        catch (Exception ex)
        {
            SessionSummary += $"\n\n❌ Error exporting playback data: {ex.Message}";
        }
    }

    /// <summary>
    /// Playback timer tick handler
    /// </summary>
    private void PlaybackTick(object? state)
    {
        if (CurrentPosition < TotalEntries - 1)
        {
            System.Windows.Application.Current.Dispatcher.Invoke(() =>
            {
                CurrentPosition++;
                CurrentEntry = TimelineEntries[CurrentPosition];
            });
        }
        else
        {
            System.Windows.Application.Current.Dispatcher.Invoke(() =>
            {
                Pause();
            });
        }
    }

    /// <summary>
    /// Extracts risk level from the non-technical summary
    /// </summary>
    private void ExtractRiskLevel()
    {
        if (SessionSummary.Contains("CRITICAL"))
            RiskLevel = "CRITICAL";
        else if (SessionSummary.Contains("HIGH"))
            RiskLevel = "HIGH";
        else if (SessionSummary.Contains("MEDIUM"))
            RiskLevel = "MEDIUM";
        else if (SessionSummary.Contains("LOW"))
            RiskLevel = "LOW";
        else
            RiskLevel = "MINIMAL";
    }

    /// <summary>
    /// Jumps to a specific position in the timeline
    /// </summary>
    public void JumpToPosition(int position)
    {
        if (position >= 0 && position < TotalEntries)
        {
            CurrentPosition = position;
            CurrentEntry = TimelineEntries[CurrentPosition];
        }
    }
}

/// <summary>
/// ViewModel wrapper for TimelineEntry
/// Provides UI-friendly properties and formatting
/// </summary>
public class TimelineEntryViewModel : ObservableObject
{
    private readonly TimelineEntry _entry;

    public TimelineEntryViewModel(TimelineEntry entry)
    {
        _entry = entry;
    }

    public DateTime Timestamp => _entry.Timestamp;
    public string EventType => _entry.EventType;
    public string Description => _entry.Description;
    public string Icon => _entry.Icon;
    public string Severity => _entry.Severity;

    /// <summary>
    /// Formatted timestamp for display
    /// </summary>
    public string FormattedTime => Timestamp.ToString("HH:mm:ss.fff");

    /// <summary>
    /// Color based on severity for UI display
    /// Implements Requirement 13.8: Intuitive interface for non-technical users
    /// </summary>
    public string SeverityColor => Severity switch
    {
        "Critical" => "#DC3545", // Red
        "Warning" => "#FFC107",  // Orange
        _ => "#28A745"           // Green
    };

    /// <summary>
    /// User-friendly event type description
    /// </summary>
    public string FriendlyEventType => EventType switch
    {
        "Mouse" => "🖱️ Mouse Activity",
        "Keyboard" => "⌨️ Keyboard Input",
        "File" => "📁 File Operation",
        "Process" => "⚙️ Program Activity",
        "Screenshot" => "📷 Screenshot Captured",
        _ => EventType
    };
}
