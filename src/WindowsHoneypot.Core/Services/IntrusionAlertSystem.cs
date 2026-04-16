using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Intrusion alert system that detects and reports security events
/// Integrates with FileMonitor to detect file-based intrusions
/// </summary>
public class IntrusionAlertSystem : IIntrusionAlertSystem, IDisposable
{
    private readonly ILogger<IntrusionAlertSystem> _logger;
    private readonly ConcurrentBag<AttackEvent> _attackEvents;
    private readonly List<IFileMonitor> _registeredMonitors;
    private readonly object _lock = new();
    private bool _isActive;
    private bool _disposed;

    // Pattern detection thresholds
    private const int PatternDetectionThreshold = 5; // Minimum attacks to detect pattern
    private const int RapidAttackThresholdSeconds = 60; // Rapid attack if within 60 seconds

    public IntrusionAlertSystem(ILogger<IntrusionAlertSystem> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _attackEvents = new ConcurrentBag<AttackEvent>();
        _registeredMonitors = new List<IFileMonitor>();
    }

    public int AttackCount => _attackEvents.Count;

    public IReadOnlyList<AttackEvent> AttackEvents => _attackEvents.ToList().AsReadOnly();

    public bool IsActive => _isActive;

    public event EventHandler<IntrusionDetectedEventArgs>? IntrusionDetected;
    public event EventHandler<AttackPatternDetectedEventArgs>? AttackPatternDetected;

    public void Start()
    {
        lock (_lock)
        {
            if (_isActive)
            {
                _logger.LogWarning("Intrusion alert system is already active");
                return;
            }

            _isActive = true;
            _logger.LogInformation("Intrusion alert system started");
        }
    }

    public void Stop()
    {
        lock (_lock)
        {
            if (!_isActive)
            {
                _logger.LogWarning("Intrusion alert system is not active");
                return;
            }

            _isActive = false;
            _logger.LogInformation("Intrusion alert system stopped");
        }
    }

    public void RegisterFileMonitor(IFileMonitor fileMonitor)
    {
        if (fileMonitor == null)
        {
            throw new ArgumentNullException(nameof(fileMonitor));
        }

        lock (_lock)
        {
            if (_registeredMonitors.Contains(fileMonitor))
            {
                _logger.LogWarning("File monitor is already registered");
                return;
            }

            // Subscribe to file monitor events
            fileMonitor.FileAccessed += OnFileAccessed;
            fileMonitor.FileModified += OnFileModified;
            fileMonitor.FileDeleted += OnFileDeleted;
            fileMonitor.FileRenamed += OnFileRenamed;

            _registeredMonitors.Add(fileMonitor);
            _logger.LogInformation("File monitor registered with intrusion alert system");
        }
    }

    public void TriggerAlert(AttackEvent attackEvent)
    {
        if (attackEvent == null)
        {
            throw new ArgumentNullException(nameof(attackEvent));
        }

        if (!_isActive)
        {
            _logger.LogWarning("Cannot trigger alert - intrusion alert system is not active");
            return;
        }

        ProcessAttackEvent(attackEvent);
    }

    public AttackPatternAnalysis AnalyzeAttackPatterns()
    {
        var events = _attackEvents.ToList();
        
        if (events.Count == 0)
        {
            return new AttackPatternAnalysis
            {
                TotalAttacks = 0,
                PatternDescription = "No attacks detected"
            };
        }

        var analysis = new AttackPatternAnalysis
        {
            TotalAttacks = events.Count,
            FirstAttackTime = events.Min(e => e.Timestamp),
            LastAttackTime = events.Max(e => e.Timestamp)
        };

        // Calculate time range
        if (analysis.FirstAttackTime.HasValue && analysis.LastAttackTime.HasValue)
        {
            analysis.AttackTimeRange = analysis.LastAttackTime.Value - analysis.FirstAttackTime.Value;
        }

        // Analyze attacks by type
        var attacksByType = events.GroupBy(e => e.EventType)
            .ToDictionary(g => g.Key, g => g.Count());
        
        analysis.AttacksByType = attacksByType;
        analysis.UniqueAttackTypes = attacksByType.Count;
        
        if (attacksByType.Any())
        {
            analysis.MostCommonAttackType = attacksByType
                .OrderByDescending(kvp => kvp.Value)
                .First()
                .Key;
        }

        // Calculate average time between attacks
        if (events.Count > 1)
        {
            var sortedEvents = events.OrderBy(e => e.Timestamp).ToList();
            var timeDifferences = new List<TimeSpan>();
            
            for (int i = 1; i < sortedEvents.Count; i++)
            {
                timeDifferences.Add(sortedEvents[i].Timestamp - sortedEvents[i - 1].Timestamp);
            }
            
            if (timeDifferences.Any())
            {
                analysis.AverageTimeBetweenAttacks = TimeSpan.FromTicks(
                    (long)timeDifferences.Average(ts => ts.Ticks));
            }
        }

        // Find most targeted files
        analysis.MostTargetedFiles = events
            .Where(e => !string.IsNullOrEmpty(e.TargetFile))
            .GroupBy(e => e.TargetFile)
            .OrderByDescending(g => g.Count())
            .Take(5)
            .Select(g => g.Key)
            .ToList();

        // Find most active processes
        analysis.MostActiveProcesses = events
            .Where(e => !string.IsNullOrEmpty(e.SourceProcess))
            .GroupBy(e => e.SourceProcess)
            .OrderByDescending(g => g.Count())
            .Take(5)
            .Select(g => g.Key)
            .ToList();

        // Detect coordinated attack patterns
        DetectCoordinatedAttack(analysis, events);

        // Assess overall severity
        analysis.OverallSeverity = AssessOverallSeverity(events);

        _logger.LogInformation(
            "Attack pattern analysis completed: {TotalAttacks} attacks, {UniqueTypes} unique types",
            analysis.TotalAttacks, analysis.UniqueAttackTypes);

        return analysis;
    }

    private void OnFileAccessed(object? sender, FileEventArgs e)
    {
        if (!_isActive) return;

        var attackEvent = new AttackEvent
        {
            EventType = AttackEventType.FileAccess,
            SourceProcess = e.ProcessName,
            ProcessId = e.ProcessId,
            TargetFile = e.FilePath,
            Timestamp = e.Timestamp,
            Description = $"File accessed: {e.FilePath} by {e.ProcessName} (PID: {e.ProcessId})",
            Severity = ThreatSeverity.Low
        };

        ProcessAttackEvent(attackEvent);
    }

    private void OnFileModified(object? sender, FileEventArgs e)
    {
        if (!_isActive) return;

        var attackEvent = new AttackEvent
        {
            EventType = AttackEventType.FileModification,
            SourceProcess = e.ProcessName,
            ProcessId = e.ProcessId,
            TargetFile = e.FilePath,
            Timestamp = e.Timestamp,
            Description = $"File modified: {e.FilePath} by {e.ProcessName} (PID: {e.ProcessId})",
            Severity = ThreatSeverity.Medium
        };

        ProcessAttackEvent(attackEvent);
    }

    private void OnFileDeleted(object? sender, FileEventArgs e)
    {
        if (!_isActive) return;

        var attackEvent = new AttackEvent
        {
            EventType = AttackEventType.FileDeletion,
            SourceProcess = e.ProcessName,
            ProcessId = e.ProcessId,
            TargetFile = e.FilePath,
            Timestamp = e.Timestamp,
            Description = $"File deleted: {e.FilePath} by {e.ProcessName} (PID: {e.ProcessId})",
            Severity = ThreatSeverity.High
        };

        ProcessAttackEvent(attackEvent);
    }

    private void OnFileRenamed(object? sender, FileRenamedEventArgs e)
    {
        if (!_isActive) return;

        var attackEvent = new AttackEvent
        {
            EventType = AttackEventType.FileRename,
            SourceProcess = e.ProcessName,
            ProcessId = e.ProcessId,
            TargetFile = e.NewName,
            Timestamp = e.Timestamp,
            Description = $"File renamed: {e.OldName} -> {e.NewName} by {e.ProcessName} (PID: {e.ProcessId})",
            Severity = ThreatSeverity.Medium,
            Metadata = new Dictionary<string, object>
            {
                { "OldName", e.OldName },
                { "NewName", e.NewName }
            }
        };

        ProcessAttackEvent(attackEvent);
    }

    private void ProcessAttackEvent(AttackEvent attackEvent)
    {
        // Add to collection
        _attackEvents.Add(attackEvent);

        // Log the event
        _logger.LogWarning(
            "Intrusion detected: {EventType} - {Description}",
            attackEvent.EventType, attackEvent.Description);

        // Fire intrusion detected event
        var eventArgs = new IntrusionDetectedEventArgs
        {
            AttackEvent = attackEvent,
            AlertMessage = GenerateAlertMessage(attackEvent),
            Severity = attackEvent.Severity
        };

        IntrusionDetected?.Invoke(this, eventArgs);

        // Check for attack patterns
        CheckForAttackPatterns();
    }

    private string GenerateAlertMessage(AttackEvent attackEvent)
    {
        return $"⚠️ INTRUSION DETECTED ⚠️\n\n" +
               $"Type: {attackEvent.EventType}\n" +
               $"Time: {attackEvent.Timestamp:yyyy-MM-dd HH:mm:ss}\n" +
               $"Process: {attackEvent.SourceProcess} (PID: {attackEvent.ProcessId})\n" +
               $"Target: {attackEvent.TargetFile}\n" +
               $"Severity: {attackEvent.Severity}\n\n" +
               $"Total Attacks: {AttackCount}";
    }

    private void CheckForAttackPatterns()
    {
        // Only check if we have enough events
        if (_attackEvents.Count < PatternDetectionThreshold)
        {
            return;
        }

        var recentEvents = _attackEvents
            .Where(e => e.Timestamp > DateTime.UtcNow.AddMinutes(-5))
            .OrderBy(e => e.Timestamp)
            .ToList();

        // Check for rapid successive attacks
        if (recentEvents.Count >= PatternDetectionThreshold)
        {
            var timeSpan = recentEvents.Last().Timestamp - recentEvents.First().Timestamp;
            
            if (timeSpan.TotalSeconds <= RapidAttackThresholdSeconds)
            {
                var analysis = AnalyzeAttackPatterns();
                analysis.CoordinatedAttackDetected = true;
                analysis.PatternDescription = $"Rapid attack pattern detected: {recentEvents.Count} attacks in {timeSpan.TotalSeconds:F1} seconds";

                _logger.LogWarning(
                    "Attack pattern detected: {PatternDescription}",
                    analysis.PatternDescription);

                var patternEventArgs = new AttackPatternDetectedEventArgs
                {
                    Analysis = analysis,
                    PatternDescription = analysis.PatternDescription,
                    DetectedAt = DateTime.UtcNow
                };

                AttackPatternDetected?.Invoke(this, patternEventArgs);
            }
        }
    }

    private void DetectCoordinatedAttack(AttackPatternAnalysis analysis, List<AttackEvent> events)
    {
        if (events.Count < PatternDetectionThreshold)
        {
            return;
        }

        // Check for multiple attack types in short time
        var recentEvents = events
            .Where(e => e.Timestamp > DateTime.UtcNow.AddMinutes(-5))
            .ToList();

        if (recentEvents.Count >= PatternDetectionThreshold)
        {
            var uniqueTypes = recentEvents.Select(e => e.EventType).Distinct().Count();
            
            if (uniqueTypes >= 3)
            {
                analysis.CoordinatedAttackDetected = true;
                analysis.PatternDescription = $"Coordinated attack detected: {uniqueTypes} different attack types in recent activity";
            }
        }

        // Check for same process attacking multiple files
        var processCounts = events
            .GroupBy(e => e.SourceProcess)
            .Where(g => g.Count() >= 3)
            .ToList();

        if (processCounts.Any())
        {
            var topProcess = processCounts.OrderByDescending(g => g.Count()).First();
            analysis.CoordinatedAttackDetected = true;
            analysis.PatternDescription += $"\nProcess '{topProcess.Key}' performed {topProcess.Count()} attacks";
        }
    }

    private ThreatSeverity AssessOverallSeverity(List<AttackEvent> events)
    {
        if (events.Count == 0)
        {
            return ThreatSeverity.Low;
        }

        // Count high severity events
        var criticalCount = events.Count(e => e.Severity == ThreatSeverity.Critical);
        var highCount = events.Count(e => e.Severity == ThreatSeverity.High);
        var mediumCount = events.Count(e => e.Severity == ThreatSeverity.Medium);

        if (criticalCount > 0 || highCount >= 3)
        {
            return ThreatSeverity.Critical;
        }

        if (highCount > 0 || mediumCount >= 5)
        {
            return ThreatSeverity.High;
        }

        if (mediumCount > 0 || events.Count >= 10)
        {
            return ThreatSeverity.Medium;
        }

        return ThreatSeverity.Low;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        Stop();

        // Unsubscribe from all monitors
        lock (_lock)
        {
            foreach (var monitor in _registeredMonitors)
            {
                try
                {
                    monitor.FileAccessed -= OnFileAccessed;
                    monitor.FileModified -= OnFileModified;
                    monitor.FileDeleted -= OnFileDeleted;
                    monitor.FileRenamed -= OnFileRenamed;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error unsubscribing from file monitor");
                }
            }

            _registeredMonitors.Clear();
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
