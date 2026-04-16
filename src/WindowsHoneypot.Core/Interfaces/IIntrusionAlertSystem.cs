using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Interfaces;

/// <summary>
/// System for detecting intrusions and generating alerts
/// </summary>
public interface IIntrusionAlertSystem
{
    /// <summary>
    /// Gets the total number of detected attacks
    /// </summary>
    int AttackCount { get; }

    /// <summary>
    /// Gets the list of all detected attack events
    /// </summary>
    IReadOnlyList<AttackEvent> AttackEvents { get; }

    /// <summary>
    /// Gets whether the alert system is currently active
    /// </summary>
    bool IsActive { get; }

    /// <summary>
    /// Starts the intrusion alert system
    /// </summary>
    void Start();

    /// <summary>
    /// Stops the intrusion alert system
    /// </summary>
    void Stop();

    /// <summary>
    /// Registers a file monitor to watch for intrusions
    /// </summary>
    /// <param name="fileMonitor">The file monitor to register</param>
    void RegisterFileMonitor(IFileMonitor fileMonitor);

    /// <summary>
    /// Manually triggers an intrusion alert
    /// </summary>
    /// <param name="attackEvent">The attack event to alert on</param>
    void TriggerAlert(AttackEvent attackEvent);

    /// <summary>
    /// Analyzes attack patterns and returns a summary
    /// </summary>
    /// <returns>Attack pattern analysis summary</returns>
    AttackPatternAnalysis AnalyzeAttackPatterns();

    /// <summary>
    /// Event fired when an intrusion is detected
    /// </summary>
    event EventHandler<IntrusionDetectedEventArgs>? IntrusionDetected;

    /// <summary>
    /// Event fired when attack patterns are detected
    /// </summary>
    event EventHandler<AttackPatternDetectedEventArgs>? AttackPatternDetected;
}
