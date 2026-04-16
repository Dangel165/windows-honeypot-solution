using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Interfaces;

/// <summary>
/// Behavioral analysis engine for detecting advanced threats
/// Detects time-delayed, VM-aware, and hardware-level attacks
/// </summary>
public interface IBehavioralAnalysisEngine
{
    /// <summary>
    /// Analyze a process for suspicious behavior
    /// </summary>
    Task<ThreatAssessment> AnalyzeProcessAsync(int processId);

    /// <summary>
    /// Detect time-delayed malware that activates later
    /// </summary>
    Task<bool> DetectTimeDelayedThreatAsync(string filePath);

    /// <summary>
    /// Detect VM-aware malware that evades virtual environments
    /// </summary>
    Task<bool> DetectVMAwareMalwareAsync(string filePath);

    /// <summary>
    /// Detect hardware-level attacks (BIOS/firmware manipulation)
    /// </summary>
    Task<bool> DetectHardwareAttackAsync();

    /// <summary>
    /// Update the behavioral model with new training data
    /// </summary>
    void UpdateBehavioralModel(ThreatData trainingData);

    /// <summary>
    /// Get list of suspicious activities detected
    /// </summary>
    List<BehavioralIndicator> GetSuspiciousActivities();

    /// <summary>
    /// Analyze file behavior over time
    /// </summary>
    Task<BehavioralAnalysisResult> AnalyzeFileBehaviorAsync(string filePath, TimeSpan monitoringPeriod);

    /// <summary>
    /// Check for sandbox evasion techniques
    /// </summary>
    Task<bool> DetectSandboxEvasionAsync(int processId);

    /// <summary>
    /// Analyze scheduled tasks for malicious patterns
    /// </summary>
    Task<List<BehavioralIndicator>> AnalyzeScheduledTasksAsync();

    /// <summary>
    /// Analyze registry run keys for persistence mechanisms
    /// </summary>
    Task<List<BehavioralIndicator>> AnalyzeRegistryPersistenceAsync();

    /// <summary>
    /// Event raised when suspicious behavior is detected
    /// </summary>
    event EventHandler<BehavioralIndicatorEventArgs> SuspiciousBehaviorDetected;
}
