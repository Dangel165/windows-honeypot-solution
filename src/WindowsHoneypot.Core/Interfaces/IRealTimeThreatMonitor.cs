using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Interfaces;

/// <summary>
/// Real-time threat monitoring interface for host system protection
/// Continuously monitors the host PC for threats using honeypot intelligence
/// </summary>
public interface IRealTimeThreatMonitor
{
    /// <summary>
    /// Start real-time protection on the host system
    /// </summary>
    Task StartProtectionAsync();

    /// <summary>
    /// Stop real-time protection
    /// </summary>
    Task StopProtectionAsync();

    /// <summary>
    /// Register a threat pattern from honeypot intelligence
    /// </summary>
    /// <param name="pattern">Threat pattern to register</param>
    void RegisterThreatPattern(ThreatPattern pattern);

    /// <summary>
    /// Remove a threat pattern from the database
    /// </summary>
    /// <param name="patternId">Pattern ID to remove</param>
    void UnregisterThreatPattern(string patternId);

    /// <summary>
    /// Get all registered threat patterns
    /// </summary>
    List<ThreatPattern> GetThreatPatterns();

    /// <summary>
    /// Event raised when a threat is detected on the host system
    /// </summary>
    event EventHandler<ThreatDetectedEventArgs> ThreatDetected;

    /// <summary>
    /// Event raised when a file operation is blocked
    /// </summary>
    event EventHandler<FileOperationBlockedEventArgs> FileOperationBlocked;

    /// <summary>
    /// Event raised when a process creation is blocked
    /// </summary>
    event EventHandler<ProcessBlockedEventArgs> ProcessBlocked;

    /// <summary>
    /// Event raised when a network connection is blocked
    /// </summary>
    event EventHandler<NetworkBlockedEventArgs> NetworkBlocked;

    /// <summary>
    /// Get current protection status
    /// </summary>
    ProtectionStatus GetProtectionStatus();

    /// <summary>
    /// Get protection statistics
    /// </summary>
    ProtectionStatistics GetStatistics();

    /// <summary>
    /// Check if a file is safe based on threat patterns
    /// </summary>
    Task<ThreatAssessment> AssessFileAsync(string filePath);

    /// <summary>
    /// Check if a process is safe based on threat patterns
    /// </summary>
    Task<ThreatAssessment> AssessProcessAsync(int processId);

    /// <summary>
    /// Check if a network connection is safe
    /// </summary>
    Task<ThreatAssessment> AssessNetworkConnectionAsync(string remoteAddress, int port);
}
