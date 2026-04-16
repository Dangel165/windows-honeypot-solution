using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Interfaces;

/// <summary>
/// Real-time detection of file system manipulation attempts
/// </summary>
public interface IFileMonitor
{
    /// <summary>
    /// Starts monitoring the specified path for file system events
    /// </summary>
    /// <param name="path">Path to monitor</param>
    void StartMonitoring(string path);

    /// <summary>
    /// Stops all file system monitoring
    /// </summary>
    void StopMonitoring();

    /// <summary>
    /// Gets the current monitoring status
    /// </summary>
    /// <returns>True if monitoring is active, false otherwise</returns>
    bool IsMonitoring { get; }

    /// <summary>
    /// Gets the list of currently monitored paths
    /// </summary>
    IReadOnlyList<string> MonitoredPaths { get; }

    /// <summary>
    /// Event fired when a file is accessed
    /// </summary>
    event EventHandler<FileEventArgs>? FileAccessed;

    /// <summary>
    /// Event fired when a file is modified
    /// </summary>
    event EventHandler<FileEventArgs>? FileModified;

    /// <summary>
    /// Event fired when a file is deleted
    /// </summary>
    event EventHandler<FileEventArgs>? FileDeleted;

    /// <summary>
    /// Event fired when a file is renamed
    /// </summary>
    event EventHandler<FileRenamedEventArgs>? FileRenamed;
}