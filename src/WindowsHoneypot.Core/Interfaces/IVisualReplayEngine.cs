using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Interfaces;

/// <summary>
/// Record and visualize attacker activities for analysis
/// </summary>
public interface IVisualReplayEngine
{
    /// <summary>
    /// Starts recording attacker activities
    /// </summary>
    void StartRecording();

    /// <summary>
    /// Stops recording attacker activities
    /// </summary>
    void StopRecording();

    /// <summary>
    /// Generates replay data from recorded activities
    /// </summary>
    /// <returns>Replay data containing all recorded activities</returns>
    Task<ReplayData> GenerateReplayAsync();

    /// <summary>
    /// Exports replay data to PDF format
    /// </summary>
    /// <param name="filePath">Path to save the PDF file</param>
    Task ExportToPdfAsync(string filePath);

    /// <summary>
    /// Generates a timeline visualization of all activities
    /// </summary>
    /// <returns>Timeline data structure for visualization</returns>
    Task<TimelineVisualization> GenerateTimelineAsync();

    /// <summary>
    /// Exports replay as video-style playback data
    /// </summary>
    /// <param name="outputPath">Path to save the playback data</param>
    Task ExportVideoStylePlaybackAsync(string outputPath);

    /// <summary>
    /// Generates a non-technical summary report for general users
    /// </summary>
    /// <returns>User-friendly summary of attack activities</returns>
    Task<string> GenerateNonTechnicalSummaryAsync();

    /// <summary>
    /// Gets the current recording status
    /// </summary>
    bool IsRecording { get; }
}