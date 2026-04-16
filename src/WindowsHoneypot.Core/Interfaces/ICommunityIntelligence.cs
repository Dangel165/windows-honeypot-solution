using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Interfaces;

/// <summary>
/// Share and receive threat intelligence with other users
/// </summary>
public interface ICommunityIntelligence
{
    /// <summary>
    /// Shares threat data with the community
    /// </summary>
    /// <param name="data">Threat data to share</param>
    Task ShareThreatDataAsync(ThreatData data);

    /// <summary>
    /// Gets the latest threat feed from the community
    /// </summary>
    /// <returns>List of threat indicators</returns>
    Task<List<ThreatIndicator>> GetThreatFeedAsync();

    /// <summary>
    /// Updates the local blacklist with community threat data
    /// </summary>
    Task UpdateLocalBlacklistAsync();

    /// <summary>
    /// Gets global threat statistics
    /// </summary>
    /// <returns>Global threat statistics</returns>
    ThreatStatistics GetGlobalStatistics();

    /// <summary>
    /// Gets regional threat statistics for a specific region
    /// Requirement 15.7: Regional statistics
    /// </summary>
    /// <param name="region">Region identifier</param>
    /// <returns>Regional threat statistics</returns>
    Task<RegionalThreatStatistics> GetRegionalStatisticsAsync(string region);

    /// <summary>
    /// Analyzes attack patterns from local blacklist
    /// Requirement 15.7: Attack pattern analysis
    /// </summary>
    /// <returns>Threat indicator analysis results</returns>
    ThreatIndicatorAnalysis AnalyzeAttackPatterns();

    /// <summary>
    /// Event fired when new threat intelligence is received
    /// </summary>
    event EventHandler<ThreatIntelligenceReceivedEventArgs>? ThreatIntelligenceReceived;
}