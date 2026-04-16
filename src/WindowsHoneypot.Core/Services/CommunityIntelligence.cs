using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Community Intelligence system for threat data sharing
/// Requirement 15: Threat sharing ecosystem and community intelligence
/// </summary>
public class CommunityIntelligence : ICommunityIntelligence
{
    private readonly ILogger<CommunityIntelligence> _logger;
    private readonly HttpClient _httpClient;
    private readonly CommunityIntelligenceConfiguration _config;
    private readonly string _localBlacklistPath;
    private readonly Queue<ThreatData> _offlineQueue;
    private ThreatStatistics _cachedStatistics;
    private DateTime _lastStatisticsUpdate;

    public event EventHandler<ThreatIntelligenceReceivedEventArgs>? ThreatIntelligenceReceived;

    public CommunityIntelligence(
        ILogger<CommunityIntelligence> logger,
        CommunityIntelligenceConfiguration config)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _config = config ?? throw new ArgumentNullException(nameof(config));
        
        _httpClient = new HttpClient
        {
            BaseAddress = new Uri(_config.CloudServerUrl),
            Timeout = TimeSpan.FromSeconds(30)
        };

        // Add API key to headers if configured
        if (!string.IsNullOrEmpty(_config.ApiKey))
        {
            _httpClient.DefaultRequestHeaders.Add("X-API-Key", _config.ApiKey);
        }

        // Set up local storage paths
        var appDataPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "WindowsHoneypot",
            "CommunityIntelligence"
        );
        Directory.CreateDirectory(appDataPath);

        _localBlacklistPath = Path.Combine(appDataPath, "blacklist.json");
        _offlineQueue = new Queue<ThreatData>();
        _cachedStatistics = new ThreatStatistics();
        _lastStatisticsUpdate = DateTime.MinValue;

        _logger.LogInformation("Community Intelligence initialized with server: {ServerUrl}", 
            _config.CloudServerUrl);
    }

    /// <summary>
    /// Shares threat data with the community
    /// Requirement 15.1: Share attacker IP and attack patterns to cloud server
    /// Requirement 15.4: Anonymize user personal information
    /// </summary>
    public async Task ShareThreatDataAsync(ThreatData data)
    {
        if (!_config.Enabled || !_config.ShareAttackData)
        {
            _logger.LogDebug("Threat data sharing is disabled");
            return;
        }

        try
        {
            // Anonymize the threat data before sharing
            var anonymizedData = AnonymizeThreatData(data);

            // Calculate integrity hash
            anonymizedData.DataHash = CalculateDataHash(anonymizedData);

            _logger.LogInformation("Sharing threat data: {ThreatId} from IP {AttackerIP}", 
                anonymizedData.ThreatId, anonymizedData.AttackerIP);

            // Try to send to cloud server
            var response = await _httpClient.PostAsJsonAsync("/api/threats", anonymizedData);

            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("Successfully shared threat data: {ThreatId}", 
                    anonymizedData.ThreatId);
                
                // Process any queued offline data
                await ProcessOfflineQueueAsync();
            }
            else
            {
                _logger.LogWarning("Failed to share threat data: {StatusCode}", 
                    response.StatusCode);
                
                // Queue for later if offline mode is enabled
                if (_config.EnableOfflineMode)
                {
                    _offlineQueue.Enqueue(anonymizedData);
                    _logger.LogInformation("Queued threat data for offline synchronization");
                }
            }
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Network error while sharing threat data");
            
            // Queue for later if offline mode is enabled
            if (_config.EnableOfflineMode)
            {
                _offlineQueue.Enqueue(data);
                _logger.LogInformation("Queued threat data for offline synchronization");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sharing threat data");
        }
    }

    /// <summary>
    /// Gets the latest threat feed from the community
    /// Requirement 15.2: Receive threat information from other users in real-time
    /// </summary>
    public async Task<List<ThreatIndicator>> GetThreatFeedAsync()
    {
        if (!_config.Enabled || !_config.ReceiveThreatFeeds)
        {
            _logger.LogDebug("Threat feed reception is disabled");
            return new List<ThreatIndicator>();
        }

        try
        {
            _logger.LogInformation("Fetching threat feed from community");

            var response = await _httpClient.GetAsync("/api/threats/feed");

            if (response.IsSuccessStatusCode)
            {
                var indicators = await response.Content.ReadFromJsonAsync<List<ThreatIndicator>>()
                    ?? new List<ThreatIndicator>();

                _logger.LogInformation("Received {Count} threat indicators from community", 
                    indicators.Count);

                // Fire event for new threat intelligence
                ThreatIntelligenceReceived?.Invoke(this, new ThreatIntelligenceReceivedEventArgs
                {
                    ThreatIndicators = indicators,
                    NewIndicatorCount = indicators.Count,
                    ReceivedAt = DateTime.UtcNow
                });

                return indicators;
            }
            else
            {
                _logger.LogWarning("Failed to fetch threat feed: {StatusCode}", 
                    response.StatusCode);
                
                // Return cached data if available in offline mode
                if (_config.EnableOfflineMode)
                {
                    return LoadCachedThreatFeed();
                }
                
                return new List<ThreatIndicator>();
            }
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Network error while fetching threat feed");
            
            // Return cached data if available in offline mode
            if (_config.EnableOfflineMode)
            {
                return LoadCachedThreatFeed();
            }
            
            return new List<ThreatIndicator>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching threat feed");
            return new List<ThreatIndicator>();
        }
    }

    /// <summary>
    /// Updates the local blacklist with community threat data
    /// Requirement 15.3: Automatically update blacklist from threat feeds
    /// Requirement 15.5: Threat scoring system based on confidence levels
    /// </summary>
    public async Task UpdateLocalBlacklistAsync()
    {
        if (!_config.Enabled || !_config.AutoUpdateBlacklist)
        {
            _logger.LogDebug("Automatic blacklist update is disabled");
            return;
        }

        try
        {
            _logger.LogInformation("Updating local blacklist from community threat feed");

            var indicators = await GetThreatFeedAsync();

            if (indicators.Count == 0)
            {
                _logger.LogInformation("No threat indicators to update");
                return;
            }

            // Load existing blacklist
            var blacklist = LoadLocalBlacklist();

            // Add new indicators with threat scoring
            int addedCount = 0;
            int updatedCount = 0;
            
            foreach (var indicator in indicators)
            {
                // Calculate threat score based on confidence and severity
                var threatScore = CalculateThreatScore(indicator);
                
                // Apply configurable confidence threshold
                var minConfidence = _config.MinimumConfidenceThreshold;
                if (indicator.Confidence >= minConfidence)
                {
                    var key = $"{indicator.Type}:{indicator.Value}";
                    
                    if (!blacklist.ContainsKey(key))
                    {
                        // Add new indicator
                        blacklist[key] = indicator;
                        addedCount++;
                        
                        _logger.LogDebug("Added threat indicator: {Type}={Value}, Score={Score}, Confidence={Confidence}",
                            indicator.Type, indicator.Value, threatScore, indicator.Confidence);
                    }
                    else
                    {
                        // Update existing indicator if new data has higher confidence
                        var existing = blacklist[key];
                        if (indicator.Confidence > existing.Confidence || 
                            indicator.LastSeen > existing.LastSeen)
                        {
                            blacklist[key] = indicator;
                            updatedCount++;
                            
                            _logger.LogDebug("Updated threat indicator: {Type}={Value}, NewConfidence={NewConf}, OldConfidence={OldConf}",
                                indicator.Type, indicator.Value, indicator.Confidence, existing.Confidence);
                        }
                    }
                }
            }

            // Remove expired indicators (older than 30 days)
            var expirationDate = DateTime.UtcNow.AddDays(-30);
            var expiredKeys = blacklist
                .Where(kvp => kvp.Value.LastSeen < expirationDate)
                .Select(kvp => kvp.Key)
                .ToList();
            
            foreach (var key in expiredKeys)
            {
                blacklist.Remove(key);
            }

            // Save updated blacklist
            SaveLocalBlacklist(blacklist);

            _logger.LogInformation(
                "Updated local blacklist: {AddedCount} new, {UpdatedCount} updated, {ExpiredCount} expired, Total={TotalCount}",
                addedCount, updatedCount, expiredKeys.Count, blacklist.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating local blacklist");
        }
    }

    /// <summary>
    /// Calculates threat score based on confidence and severity
    /// Requirement 15.5: Threat scoring system based on confidence levels
    /// </summary>
    private int CalculateThreatScore(ThreatIndicator indicator)
    {
        // Base score from confidence (0-100)
        var score = indicator.Confidence;

        // Severity multiplier
        var severityMultiplier = indicator.Severity switch
        {
            ThreatSeverity.Critical => 1.5,
            ThreatSeverity.High => 1.3,
            ThreatSeverity.Medium => 1.0,
            ThreatSeverity.Low => 0.7,
            _ => 1.0
        };

        // Age factor (newer threats get higher scores)
        var age = (DateTime.UtcNow - indicator.FirstSeen).TotalDays;
        var ageFactor = age switch
        {
            < 1 => 1.2,      // Very recent
            < 7 => 1.1,      // Recent
            < 30 => 1.0,     // Current
            < 90 => 0.9,     // Aging
            _ => 0.8         // Old
        };

        // Calculate final score (capped at 100)
        var finalScore = (int)Math.Min(100, score * severityMultiplier * ageFactor);
        
        return finalScore;
    }

    /// <summary>
    /// Gets global threat statistics
    /// Requirement 15.6: Visualize global threat trends on dashboard
    /// Requirement 15.7: Provide regional and attack-type threat statistics
    /// Requirement 15.8: Support offline mode with cached threat data
    /// </summary>
    public ThreatStatistics GetGlobalStatistics()
    {
        // Return cached statistics if recent (within 5 minutes)
        if ((DateTime.UtcNow - _lastStatisticsUpdate).TotalMinutes < 5)
        {
            return _cachedStatistics;
        }

        try
        {
            _logger.LogInformation("Fetching global threat statistics");

            // Synchronous call - fire and forget for async update
            _ = Task.Run(async () =>
            {
                try
                {
                    var response = await _httpClient.GetAsync("/api/threats/statistics");

                    if (response.IsSuccessStatusCode)
                    {
                        var statistics = await response.Content.ReadFromJsonAsync<ThreatStatistics>();
                        if (statistics != null)
                        {
                            _cachedStatistics = statistics;
                            _lastStatisticsUpdate = DateTime.UtcNow;
                            
                            // Save to cache for offline mode
                            SaveStatisticsCache(statistics);
                            
                            _logger.LogInformation("Updated global threat statistics: {TotalThreats} total, {Recent} in 24h",
                                statistics.TotalThreats, statistics.ThreatsLast24Hours);
                        }
                    }
                    else
                    {
                        // Load from cache if server unavailable
                        if (_config.EnableOfflineMode)
                        {
                            var cached = LoadStatisticsCache();
                            if (cached != null)
                            {
                                _cachedStatistics = cached;
                                _logger.LogInformation("Loaded threat statistics from cache (offline mode)");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error fetching global statistics");
                    
                    // Load from cache on error
                    if (_config.EnableOfflineMode)
                    {
                        var cached = LoadStatisticsCache();
                        if (cached != null)
                        {
                            _cachedStatistics = cached;
                            _logger.LogInformation("Loaded threat statistics from cache (error fallback)");
                        }
                    }
                }
            });

            return _cachedStatistics;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting global statistics");
            return _cachedStatistics;
        }
    }

    /// <summary>
    /// Gets regional threat statistics for a specific region
    /// Requirement 15.7: Provide regional and attack-type threat statistics
    /// </summary>
    public async Task<RegionalThreatStatistics> GetRegionalStatisticsAsync(string region)
    {
        if (!_config.Enabled)
        {
            _logger.LogDebug("Community intelligence is disabled");
            return new RegionalThreatStatistics { Region = region };
        }

        try
        {
            _logger.LogInformation("Fetching regional threat statistics for: {Region}", region);

            var response = await _httpClient.GetAsync($"/api/threats/statistics/region/{Uri.EscapeDataString(region)}");

            if (response.IsSuccessStatusCode)
            {
                var statistics = await response.Content.ReadFromJsonAsync<RegionalThreatStatistics>();
                if (statistics != null)
                {
                    _logger.LogInformation("Received regional statistics for {Region}: {ThreatCount} threats",
                        region, statistics.ThreatCount);
                    return statistics;
                }
            }
            else
            {
                _logger.LogWarning("Failed to fetch regional statistics: {StatusCode}", response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching regional statistics for {Region}", region);
        }

        return new RegionalThreatStatistics { Region = region };
    }

    /// <summary>
    /// Analyzes attack patterns from local blacklist
    /// Requirement 15.7: Attack pattern analysis
    /// </summary>
    public ThreatIndicatorAnalysis AnalyzeAttackPatterns()
    {
        try
        {
            var blacklist = LoadLocalBlacklist();
            var analysis = new ThreatIndicatorAnalysis
            {
                TotalIndicators = blacklist.Count,
                AnalyzedAt = DateTime.UtcNow
            };

            // Analyze by type
            analysis.IndicatorsByType = blacklist.Values
                .GroupBy(i => i.Type)
                .ToDictionary(g => g.Key, g => g.Count());

            // Analyze by severity
            analysis.IndicatorsBySeverity = blacklist.Values
                .GroupBy(i => i.Severity)
                .ToDictionary(g => g.Key, g => g.Count());

            // Find most common tags
            var allTags = blacklist.Values
                .SelectMany(i => i.Tags)
                .GroupBy(t => t)
                .OrderByDescending(g => g.Count())
                .Take(10)
                .ToDictionary(g => g.Key, g => g.Count());
            
            analysis.CommonTags = allTags;

            // Calculate average confidence
            if (blacklist.Count > 0)
            {
                analysis.AverageConfidence = (int)blacklist.Values.Average(i => i.Confidence);
            }

            // Find high-risk indicators (confidence >= 90)
            analysis.HighRiskIndicatorCount = blacklist.Values.Count(i => i.Confidence >= 90);

            _logger.LogDebug("Attack pattern analysis: {Total} indicators, {HighRisk} high-risk",
                analysis.TotalIndicators, analysis.HighRiskIndicatorCount);

            return analysis;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing attack patterns");
            return new ThreatIndicatorAnalysis();
        }
    }

    /// <summary>
    /// Anonymizes threat data to protect user privacy
    /// Requirement 15.4: Anonymize user personal information when sharing attack data
    /// Requirement 15.9: Respect user-configured sharing level
    /// </summary>
    private ThreatData AnonymizeThreatData(ThreatData data)
    {
        var anonymized = new ThreatData
        {
            ThreatId = data.ThreatId,
            AttackerIP = data.AttackerIP,
            DetectionTime = data.DetectionTime,
            Severity = data.Severity,
            GeographicLocation = AnonymizeLocation(data.GeographicLocation),
            Version = data.Version,
            // Generate anonymous source ID based on machine hash
            SourceId = GenerateAnonymousSourceId()
        };

        // Apply sharing level filtering
        switch (_config.SharingLevel)
        {
            case ThreatSharingLevel.Minimal:
                // Share only IP and basic severity
                anonymized.AttackPatterns = new List<string>();
                anonymized.Indicators = new Dictionary<string, string>();
                break;

            case ThreatSharingLevel.Standard:
                // Share IP, attack types, and basic patterns
                anonymized.AttackPatterns = data.AttackPatterns.Take(5).ToList();
                anonymized.Indicators = new Dictionary<string, string>();
                break;

            case ThreatSharingLevel.Detailed:
                // Share attack patterns and filtered indicators
                anonymized.AttackPatterns = new List<string>(data.AttackPatterns);
                anonymized.Indicators = FilterIndicators(data.Indicators);
                break;

            case ThreatSharingLevel.Full:
                // Share all information (still anonymized)
                anonymized.AttackPatterns = new List<string>(data.AttackPatterns);
                anonymized.Indicators = FilterIndicators(data.Indicators);
                break;

            default:
                anonymized.AttackPatterns = new List<string>(data.AttackPatterns);
                anonymized.Indicators = FilterIndicators(data.Indicators);
                break;
        }

        return anonymized;
    }

    /// <summary>
    /// Filters indicators to remove personally identifiable information
    /// </summary>
    private Dictionary<string, string> FilterIndicators(Dictionary<string, string> indicators)
    {
        var filtered = new Dictionary<string, string>(indicators);

        // Remove any potentially identifying information
        var keysToRemove = new List<string>();
        foreach (var key in filtered.Keys)
        {
            if (key.Contains("username", StringComparison.OrdinalIgnoreCase) ||
                key.Contains("hostname", StringComparison.OrdinalIgnoreCase) ||
                key.Contains("email", StringComparison.OrdinalIgnoreCase) ||
                key.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                key.Contains("credential", StringComparison.OrdinalIgnoreCase))
            {
                keysToRemove.Add(key);
            }
        }

        foreach (var key in keysToRemove)
        {
            filtered.Remove(key);
        }

        return filtered;
    }

    /// <summary>
    /// Anonymizes geographic location to country level only
    /// </summary>
    private string AnonymizeLocation(string location)
    {
        if (string.IsNullOrEmpty(location))
            return string.Empty;

        // Extract only country code or country name
        var parts = location.Split(',');
        return parts.Length > 0 ? parts[0].Trim() : location;
    }

    /// <summary>
    /// Generates an anonymous source ID based on machine characteristics
    /// </summary>
    private string GenerateAnonymousSourceId()
    {
        try
        {
            // Use machine name and OS version to create a consistent but anonymous ID
            var machineInfo = $"{Environment.MachineName}_{Environment.OSVersion}";
            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(machineInfo));
            return Convert.ToHexString(hashBytes)[..16]; // First 16 characters
        }
        catch
        {
            return Guid.NewGuid().ToString("N")[..16];
        }
    }

    /// <summary>
    /// Calculates integrity hash for threat data
    /// </summary>
    private string CalculateDataHash(ThreatData data)
    {
        try
        {
            var json = JsonSerializer.Serialize(data, new JsonSerializerOptions
            {
                WriteIndented = false
            });

            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(json));
            return Convert.ToHexString(hashBytes);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error calculating data hash");
            return string.Empty;
        }
    }

    /// <summary>
    /// Processes queued offline threat data
    /// Requirement 15.8: Ensure basic defense functions work in offline mode
    /// </summary>
    private async Task ProcessOfflineQueueAsync()
    {
        if (_offlineQueue.Count == 0)
            return;

        _logger.LogInformation("Processing {Count} queued offline threat data", 
            _offlineQueue.Count);

        var processedCount = 0;
        var failedCount = 0;

        while (_offlineQueue.Count > 0 && processedCount < 10) // Limit batch size
        {
            var data = _offlineQueue.Dequeue();
            
            try
            {
                var response = await _httpClient.PostAsJsonAsync("/api/threats", data);
                
                if (response.IsSuccessStatusCode)
                {
                    processedCount++;
                }
                else
                {
                    // Re-queue if failed
                    _offlineQueue.Enqueue(data);
                    failedCount++;
                    break; // Stop processing if server is having issues
                }
            }
            catch
            {
                // Re-queue if failed
                _offlineQueue.Enqueue(data);
                failedCount++;
                break; // Stop processing on network error
            }
        }

        _logger.LogInformation("Processed {ProcessedCount} offline items, {FailedCount} failed", 
            processedCount, failedCount);
    }

    /// <summary>
    /// Loads the local blacklist from disk
    /// </summary>
    private Dictionary<string, ThreatIndicator> LoadLocalBlacklist()
    {
        try
        {
            if (File.Exists(_localBlacklistPath))
            {
                var json = File.ReadAllText(_localBlacklistPath);
                return JsonSerializer.Deserialize<Dictionary<string, ThreatIndicator>>(json)
                    ?? new Dictionary<string, ThreatIndicator>();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading local blacklist");
        }

        return new Dictionary<string, ThreatIndicator>();
    }

    /// <summary>
    /// Saves the local blacklist to disk
    /// </summary>
    private void SaveLocalBlacklist(Dictionary<string, ThreatIndicator> blacklist)
    {
        try
        {
            var json = JsonSerializer.Serialize(blacklist, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            File.WriteAllText(_localBlacklistPath, json);
            _logger.LogDebug("Saved local blacklist with {Count} indicators", blacklist.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error saving local blacklist");
        }
    }

    /// <summary>
    /// Loads cached threat feed from disk
    /// </summary>
    private List<ThreatIndicator> LoadCachedThreatFeed()
    {
        try
        {
            var blacklist = LoadLocalBlacklist();
            return blacklist.Values.ToList();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading cached threat feed");
            return new List<ThreatIndicator>();
        }
    }

    /// <summary>
    /// Saves threat statistics to cache for offline mode
    /// Requirement 15.8: Support offline mode with cached threat data
    /// </summary>
    private void SaveStatisticsCache(ThreatStatistics statistics)
    {
        try
        {
            var cachePath = Path.Combine(
                Path.GetDirectoryName(_localBlacklistPath) ?? string.Empty,
                "statistics_cache.json"
            );

            var json = JsonSerializer.Serialize(statistics, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            File.WriteAllText(cachePath, json);
            _logger.LogDebug("Saved threat statistics to cache");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error saving statistics cache");
        }
    }

    /// <summary>
    /// Loads threat statistics from cache
    /// Requirement 15.8: Support offline mode with cached threat data
    /// </summary>
    private ThreatStatistics? LoadStatisticsCache()
    {
        try
        {
            var cachePath = Path.Combine(
                Path.GetDirectoryName(_localBlacklistPath) ?? string.Empty,
                "statistics_cache.json"
            );

            if (File.Exists(cachePath))
            {
                var json = File.ReadAllText(cachePath);
                return JsonSerializer.Deserialize<ThreatStatistics>(json);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading statistics cache");
        }

        return null;
    }
}
