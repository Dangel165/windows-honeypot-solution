using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Persistent threat pattern database with save/load capabilities
/// Stores threat patterns learned from honeypot intelligence
/// </summary>
public class ThreatPatternDatabase
{
    private readonly ILogger<ThreatPatternDatabase> _logger;
    private readonly string _databasePath;
    private readonly Dictionary<string, ThreatPattern> _patterns;
    private readonly object _lock = new();
    private readonly JsonSerializerOptions _jsonOptions;

    public ThreatPatternDatabase(ILogger<ThreatPatternDatabase> logger, string? databasePath = null)
    {
        _logger = logger;
        _databasePath = databasePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "WindowsHoneypot",
            "ThreatPatterns",
            "patterns.db");
        
        _patterns = new Dictionary<string, ThreatPattern>();
        _jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNameCaseInsensitive = true
        };

        EnsureDatabaseDirectory();
    }

    /// <summary>
    /// Add or update a threat pattern in the database
    /// </summary>
    public void AddOrUpdatePattern(ThreatPattern pattern)
    {
        if (pattern == null)
            throw new ArgumentNullException(nameof(pattern));

        lock (_lock)
        {
            pattern.LastUpdated = DateTime.UtcNow;
            
            if (_patterns.ContainsKey(pattern.PatternId))
            {
                _logger.LogInformation("Updating threat pattern: {PatternName} (ID: {PatternId})", 
                    pattern.Name, pattern.PatternId);
            }
            else
            {
                _logger.LogInformation("Adding new threat pattern: {PatternName} (ID: {PatternId})", 
                    pattern.Name, pattern.PatternId);
            }

            _patterns[pattern.PatternId] = pattern;
        }
    }

    /// <summary>
    /// Remove a threat pattern from the database
    /// </summary>
    public bool RemovePattern(string patternId)
    {
        lock (_lock)
        {
            if (_patterns.Remove(patternId))
            {
                _logger.LogInformation("Removed threat pattern: {PatternId}", patternId);
                return true;
            }
            
            _logger.LogWarning("Threat pattern not found: {PatternId}", patternId);
            return false;
        }
    }

    /// <summary>
    /// Get a threat pattern by ID
    /// </summary>
    public ThreatPattern? GetPattern(string patternId)
    {
        lock (_lock)
        {
            return _patterns.TryGetValue(patternId, out var pattern) ? pattern : null;
        }
    }

    /// <summary>
    /// Get all threat patterns
    /// </summary>
    public List<ThreatPattern> GetAllPatterns()
    {
        lock (_lock)
        {
            return _patterns.Values.ToList();
        }
    }

    /// <summary>
    /// Get patterns by type
    /// </summary>
    public List<ThreatPattern> GetPatternsByType(ThreatPatternType type)
    {
        lock (_lock)
        {
            return _patterns.Values.Where(p => p.Type == type).ToList();
        }
    }

    /// <summary>
    /// Get patterns by severity
    /// </summary>
    public List<ThreatPattern> GetPatternsBySeverity(ThreatSeverity severity)
    {
        lock (_lock)
        {
            return _patterns.Values.Where(p => p.Severity == severity).ToList();
        }
    }

    /// <summary>
    /// Get high-confidence patterns (confidence >= threshold)
    /// </summary>
    public List<ThreatPattern> GetHighConfidencePatterns(double confidenceThreshold = 0.7)
    {
        lock (_lock)
        {
            return _patterns.Values.Where(p => p.ConfidenceScore >= confidenceThreshold).ToList();
        }
    }

    /// <summary>
    /// Save the database to disk
    /// </summary>
    public async Task SaveAsync()
    {
        try
        {
            List<ThreatPattern> patternsToSave;
            lock (_lock)
            {
                patternsToSave = _patterns.Values.ToList();
            }

            var json = JsonSerializer.Serialize(patternsToSave, _jsonOptions);
            
            // Create backup of existing database
            if (File.Exists(_databasePath))
            {
                var backupPath = _databasePath + ".backup";
                File.Copy(_databasePath, backupPath, true);
            }

            // Write to temporary file first
            var tempPath = _databasePath + ".tmp";
            await File.WriteAllTextAsync(tempPath, json);

            // Calculate and store hash for integrity verification
            var hash = CalculateHash(json);
            var hashPath = _databasePath + ".hash";
            await File.WriteAllTextAsync(hashPath, hash);

            // Move temporary file to actual database file
            File.Move(tempPath, _databasePath, true);

            _logger.LogInformation("Threat pattern database saved successfully: {Count} patterns", 
                patternsToSave.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save threat pattern database");
            throw;
        }
    }

    /// <summary>
    /// Load the database from disk
    /// </summary>
    public async Task LoadAsync()
    {
        try
        {
            if (!File.Exists(_databasePath))
            {
                _logger.LogInformation("No existing threat pattern database found, starting fresh");
                return;
            }

            var json = await File.ReadAllTextAsync(_databasePath);
            
            // Verify integrity if hash file exists
            var hashPath = _databasePath + ".hash";
            if (File.Exists(hashPath))
            {
                var storedHash = await File.ReadAllTextAsync(hashPath);
                var calculatedHash = CalculateHash(json);
                
                if (storedHash != calculatedHash)
                {
                    _logger.LogWarning("Database integrity check failed, attempting to load backup");
                    await LoadBackupAsync();
                    return;
                }
            }

            var patterns = JsonSerializer.Deserialize<List<ThreatPattern>>(json, _jsonOptions);
            
            if (patterns != null)
            {
                lock (_lock)
                {
                    _patterns.Clear();
                    foreach (var pattern in patterns)
                    {
                        _patterns[pattern.PatternId] = pattern;
                    }
                }

                _logger.LogInformation("Loaded {Count} threat patterns from database", patterns.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load threat pattern database");
            
            // Try to load backup
            await LoadBackupAsync();
        }
    }

    /// <summary>
    /// Load backup database
    /// </summary>
    private async Task LoadBackupAsync()
    {
        try
        {
            var backupPath = _databasePath + ".backup";
            if (!File.Exists(backupPath))
            {
                _logger.LogWarning("No backup database found");
                return;
            }

            var json = await File.ReadAllTextAsync(backupPath);
            var patterns = JsonSerializer.Deserialize<List<ThreatPattern>>(json, _jsonOptions);
            
            if (patterns != null)
            {
                lock (_lock)
                {
                    _patterns.Clear();
                    foreach (var pattern in patterns)
                    {
                        _patterns[pattern.PatternId] = pattern;
                    }
                }

                _logger.LogInformation("Loaded {Count} threat patterns from backup", patterns.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load backup database");
        }
    }

    /// <summary>
    /// Clear all patterns from the database
    /// </summary>
    public void Clear()
    {
        lock (_lock)
        {
            _patterns.Clear();
            _logger.LogInformation("Cleared all threat patterns from database");
        }
    }

    /// <summary>
    /// Get database statistics
    /// </summary>
    public DatabaseStatistics GetStatistics()
    {
        lock (_lock)
        {
            return new DatabaseStatistics
            {
                TotalPatterns = _patterns.Count,
                PatternsByType = _patterns.Values
                    .GroupBy(p => p.Type)
                    .ToDictionary(g => g.Key, g => g.Count()),
                PatternsBySeverity = _patterns.Values
                    .GroupBy(p => p.Severity)
                    .ToDictionary(g => g.Key, g => g.Count()),
                AverageConfidence = _patterns.Values.Any() 
                    ? _patterns.Values.Average(p => p.ConfidenceScore) 
                    : 0,
                HighConfidenceCount = _patterns.Values.Count(p => p.ConfidenceScore >= 0.8),
                CommunityPatternsCount = _patterns.Values.Count(p => p.IsFromCommunity),
                LocalPatternsCount = _patterns.Values.Count(p => !p.IsFromCommunity),
                LastUpdated = _patterns.Values.Any() 
                    ? _patterns.Values.Max(p => p.LastUpdated) 
                    : DateTime.MinValue
            };
        }
    }

    /// <summary>
    /// Import patterns from honeypot intelligence
    /// </summary>
    public int ImportFromHoneypot(List<ThreatPattern> patterns, string honeypotId)
    {
        int importedCount = 0;
        
        foreach (var pattern in patterns)
        {
            pattern.SourceHoneypotId = honeypotId;
            pattern.IsFromCommunity = false;
            AddOrUpdatePattern(pattern);
            importedCount++;
        }

        _logger.LogInformation("Imported {Count} patterns from honeypot {HoneypotId}", 
            importedCount, honeypotId);
        
        return importedCount;
    }

    /// <summary>
    /// Import patterns from community intelligence
    /// </summary>
    public int ImportFromCommunity(List<ThreatPattern> patterns)
    {
        int importedCount = 0;
        
        foreach (var pattern in patterns)
        {
            pattern.IsFromCommunity = true;
            AddOrUpdatePattern(pattern);
            importedCount++;
        }

        _logger.LogInformation("Imported {Count} patterns from community intelligence", importedCount);
        
        return importedCount;
    }

    /// <summary>
    /// Export patterns for sharing
    /// </summary>
    public List<ThreatPattern> ExportForSharing(double minConfidence = 0.7)
    {
        lock (_lock)
        {
            return _patterns.Values
                .Where(p => p.ConfidenceScore >= minConfidence)
                .Select(p => new ThreatPattern
                {
                    PatternId = Guid.NewGuid().ToString(), // New ID for sharing
                    Name = p.Name,
                    Description = p.Description,
                    Type = p.Type,
                    Severity = p.Severity,
                    FileHashes = new List<string>(p.FileHashes),
                    FileNamePatterns = new List<string>(p.FileNamePatterns),
                    ProcessNamePatterns = new List<string>(p.ProcessNamePatterns),
                    RegistryKeyPatterns = new List<string>(p.RegistryKeyPatterns),
                    NetworkAddressPatterns = new List<string>(p.NetworkAddressPatterns),
                    NetworkPorts = new List<int>(p.NetworkPorts),
                    BehavioralSignatures = new List<string>(p.BehavioralSignatures),
                    ConfidenceScore = p.ConfidenceScore,
                    IsFromCommunity = false // Will be set by recipient
                })
                .ToList();
        }
    }

    private void EnsureDatabaseDirectory()
    {
        var directory = Path.GetDirectoryName(_databasePath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
            _logger.LogInformation("Created threat pattern database directory: {Directory}", directory);
        }
    }

    private string CalculateHash(string content)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(content);
        var hash = sha256.ComputeHash(bytes);
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }
}

/// <summary>
/// Database statistics
/// </summary>
public class DatabaseStatistics
{
    public int TotalPatterns { get; set; }
    public Dictionary<ThreatPatternType, int> PatternsByType { get; set; } = new();
    public Dictionary<ThreatSeverity, int> PatternsBySeverity { get; set; } = new();
    public double AverageConfidence { get; set; }
    public int HighConfidenceCount { get; set; }
    public int CommunityPatternsCount { get; set; }
    public int LocalPatternsCount { get; set; }
    public DateTime LastUpdated { get; set; }
}
