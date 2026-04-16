using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Integrates honeypot intelligence with real-time protection
/// Automatically converts honeypot detections into threat patterns
/// </summary>
public class HoneypotIntelligenceIntegration
{
    private readonly ILogger<HoneypotIntelligenceIntegration> _logger;
    private readonly IRealTimeThreatMonitor _threatMonitor;
    private readonly ThreatPatternDatabase _patternDatabase;
    private readonly IFileMonitor? _fileMonitor;
    private readonly IHoneyAccountSystem? _honeyAccountSystem;

    public HoneypotIntelligenceIntegration(
        ILogger<HoneypotIntelligenceIntegration> logger,
        IRealTimeThreatMonitor threatMonitor,
        ThreatPatternDatabase patternDatabase,
        IFileMonitor? fileMonitor = null,
        IHoneyAccountSystem? honeyAccountSystem = null)
    {
        _logger = logger;
        _threatMonitor = threatMonitor;
        _patternDatabase = patternDatabase;
        _fileMonitor = fileMonitor;
        _honeyAccountSystem = honeyAccountSystem;
    }

    /// <summary>
    /// Start monitoring honeypot events and converting them to threat patterns
    /// </summary>
    public void StartIntegration()
    {
        _logger.LogInformation("Starting honeypot intelligence integration...");

        // Subscribe to file monitor events
        if (_fileMonitor != null)
        {
            _fileMonitor.FileAccessed += OnFileAccessed;
            _fileMonitor.FileModified += OnFileModified;
            _logger.LogInformation("Subscribed to file monitor events");
        }

        // Subscribe to honey account events
        if (_honeyAccountSystem != null)
        {
            _honeyAccountSystem.CredentialUsed += OnCredentialUsed;
            _logger.LogInformation("Subscribed to honey account events");
        }

        _logger.LogInformation("Honeypot intelligence integration started");
    }

    /// <summary>
    /// Stop monitoring honeypot events
    /// </summary>
    public void StopIntegration()
    {
        _logger.LogInformation("Stopping honeypot intelligence integration...");

        if (_fileMonitor != null)
        {
            _fileMonitor.FileAccessed -= OnFileAccessed;
            _fileMonitor.FileModified -= OnFileModified;
        }

        if (_honeyAccountSystem != null)
        {
            _honeyAccountSystem.CredentialUsed -= OnCredentialUsed;
        }

        _logger.LogInformation("Honeypot intelligence integration stopped");
    }

    /// <summary>
    /// Manually create threat pattern from attack event
    /// </summary>
    public ThreatPattern CreateThreatPatternFromAttack(AttackEvent attackEvent)
    {
        var pattern = new ThreatPattern
        {
            Name = $"Attack_{attackEvent.EventType}_{DateTime.UtcNow:yyyyMMddHHmmss}",
            Description = $"Threat pattern created from {attackEvent.EventType} attack",
            Type = DeterminePatternType(attackEvent.EventType),
            Severity = DetermineSeverity(attackEvent.EventType),
            CreatedAt = DateTime.UtcNow,
            LastUpdated = DateTime.UtcNow,
            ConfidenceScore = 0.8, // Initial confidence
            SourceHoneypotId = Environment.MachineName,
            IsFromCommunity = false
        };

        // Add pattern matching criteria based on attack type
        switch (attackEvent.EventType)
        {
            case AttackEventType.FileModification:
            case AttackEventType.FileDeletion:
            case AttackEventType.FileRename:
                if (!string.IsNullOrEmpty(attackEvent.TargetFile))
                {
                    var fileName = Path.GetFileName(attackEvent.TargetFile);
                    pattern.FileNamePatterns.Add(fileName);
                }
                break;

            case AttackEventType.ProcessCreation:
                if (!string.IsNullOrEmpty(attackEvent.SourceProcess))
                {
                    pattern.ProcessNamePatterns.Add(attackEvent.SourceProcess);
                }
                break;

            case AttackEventType.NetworkAttempt:
                // Network patterns would be added from metadata
                if (attackEvent.Metadata.TryGetValue("RemoteAddress", out var address))
                {
                    pattern.NetworkAddressPatterns.Add(address.ToString() ?? "");
                }
                if (attackEvent.Metadata.TryGetValue("Port", out var port))
                {
                    if (int.TryParse(port.ToString(), out var portNum))
                    {
                        pattern.NetworkPorts.Add(portNum);
                    }
                }
                break;
        }

        // Add behavioral signatures
        pattern.BehavioralSignatures.Add($"{attackEvent.EventType}:{attackEvent.SourceProcess}");

        // Store metadata
        pattern.Metadata["OriginalEventId"] = attackEvent.EventId.ToString();
        pattern.Metadata["DetectionTimestamp"] = attackEvent.Timestamp.ToString("O");

        return pattern;
    }

    /// <summary>
    /// Create threat pattern from attacker profile
    /// </summary>
    public ThreatPattern CreateThreatPatternFromAttacker(AttackerProfile attacker)
    {
        var pattern = new ThreatPattern
        {
            Name = $"Attacker_{attacker.SessionId}",
            Description = $"Threat pattern from attacker profile {attacker.SessionId}",
            Type = ThreatPatternType.Composite,
            Severity = ThreatSeverity.High,
            CreatedAt = DateTime.UtcNow,
            LastUpdated = DateTime.UtcNow,
            ConfidenceScore = 0.9, // High confidence from honey account usage
            SourceHoneypotId = Environment.MachineName,
            IsFromCommunity = false
        };

        // Add network indicators
        if (!string.IsNullOrEmpty(attacker.IPAddress))
        {
            pattern.NetworkAddressPatterns.Add(attacker.IPAddress);
        }

        // Add behavioral signatures from user agent and browser info
        if (!string.IsNullOrEmpty(attacker.UserAgent))
        {
            pattern.BehavioralSignatures.Add($"UserAgent:{attacker.UserAgent}");
        }

        // Store attacker metadata
        pattern.Metadata["AttackerIP"] = attacker.IPAddress;
        pattern.Metadata["UserAgent"] = attacker.UserAgent;
        pattern.Metadata["Language"] = attacker.Language;
        pattern.Metadata["ScreenResolution"] = attacker.ScreenResolution;
        pattern.Metadata["FirstSeen"] = attacker.FirstSeen.ToString("O");

        return pattern;
    }

    /// <summary>
    /// Import threat patterns from community intelligence
    /// </summary>
    public async Task<int> ImportCommunityPatternsAsync(List<ThreatPattern> communityPatterns)
    {
        _logger.LogInformation("Importing {Count} patterns from community intelligence", 
            communityPatterns.Count);

        int importedCount = _patternDatabase.ImportFromCommunity(communityPatterns);

        // Register patterns with real-time monitor
        foreach (var pattern in communityPatterns)
        {
            _threatMonitor.RegisterThreatPattern(pattern);
        }

        // Save to database
        await _patternDatabase.SaveAsync();

        _logger.LogInformation("Imported and registered {Count} community patterns", importedCount);

        return importedCount;
    }

    /// <summary>
    /// Export local patterns for community sharing
    /// </summary>
    public List<ThreatPattern> ExportPatternsForSharing(double minConfidence = 0.7)
    {
        var patterns = _patternDatabase.ExportForSharing(minConfidence);
        
        _logger.LogInformation("Exported {Count} patterns for community sharing", patterns.Count);
        
        return patterns;
    }

    /// <summary>
    /// Get integration statistics
    /// </summary>
    public IntegrationStatistics GetStatistics()
    {
        var dbStats = _patternDatabase.GetStatistics();
        var protectionStatus = _threatMonitor.GetProtectionStatus();

        return new IntegrationStatistics
        {
            TotalPatterns = dbStats.TotalPatterns,
            LocalPatterns = dbStats.LocalPatternsCount,
            CommunityPatterns = dbStats.CommunityPatternsCount,
            HighConfidencePatterns = dbStats.HighConfidenceCount,
            ActivePatterns = protectionStatus.ActivePatterns,
            LastUpdate = dbStats.LastUpdated,
            ProtectionActive = protectionStatus.IsActive
        };
    }

    private void OnFileAccessed(object? sender, FileEventArgs e)
    {
        _logger.LogDebug("File accessed in honeypot: {FilePath} by {ProcessName}", 
            e.FilePath, e.ProcessName);

        // Create attack event
        var attackEvent = new AttackEvent
        {
            EventType = e.EventType,
            Timestamp = e.Timestamp,
            SourceProcess = e.ProcessName,
            TargetFile = e.FilePath
        };

        // Create and register threat pattern
        var pattern = CreateThreatPatternFromAttack(attackEvent);
        _patternDatabase.AddOrUpdatePattern(pattern);
        _threatMonitor.RegisterThreatPattern(pattern);

        _logger.LogInformation("Created threat pattern from file access: {PatternName}", pattern.Name);
    }

    private void OnFileModified(object? sender, FileEventArgs e)
    {
        _logger.LogWarning("File modified in honeypot: {FilePath} by {ProcessName}", 
            e.FilePath, e.ProcessName);

        // Create attack event
        var attackEvent = new AttackEvent
        {
            EventType = AttackEventType.FileModification,
            Timestamp = e.Timestamp,
            SourceProcess = e.ProcessName,
            TargetFile = e.FilePath
        };

        // Create and register threat pattern with higher severity
        var pattern = CreateThreatPatternFromAttack(attackEvent);
        pattern.Severity = ThreatSeverity.High;
        pattern.ConfidenceScore = 0.9; // Higher confidence for modification

        _patternDatabase.AddOrUpdatePattern(pattern);
        _threatMonitor.RegisterThreatPattern(pattern);

        _logger.LogWarning("Created high-severity threat pattern from file modification: {PatternName}", 
            pattern.Name);
    }

    private void OnCredentialUsed(object? sender, CredentialAttemptEventArgs e)
    {
        _logger.LogWarning("Honey account credentials used: {Username} from {IP}", 
            e.Username, e.SourceIP);

        // Create threat pattern from attacker profile
        var pattern = CreateThreatPatternFromAttacker(e.AttackerProfile);
        
        _patternDatabase.AddOrUpdatePattern(pattern);
        _threatMonitor.RegisterThreatPattern(pattern);

        _logger.LogWarning("Created threat pattern from credential usage: {PatternName}", pattern.Name);
    }

    private ThreatPatternType DeterminePatternType(AttackEventType eventType)
    {
        return eventType switch
        {
            AttackEventType.FileAccess or 
            AttackEventType.FileModification or 
            AttackEventType.FileDeletion or 
            AttackEventType.FileRename => ThreatPatternType.FileName,
            
            AttackEventType.ProcessCreation => ThreatPatternType.ProcessName,
            AttackEventType.NetworkAttempt => ThreatPatternType.NetworkAddress,
            AttackEventType.RegistryAccess => ThreatPatternType.RegistryKey,
            _ => ThreatPatternType.Behavioral
        };
    }

    private ThreatSeverity DetermineSeverity(AttackEventType eventType)
    {
        return eventType switch
        {
            AttackEventType.SandboxEscape or 
            AttackEventType.PrivilegeEscalation => ThreatSeverity.Critical,
            
            AttackEventType.FileModification or 
            AttackEventType.FileDeletion or 
            AttackEventType.CredentialUsage => ThreatSeverity.High,
            
            AttackEventType.FileRename or 
            AttackEventType.ProcessCreation or 
            AttackEventType.NetworkAttempt => ThreatSeverity.Medium,
            
            _ => ThreatSeverity.Low
        };
    }
}

/// <summary>
/// Integration statistics
/// </summary>
public class IntegrationStatistics
{
    public int TotalPatterns { get; set; }
    public int LocalPatterns { get; set; }
    public int CommunityPatterns { get; set; }
    public int HighConfidencePatterns { get; set; }
    public int ActivePatterns { get; set; }
    public DateTime LastUpdate { get; set; }
    public bool ProtectionActive { get; set; }
}
