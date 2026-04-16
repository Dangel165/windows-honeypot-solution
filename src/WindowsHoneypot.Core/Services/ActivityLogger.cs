using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Comprehensive activity logging system with encryption and integrity protection
/// Implements Requirements 9.1, 9.2, 9.3, 9.4, 9.5, 9.6
/// </summary>
public class ActivityLogger : IDisposable
{
    private readonly ILogger<ActivityLogger> _logger;
    private readonly string _logDirectory;
    private readonly string _encryptionKey;
    private readonly ConcurrentQueue<AttackEvent> _logQueue;
    private readonly object _lock = new();
    private bool _disposed;
    private Task? _flushTask;
    private CancellationTokenSource? _cancellationTokenSource;
    private readonly int _maxLogFileSizeMB;
    private readonly int _logRetentionDays;
    private string _currentLogFile;
    private readonly Dictionary<string, string> _logFileHashes;

    public ActivityLogger(
        ILogger<ActivityLogger> logger,
        string? logDirectory = null,
        int maxLogFileSizeMB = 100,
        int logRetentionDays = 90)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _logDirectory = logDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "WindowsHoneypot",
            "Logs"
        );
        _maxLogFileSizeMB = maxLogFileSizeMB;
        _logRetentionDays = logRetentionDays;
        _logQueue = new ConcurrentQueue<AttackEvent>();
        _logFileHashes = new Dictionary<string, string>();

        // Generate encryption key (in production, this should be securely stored)
        _encryptionKey = GenerateEncryptionKey();
        _currentLogFile = GetNewLogFilePath();

        // Ensure log directory exists
        Directory.CreateDirectory(_logDirectory);

        // Start background flush task
        StartBackgroundFlush();
    }

    /// <summary>
    /// Logs an attack event with timestamp and details
    /// </summary>
    public void LogActivity(AttackEvent attackEvent)
    {
        if (attackEvent == null)
        {
            throw new ArgumentNullException(nameof(attackEvent));
        }

        // Ensure timestamp is set
        if (attackEvent.Timestamp == default)
        {
            attackEvent.Timestamp = DateTime.UtcNow;
        }

        _logQueue.Enqueue(attackEvent);
        
        _logger.LogInformation(
            "Activity logged: {EventType} by {SourceProcess} (PID: {ProcessId}) - {Description}",
            attackEvent.EventType,
            attackEvent.SourceProcess,
            attackEvent.ProcessId,
            attackEvent.Description
        );
    }

    /// <summary>
    /// Exports logs to JSON format
    /// </summary>
    public async Task<string> ExportToJsonAsync(DateTime? startDate = null, DateTime? endDate = null)
    {
        _logger.LogInformation("Exporting logs to JSON format");

        var events = await LoadEventsAsync(startDate, endDate);
        var json = JsonSerializer.Serialize(events, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        var exportPath = Path.Combine(_logDirectory, $"export_{DateTime.UtcNow:yyyyMMddHHmmss}.json");
        await File.WriteAllTextAsync(exportPath, json);

        _logger.LogInformation("Logs exported to JSON: {Path}", exportPath);
        return exportPath;
    }

    /// <summary>
    /// Exports logs to XML format
    /// </summary>
    public async Task<string> ExportToXmlAsync(DateTime? startDate = null, DateTime? endDate = null)
    {
        _logger.LogInformation("Exporting logs to XML format");

        var events = await LoadEventsAsync(startDate, endDate);
        
        var root = new XElement("AttackEvents");
        foreach (var evt in events)
        {
            var eventElement = new XElement("AttackEvent",
                new XElement("EventId", evt.EventId),
                new XElement("Timestamp", evt.Timestamp.ToString("o")),
                new XElement("EventType", evt.EventType),
                new XElement("SourceProcess", evt.SourceProcess),
                new XElement("ProcessId", evt.ProcessId),
                new XElement("TargetFile", evt.TargetFile),
                new XElement("Description", evt.Description),
                new XElement("Severity", evt.Severity)
            );

            if (evt.Metadata.Any())
            {
                var metadataElement = new XElement("Metadata");
                foreach (var kvp in evt.Metadata)
                {
                    metadataElement.Add(new XElement(kvp.Key, kvp.Value));
                }
                eventElement.Add(metadataElement);
            }

            root.Add(eventElement);
        }

        var doc = new XDocument(root);
        var exportPath = Path.Combine(_logDirectory, $"export_{DateTime.UtcNow:yyyyMMddHHmmss}.xml");
        await Task.Run(() => doc.Save(exportPath));

        _logger.LogInformation("Logs exported to XML: {Path}", exportPath);
        return exportPath;
    }

    /// <summary>
    /// Exports logs to CSV format
    /// </summary>
    public async Task<string> ExportToCsvAsync(DateTime? startDate = null, DateTime? endDate = null)
    {
        _logger.LogInformation("Exporting logs to CSV format");

        var events = await LoadEventsAsync(startDate, endDate);
        var csv = new StringBuilder();
        
        // Header
        csv.AppendLine("EventId,Timestamp,EventType,SourceProcess,ProcessId,TargetFile,Description,Severity");

        // Data rows
        foreach (var evt in events)
        {
            csv.AppendLine($"\"{evt.EventId}\",\"{evt.Timestamp:o}\",\"{evt.EventType}\",\"{EscapeCsv(evt.SourceProcess)}\",\"{evt.ProcessId}\",\"{EscapeCsv(evt.TargetFile)}\",\"{EscapeCsv(evt.Description)}\",\"{evt.Severity}\"");
        }

        var exportPath = Path.Combine(_logDirectory, $"export_{DateTime.UtcNow:yyyyMMddHHmmss}.csv");
        await File.WriteAllTextAsync(exportPath, csv.ToString());

        _logger.LogInformation("Logs exported to CSV: {Path}", exportPath);
        return exportPath;
    }

    /// <summary>
    /// Generates a legal-grade forensic report
    /// </summary>
    public async Task<string> GenerateForensicReportAsync(DateTime? startDate = null, DateTime? endDate = null)
    {
        _logger.LogInformation("Generating forensic report");

        var events = await LoadEventsAsync(startDate, endDate);
        var report = new StringBuilder();

        report.AppendLine("═══════════════════════════════════════════════════════════════");
        report.AppendLine("           WINDOWS HONEYPOT FORENSIC REPORT");
        report.AppendLine("═══════════════════════════════════════════════════════════════");
        report.AppendLine();
        report.AppendLine($"Report Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        report.AppendLine($"Report Period: {startDate?.ToString("yyyy-MM-dd") ?? "All"} to {endDate?.ToString("yyyy-MM-dd") ?? "All"}");
        report.AppendLine($"Total Events: {events.Count}");
        report.AppendLine();

        // Summary statistics
        report.AppendLine("SUMMARY STATISTICS");
        report.AppendLine("─────────────────────────────────────────────────────────────");
        var eventsByType = events.GroupBy(e => e.EventType).OrderByDescending(g => g.Count());
        foreach (var group in eventsByType)
        {
            report.AppendLine($"  {group.Key}: {group.Count()} events");
        }
        report.AppendLine();

        var eventsBySeverity = events.GroupBy(e => e.Severity).OrderByDescending(g => g.Count());
        foreach (var group in eventsBySeverity)
        {
            report.AppendLine($"  {group.Key} Severity: {group.Count()} events");
        }
        report.AppendLine();

        // Detailed event log
        report.AppendLine("DETAILED EVENT LOG");
        report.AppendLine("─────────────────────────────────────────────────────────────");
        foreach (var evt in events.OrderBy(e => e.Timestamp))
        {
            report.AppendLine($"[{evt.Timestamp:yyyy-MM-dd HH:mm:ss}] {evt.EventType} - {evt.Severity}");
            report.AppendLine($"  Process: {evt.SourceProcess} (PID: {evt.ProcessId})");
            if (!string.IsNullOrEmpty(evt.TargetFile))
            {
                report.AppendLine($"  Target: {evt.TargetFile}");
            }
            report.AppendLine($"  Description: {evt.Description}");
            report.AppendLine();
        }

        // Chain of custody
        report.AppendLine("CHAIN OF CUSTODY");
        report.AppendLine("─────────────────────────────────────────────────────────────");
        report.AppendLine($"Log Directory: {_logDirectory}");
        report.AppendLine($"Encryption: AES-256");
        report.AppendLine($"Integrity Protection: SHA-256 hashes");
        report.AppendLine();

        // File integrity verification
        report.AppendLine("FILE INTEGRITY VERIFICATION");
        report.AppendLine("─────────────────────────────────────────────────────────────");
        foreach (var kvp in _logFileHashes)
        {
            report.AppendLine($"  {Path.GetFileName(kvp.Key)}: {kvp.Value}");
        }
        report.AppendLine();

        report.AppendLine("═══════════════════════════════════════════════════════════════");
        report.AppendLine("                    END OF REPORT");
        report.AppendLine("═══════════════════════════════════════════════════════════════");

        var reportPath = Path.Combine(_logDirectory, $"forensic_report_{DateTime.UtcNow:yyyyMMddHHmmss}.txt");
        await File.WriteAllTextAsync(reportPath, report.ToString());

        _logger.LogInformation("Forensic report generated: {Path}", reportPath);
        return reportPath;
    }

    /// <summary>
    /// Verifies the integrity of log files using stored hashes
    /// </summary>
    public async Task<Dictionary<string, bool>> VerifyLogIntegrityAsync()
    {
        _logger.LogInformation("Verifying log file integrity");

        var results = new Dictionary<string, bool>();

        foreach (var kvp in _logFileHashes.ToList())
        {
            var filePath = kvp.Key;
            var storedHash = kvp.Value;

            if (!File.Exists(filePath))
            {
                results[filePath] = false;
                _logger.LogWarning("Log file not found: {Path}", filePath);
                continue;
            }

            var currentHash = await ComputeFileHashAsync(filePath);
            var isValid = currentHash.Equals(storedHash, StringComparison.OrdinalIgnoreCase);
            results[filePath] = isValid;

            if (!isValid)
            {
                _logger.LogError("Log file integrity check failed: {Path}", filePath);
            }
        }

        return results;
    }

    /// <summary>
    /// Performs automatic log rotation and cleanup
    /// </summary>
    public async Task RotateLogsAsync()
    {
        _logger.LogInformation("Performing log rotation");

        // Check current log file size
        if (File.Exists(_currentLogFile))
        {
            var fileInfo = new FileInfo(_currentLogFile);
            if (fileInfo.Length > _maxLogFileSizeMB * 1024 * 1024)
            {
                // Create new log file
                _currentLogFile = GetNewLogFilePath();
                _logger.LogInformation("Created new log file: {Path}", _currentLogFile);
            }
        }

        // Clean up old logs
        var cutoffDate = DateTime.UtcNow.AddDays(-_logRetentionDays);
        var logFiles = Directory.GetFiles(_logDirectory, "honeypot_*.log");

        foreach (var logFile in logFiles)
        {
            var fileInfo = new FileInfo(logFile);
            if (fileInfo.CreationTimeUtc < cutoffDate)
            {
                try
                {
                    File.Delete(logFile);
                    _logFileHashes.Remove(logFile);
                    _logger.LogInformation("Deleted old log file: {Path}", logFile);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to delete old log file: {Path}", logFile);
                }
            }
        }

        await Task.CompletedTask;
    }

    /// <summary>
    /// Starts background task to flush logs to disk
    /// </summary>
    private void StartBackgroundFlush()
    {
        _cancellationTokenSource = new CancellationTokenSource();
        _flushTask = Task.Run(() => FlushLogsAsync(_cancellationTokenSource.Token), _cancellationTokenSource.Token);
    }

    /// <summary>
    /// Background task that periodically flushes logs to disk
    /// </summary>
    private async Task FlushLogsAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(10), cancellationToken);

                if (_logQueue.IsEmpty)
                {
                    continue;
                }

                var events = new List<AttackEvent>();
                while (_logQueue.TryDequeue(out var evt))
                {
                    events.Add(evt);
                }

                if (events.Any())
                {
                    await WriteEventsToFileAsync(events);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error flushing logs to disk");
            }
        }
    }

    /// <summary>
    /// Writes events to encrypted log file
    /// </summary>
    private async Task WriteEventsToFileAsync(List<AttackEvent> events)
    {
        try
        {
            var json = JsonSerializer.Serialize(events);
            var encrypted = EncryptString(json, _encryptionKey);

            await File.AppendAllTextAsync(_currentLogFile, encrypted + Environment.NewLine);

            // Update file hash
            var hash = await ComputeFileHashAsync(_currentLogFile);
            _logFileHashes[_currentLogFile] = hash;

            _logger.LogDebug("Flushed {Count} events to log file", events.Count);

            // Check if rotation is needed
            await RotateLogsAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to write events to file");
        }
    }

    /// <summary>
    /// Loads events from log files within date range
    /// </summary>
    private async Task<List<AttackEvent>> LoadEventsAsync(DateTime? startDate, DateTime? endDate)
    {
        var allEvents = new List<AttackEvent>();

        var logFiles = Directory.GetFiles(_logDirectory, "honeypot_*.log");

        foreach (var logFile in logFiles)
        {
            try
            {
                var lines = await File.ReadAllLinesAsync(logFile);
                
                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        continue;
                    }

                    try
                    {
                        var decrypted = DecryptString(line, _encryptionKey);
                        var events = JsonSerializer.Deserialize<List<AttackEvent>>(decrypted);

                        if (events != null)
                        {
                            foreach (var evt in events)
                            {
                                if ((!startDate.HasValue || evt.Timestamp >= startDate.Value) &&
                                    (!endDate.HasValue || evt.Timestamp <= endDate.Value))
                                {
                                    allEvents.Add(evt);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to decrypt/parse log line");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load log file: {Path}", logFile);
            }
        }

        return allEvents;
    }

    /// <summary>
    /// Generates a new log file path with timestamp
    /// </summary>
    private string GetNewLogFilePath()
    {
        return Path.Combine(_logDirectory, $"honeypot_{DateTime.UtcNow:yyyyMMddHHmmss}.log");
    }

    /// <summary>
    /// Generates an encryption key (in production, use secure key management)
    /// </summary>
    private string GenerateEncryptionKey()
    {
        // In production, this should be securely generated and stored
        // For now, we use a deterministic key based on machine
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(Environment.MachineName + "WindowsHoneypot"));
        return Convert.ToBase64String(hash);
    }

    /// <summary>
    /// Encrypts a string using AES-256
    /// </summary>
    private string EncryptString(string plainText, string key)
    {
        using var aes = Aes.Create();
        aes.Key = Convert.FromBase64String(key);
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream();
        
        // Write IV first
        ms.Write(aes.IV, 0, aes.IV.Length);

        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        using (var sw = new StreamWriter(cs))
        {
            sw.Write(plainText);
        }

        return Convert.ToBase64String(ms.ToArray());
    }

    /// <summary>
    /// Decrypts a string using AES-256
    /// </summary>
    private string DecryptString(string cipherText, string key)
    {
        var fullCipher = Convert.FromBase64String(cipherText);

        using var aes = Aes.Create();
        aes.Key = Convert.FromBase64String(key);

        // Extract IV
        var iv = new byte[aes.IV.Length];
        Array.Copy(fullCipher, 0, iv, 0, iv.Length);
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream(fullCipher, iv.Length, fullCipher.Length - iv.Length);
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var sr = new StreamReader(cs);
        
        return sr.ReadToEnd();
    }

    /// <summary>
    /// Computes SHA-256 hash of a file
    /// </summary>
    private async Task<string> ComputeFileHashAsync(string filePath)
    {
        using var sha256 = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        var hash = await sha256.ComputeHashAsync(stream);
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }

    /// <summary>
    /// Escapes CSV special characters
    /// </summary>
    private string EscapeCsv(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        return value.Replace("\"", "\"\"");
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        // Stop background flush and flush remaining logs
        _cancellationTokenSource?.Cancel();
        
        try
        {
            _flushTask?.Wait(TimeSpan.FromSeconds(5));
        }
        catch (AggregateException ex) when (ex.InnerException is TaskCanceledException)
        {
            // Expected
        }

        // Flush any remaining logs
        var remainingEvents = new List<AttackEvent>();
        while (_logQueue.TryDequeue(out var evt))
        {
            remainingEvents.Add(evt);
        }

        if (remainingEvents.Any())
        {
            WriteEventsToFileAsync(remainingEvents).GetAwaiter().GetResult();
        }

        _cancellationTokenSource?.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
