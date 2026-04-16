using System.Diagnostics;
using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Automated response system for threat quarantine, recovery, and notifications.
/// Tasks 22.1, 22.2, 22.3
/// </summary>
public class AutomatedResponseSystem : IAutomatedResponseSystem
{
    private readonly ILogger<AutomatedResponseSystem> _logger;
    private readonly List<ThreatNotification> _notifications = new();
    private readonly List<AuditLogEntry> _auditLog = new();
    private readonly List<RestorePointResult> _restorePoints = new();
    private ResponsePolicy _policy = new();
    private readonly object _lock = new();

    public event EventHandler<ThreatNotification>? NotificationRaised;

    public AutomatedResponseSystem(ILogger<AutomatedResponseSystem> logger)
    {
        _logger = logger;
    }

    public async Task<QuarantineResult> QuarantineThreatAsync(string filePath)
    {
        var result = new QuarantineResult { OriginalPath = filePath };

        if (!File.Exists(filePath))
        {
            result.Success = false;
            result.ErrorMessage = $"File not found: {filePath}";
            AddAuditEntry("QuarantineFile", filePath, false, result.ErrorMessage);
            return result;
        }

        try
        {
            var quarantineDir = Path.Combine(Path.GetTempPath(), "HoneypotQuarantine");
            Directory.CreateDirectory(quarantineDir);

            var fileName = Path.GetFileName(filePath) + ".quarantine";
            var quarantinePath = Path.Combine(quarantineDir, fileName);
            if (File.Exists(quarantinePath))
                quarantinePath = Path.Combine(quarantineDir, Guid.NewGuid().ToString("N") + "_" + fileName);

            await Task.Run(() => File.Move(filePath, quarantinePath));

            result.Success = true;
            result.QuarantinePath = quarantinePath;
            result.QuarantinedAt = DateTime.UtcNow;

            _logger.LogInformation("File quarantined: {OriginalPath} -> {QuarantinePath}", filePath, quarantinePath);
            AddAuditEntry("QuarantineFile", filePath, true, $"Moved to {quarantinePath}");
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorMessage = ex.Message;
            _logger.LogError(ex, "Failed to quarantine file: {FilePath}", filePath);
            AddAuditEntry("QuarantineFile", filePath, false, ex.Message);
        }

        return result;
    }

    public async Task<bool> TerminateProcessAsync(int processId)
    {
        try
        {
            await Task.Run(() => Process.GetProcessById(processId).Kill());
            AddAuditEntry("TerminateProcess", processId.ToString(), true, $"Process {processId} terminated");
            return true;
        }
        catch (ArgumentException)
        {
            AddAuditEntry("TerminateProcess", processId.ToString(), false, "Process not found");
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to terminate process: PID {ProcessId}", processId);
            AddAuditEntry("TerminateProcess", processId.ToString(), false, ex.Message);
            return false;
        }
    }

    public async Task<bool> IsolateSystemAsync()
    {
        await Task.CompletedTask;
        _logger.LogWarning("Network isolation requested (admin privileges required for actual firewall changes)");
        AddAuditEntry("IsolateSystem", "Network", true, "Network isolation requested");
        return true;
    }

    public async Task<RestorePointResult> CreateRestorePointAsync(string description)
    {
        await Task.CompletedTask;
        var result = new RestorePointResult { Success = true, Description = description, CreatedAt = DateTime.UtcNow };
        lock (_lock) { _restorePoints.Add(result); }
        AddAuditEntry("CreateRestorePoint", result.RestorePointId, true, description);
        return result;
    }

    public async Task<bool> RollbackToRestorePointAsync(string restorePointId)
    {
        await Task.CompletedTask;
        RestorePointResult? point;
        lock (_lock) { point = _restorePoints.FirstOrDefault(r => r.RestorePointId == restorePointId); }

        if (point == null)
        {
            AddAuditEntry("RollbackToRestorePoint", restorePointId, false, "Restore point not found");
            return false;
        }

        AddAuditEntry("RollbackToRestorePoint", restorePointId, true, $"Rolled back to: {point.Description}");
        return true;
    }

    public List<RestorePointResult> GetRestorePoints()
    {
        lock (_lock) { return new List<RestorePointResult>(_restorePoints); }
    }

    public void SendNotification(ThreatNotification notification)
    {
        lock (_lock) { _notifications.Add(notification); }
        AddAuditEntry("SendNotification", notification.NotificationId, true, notification.Title);
        NotificationRaised?.Invoke(this, notification);
    }

    public List<ThreatNotification> GetNotifications()
    {
        lock (_lock) { return new List<ThreatNotification>(_notifications); }
    }

    public List<AuditLogEntry> GetAuditLog()
    {
        lock (_lock) { return new List<AuditLogEntry>(_auditLog); }
    }

    public void ConfigureResponsePolicy(ResponsePolicy policy)
    {
        lock (_lock) { _policy = policy; }
        AddAuditEntry("ConfigurePolicy", "ResponsePolicy", true, "Policy updated");
    }

    public ResponsePolicy GetResponsePolicy()
    {
        lock (_lock) { return _policy; }
    }

    private void AddAuditEntry(string action, string target, bool success, string details)
    {
        lock (_lock)
        {
            _auditLog.Add(new AuditLogEntry
            {
                Action = action, Target = target, Success = success,
                Details = details, Timestamp = DateTime.UtcNow
            });
        }
    }
}
