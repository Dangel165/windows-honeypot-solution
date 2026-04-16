namespace WindowsHoneypot.Core.Models;

public class QuarantineResult
{
    public bool Success { get; set; }
    public string OriginalPath { get; set; } = string.Empty;
    public string QuarantinePath { get; set; } = string.Empty;
    public string ErrorMessage { get; set; } = string.Empty;
    public DateTime QuarantinedAt { get; set; } = DateTime.UtcNow;
}

public class RestorePointResult
{
    public bool Success { get; set; }
    public string RestorePointId { get; set; } = Guid.NewGuid().ToString();
    public string Description { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string ErrorMessage { get; set; } = string.Empty;
}

public class ThreatNotification
{
    public string NotificationId { get; set; } = Guid.NewGuid().ToString();
    public string Title { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public ThreatSeverity Severity { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public bool IsRead { get; set; }
    public List<string> RemediationSteps { get; set; } = new();
}

public class AuditLogEntry
{
    public string EntryId { get; set; } = Guid.NewGuid().ToString();
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string Action { get; set; } = string.Empty;
    public string Target { get; set; } = string.Empty;
    public bool Success { get; set; }
    public string Details { get; set; } = string.Empty;
}

public class ResponsePolicy
{
    public bool AutoQuarantineEnabled { get; set; } = true;
    public bool AutoTerminateProcessEnabled { get; set; } = true;
    public bool AutoIsolateNetworkEnabled { get; set; } = false;
    public bool CreateRestorePointBeforeAction { get; set; } = true;
    public ThreatSeverity MinimumSeverityForAutoResponse { get; set; } = ThreatSeverity.High;
}
