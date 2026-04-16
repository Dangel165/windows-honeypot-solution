using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Interfaces;

public interface IAutomatedResponseSystem
{
    Task<QuarantineResult> QuarantineThreatAsync(string filePath);
    Task<bool> TerminateProcessAsync(int processId);
    Task<bool> IsolateSystemAsync();
    Task<RestorePointResult> CreateRestorePointAsync(string description);
    Task<bool> RollbackToRestorePointAsync(string restorePointId);
    List<RestorePointResult> GetRestorePoints();
    void SendNotification(ThreatNotification notification);
    List<ThreatNotification> GetNotifications();
    List<AuditLogEntry> GetAuditLog();
    void ConfigureResponsePolicy(ResponsePolicy policy);
    ResponsePolicy GetResponsePolicy();
    event EventHandler<ThreatNotification> NotificationRaised;
}
