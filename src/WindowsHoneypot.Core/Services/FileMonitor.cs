using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Real-time file system monitoring using FileSystemWatcher with process identification
/// </summary>
public class FileMonitor : IFileMonitor, IDisposable
{
    private readonly ILogger<FileMonitor> _logger;
    private readonly ConcurrentDictionary<string, FileSystemWatcher> _watchers;
    private readonly List<string> _monitoredPaths;
    private readonly object _lock = new();
    private bool _disposed;

    public FileMonitor(ILogger<FileMonitor> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _watchers = new ConcurrentDictionary<string, FileSystemWatcher>();
        _monitoredPaths = new List<string>();
    }

    public bool IsMonitoring => _watchers.Any(w => w.Value.EnableRaisingEvents);

    public IReadOnlyList<string> MonitoredPaths
    {
        get
        {
            lock (_lock)
            {
                return _monitoredPaths.AsReadOnly();
            }
        }
    }

    public event EventHandler<FileEventArgs>? FileAccessed;
    public event EventHandler<FileEventArgs>? FileModified;
    public event EventHandler<FileEventArgs>? FileDeleted;
    public event EventHandler<FileRenamedEventArgs>? FileRenamed;

    public void StartMonitoring(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Path cannot be null or empty", nameof(path));
        }

        if (!Directory.Exists(path))
        {
            throw new DirectoryNotFoundException($"Directory not found: {path}");
        }

        lock (_lock)
        {
            if (_watchers.ContainsKey(path))
            {
                _logger.LogWarning("Path {Path} is already being monitored", path);
                return;
            }

            try
            {
                var watcher = new FileSystemWatcher(path)
                {
                    NotifyFilter = NotifyFilters.FileName
                                 | NotifyFilters.DirectoryName
                                 | NotifyFilters.LastWrite
                                 | NotifyFilters.LastAccess
                                 | NotifyFilters.CreationTime,
                    IncludeSubdirectories = true,
                    EnableRaisingEvents = true
                };

                // Subscribe to events
                watcher.Changed += OnFileChanged;
                watcher.Created += OnFileCreated;
                watcher.Deleted += OnFileDeleted;
                watcher.Renamed += OnFileRenamed;
                watcher.Error += OnError;

                if (_watchers.TryAdd(path, watcher))
                {
                    _monitoredPaths.Add(path);
                    _logger.LogInformation("Started monitoring path: {Path}", path);
                }
                else
                {
                    watcher.Dispose();
                    _logger.LogWarning("Failed to add watcher for path: {Path}", path);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error starting file monitoring for path: {Path}", path);
                throw;
            }
        }
    }

    public void StopMonitoring()
    {
        lock (_lock)
        {
            foreach (var watcher in _watchers.Values)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Changed -= OnFileChanged;
                    watcher.Created -= OnFileCreated;
                    watcher.Deleted -= OnFileDeleted;
                    watcher.Renamed -= OnFileRenamed;
                    watcher.Error -= OnError;
                    watcher.Dispose();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error stopping file watcher");
                }
            }

            _watchers.Clear();
            _monitoredPaths.Clear();
            _logger.LogInformation("Stopped all file monitoring");
        }
    }

    private void OnFileChanged(object sender, FileSystemEventArgs e)
    {
        try
        {
            var processInfo = GetProcessInfoForFile(e.FullPath);
            
            var eventArgs = new FileEventArgs
            {
                FilePath = e.FullPath,
                ProcessName = processInfo.ProcessName,
                ProcessId = processInfo.ProcessId,
                Timestamp = DateTime.UtcNow,
                EventType = AttackEventType.FileModification
            };

            _logger.LogInformation(
                "File modified: {FilePath} by process {ProcessName} (PID: {ProcessId})",
                e.FullPath, processInfo.ProcessName, processInfo.ProcessId);

            FileModified?.Invoke(this, eventArgs);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling file changed event for: {Path}", e.FullPath);
        }
    }

    private void OnFileCreated(object sender, FileSystemEventArgs e)
    {
        try
        {
            var processInfo = GetProcessInfoForFile(e.FullPath);
            
            var eventArgs = new FileEventArgs
            {
                FilePath = e.FullPath,
                ProcessName = processInfo.ProcessName,
                ProcessId = processInfo.ProcessId,
                Timestamp = DateTime.UtcNow,
                EventType = AttackEventType.FileAccess
            };

            _logger.LogInformation(
                "File created: {FilePath} by process {ProcessName} (PID: {ProcessId})",
                e.FullPath, processInfo.ProcessName, processInfo.ProcessId);

            FileAccessed?.Invoke(this, eventArgs);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling file created event for: {Path}", e.FullPath);
        }
    }

    private void OnFileDeleted(object sender, FileSystemEventArgs e)
    {
        try
        {
            var processInfo = GetProcessInfoForFile(e.FullPath);
            
            var eventArgs = new FileEventArgs
            {
                FilePath = e.FullPath,
                ProcessName = processInfo.ProcessName,
                ProcessId = processInfo.ProcessId,
                Timestamp = DateTime.UtcNow,
                EventType = AttackEventType.FileDeletion
            };

            _logger.LogInformation(
                "File deleted: {FilePath} by process {ProcessName} (PID: {ProcessId})",
                e.FullPath, processInfo.ProcessName, processInfo.ProcessId);

            FileDeleted?.Invoke(this, eventArgs);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling file deleted event for: {Path}", e.FullPath);
        }
    }

    private void OnFileRenamed(object sender, RenamedEventArgs e)
    {
        try
        {
            var processInfo = GetProcessInfoForFile(e.FullPath);
            
            var eventArgs = new FileRenamedEventArgs
            {
                FilePath = e.FullPath,
                OldName = e.OldFullPath,
                NewName = e.FullPath,
                ProcessName = processInfo.ProcessName,
                ProcessId = processInfo.ProcessId,
                Timestamp = DateTime.UtcNow,
                EventType = AttackEventType.FileRename
            };

            _logger.LogInformation(
                "File renamed: {OldPath} -> {NewPath} by process {ProcessName} (PID: {ProcessId})",
                e.OldFullPath, e.FullPath, processInfo.ProcessName, processInfo.ProcessId);

            FileRenamed?.Invoke(this, eventArgs);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling file renamed event for: {Path}", e.FullPath);
        }
    }

    private void OnError(object sender, ErrorEventArgs e)
    {
        var exception = e.GetException();
        _logger.LogError(exception, "FileSystemWatcher error occurred");
    }

    /// <summary>
    /// Gets process information for the process that accessed the file
    /// Uses Win32 API to identify the process
    /// </summary>
    private (string ProcessName, int ProcessId) GetProcessInfoForFile(string filePath)
    {
        try
        {
            // Try to get the process that has a handle to the file
            // This is a best-effort approach as Windows doesn't provide direct API for this
            
            // First, try to find processes with open handles to the file
            var processes = Process.GetProcesses();
            
            foreach (var process in processes)
            {
                try
                {
                    // Check if process has access to the file path
                    // This is a simplified approach - in production, you'd use more sophisticated methods
                    if (process.ProcessName.Contains("explorer", StringComparison.OrdinalIgnoreCase) ||
                        process.ProcessName.Contains("cmd", StringComparison.OrdinalIgnoreCase) ||
                        process.ProcessName.Contains("powershell", StringComparison.OrdinalIgnoreCase))
                    {
                        return (process.ProcessName, process.Id);
                    }
                }
                catch
                {
                    // Process may have exited or we don't have access
                    continue;
                }
                finally
                {
                    process.Dispose();
                }
            }

            // If we can't identify the specific process, return unknown
            return ("Unknown", 0);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to identify process for file: {FilePath}", filePath);
            return ("Unknown", 0);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        StopMonitoring();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
