using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Central orchestration and coordination of all honeypot activities.
/// Manages the complete lifecycle of the honeypot system including sandbox management,
/// monitoring, deception, and intelligence gathering.
/// </summary>
public class HoneypotManager : IHoneypotManager, IDisposable
{
    private readonly ILogger<HoneypotManager> _logger;
    private readonly SandboxConfigurationGenerator _configGenerator;
    private readonly ProcessTracker _processTracker;
    private readonly IFileMonitor _fileMonitor;
    private readonly INetworkBlocker _networkBlocker;
    private readonly IDeceptionEngine _deceptionEngine;
    private readonly IIntrusionAlertSystem _intrusionAlertSystem;
    private readonly IProcessCamouflage _processCamouflage;
    private readonly IHoneyAccountSystem _honeyAccountSystem;
    private readonly IVisualReplayEngine _visualReplayEngine;
    private readonly IInstantSanitization _instantSanitization;
    private readonly ICommunityIntelligence _communityIntelligence;
    private readonly IConfigurationManager _configurationManager;
    private readonly PrivilegeMonitor _privilegeMonitor;
    private readonly ActivityLogger _activityLogger;

    private SandboxStatus _currentStatus = SandboxStatus.Stopped;
    private SandboxConfiguration? _currentConfiguration;
    private string? _currentWsbFilePath;
    private readonly List<IEventHandler> _eventHandlers = new();
    private readonly object _lockObject = new();
    private bool _disposed;

    /// <summary>
    /// Event fired when an intrusion is detected
    /// </summary>
    public event EventHandler<IntrusionDetectedEventArgs>? IntrusionDetected;

    /// <summary>
    /// Event fired when sandbox status changes
    /// </summary>
    public event EventHandler<SandboxStatusChangedEventArgs>? SandboxStatusChanged;

    public HoneypotManager(
        ILogger<HoneypotManager> logger,
        SandboxConfigurationGenerator configGenerator,
        ProcessTracker processTracker,
        IFileMonitor fileMonitor,
        INetworkBlocker networkBlocker,
        IDeceptionEngine deceptionEngine,
        IIntrusionAlertSystem intrusionAlertSystem,
        IProcessCamouflage processCamouflage,
        IHoneyAccountSystem honeyAccountSystem,
        IVisualReplayEngine visualReplayEngine,
        IInstantSanitization instantSanitization,
        ICommunityIntelligence communityIntelligence,
        IConfigurationManager configurationManager,
        PrivilegeMonitor privilegeMonitor,
        ActivityLogger activityLogger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _configGenerator = configGenerator ?? throw new ArgumentNullException(nameof(configGenerator));
        _processTracker = processTracker ?? throw new ArgumentNullException(nameof(processTracker));
        _fileMonitor = fileMonitor ?? throw new ArgumentNullException(nameof(fileMonitor));
        _networkBlocker = networkBlocker ?? throw new ArgumentNullException(nameof(networkBlocker));
        _deceptionEngine = deceptionEngine ?? throw new ArgumentNullException(nameof(deceptionEngine));
        _intrusionAlertSystem = intrusionAlertSystem ?? throw new ArgumentNullException(nameof(intrusionAlertSystem));
        _processCamouflage = processCamouflage ?? throw new ArgumentNullException(nameof(processCamouflage));
        _honeyAccountSystem = honeyAccountSystem ?? throw new ArgumentNullException(nameof(honeyAccountSystem));
        _visualReplayEngine = visualReplayEngine ?? throw new ArgumentNullException(nameof(visualReplayEngine));
        _instantSanitization = instantSanitization ?? throw new ArgumentNullException(nameof(instantSanitization));
        _communityIntelligence = communityIntelligence ?? throw new ArgumentNullException(nameof(communityIntelligence));
        _configurationManager = configurationManager ?? throw new ArgumentNullException(nameof(configurationManager));
        _privilegeMonitor = privilegeMonitor ?? throw new ArgumentNullException(nameof(privilegeMonitor));
        _activityLogger = activityLogger ?? throw new ArgumentNullException(nameof(activityLogger));

        InitializeEventHandlers();
        _logger.LogInformation("HoneypotManager initialized successfully");
    }

    /// <summary>
    /// Initializes event handlers for all subsystems
    /// </summary>
    private void InitializeEventHandlers()
    {
        // File Monitor events
        _fileMonitor.FileAccessed += OnFileAccessed;
        _fileMonitor.FileModified += OnFileModified;
        _fileMonitor.FileDeleted += OnFileDeleted;
        _fileMonitor.FileRenamed += OnFileRenamed;

        // Network Blocker events
        _networkBlocker.NetworkAttemptBlocked += OnNetworkAttemptBlocked;

        // Honey Account System events
        _honeyAccountSystem.CredentialUsed += OnCredentialUsed;

        // Process Tracker events
        _processTracker.ProcessExited += OnSandboxProcessExited;

        // Intrusion Alert System events
        _intrusionAlertSystem.IntrusionDetected += OnIntrusionDetectedInternal;

        // Community Intelligence events
        _communityIntelligence.ThreatIntelligenceReceived += OnThreatIntelligenceReceived;

        _logger.LogDebug("Event handlers initialized");
    }

    /// <summary>
    /// Starts the sandbox with the specified configuration
    /// </summary>
    public async Task<bool> StartSandboxAsync(SandboxConfiguration config)
    {
        if (config == null)
            throw new ArgumentNullException(nameof(config));

        lock (_lockObject)
        {
            if (_currentStatus != SandboxStatus.Stopped)
            {
                _logger.LogWarning("Cannot start sandbox: current status is {Status}", _currentStatus);
                return false;
            }

            UpdateStatus(SandboxStatus.Starting);
        }

        try
        {
            _logger.LogInformation("Starting honeypot with configuration: BaitFolder={BaitFolder}, DeceptionLevel={DeceptionLevel}",
                config.BaitFolderPath, config.DeceptionLevel);

            // Step 1: Validate configuration
            var validationResult = _configGenerator.ValidateConfiguration(config);
            if (!validationResult.IsValid)
            {
                _logger.LogError("Configuration validation failed: {Errors}", 
                    string.Join(", ", validationResult.Errors));
                UpdateStatus(SandboxStatus.Error);
                return false;
            }

            // Log warnings if any
            foreach (var warning in validationResult.Warnings)
            {
                _logger.LogWarning("Configuration warning: {Warning}", warning);
            }

            // Step 2: Apply deception techniques
            _logger.LogInformation("Applying deception techniques at level: {Level}", config.DeceptionLevel);
            await _deceptionEngine.ApplyHardwareSpoofingAsync(config.DeceptionLevel);

            // Step 3: Start process camouflage
            if (config.FakeProcesses != null && config.FakeProcesses.Count > 0)
            {
                _logger.LogInformation("Starting {Count} fake processes for camouflage", config.FakeProcesses.Count);
                await _processCamouflage.StartFakeProcessesAsync(config.FakeProcesses);
            }

            // Step 4: Plant honey credentials
            _logger.LogInformation("Planting honey credentials");
            var honeyAccounts = GenerateDefaultHoneyAccounts();
            await _honeyAccountSystem.PlantCredentialsAsync(honeyAccounts);
            await _honeyAccountSystem.StartFakeServerAsync(8080);

            // Step 5: Enable network blocking
            _logger.LogInformation("Enabling network traffic blocking");
            await _networkBlocker.BlockAllTrafficAsync();

            // Step 6: Generate .wsb configuration file
            _logger.LogInformation("Generating Windows Sandbox configuration file");
            _currentWsbFilePath = Path.Combine(Path.GetTempPath(), $"honeypot_{Guid.NewGuid()}.wsb");
            await _configGenerator.SaveWsbFileAsync(config, _currentWsbFilePath);

            // Step 7: Start sandbox process
            _logger.LogInformation("Launching Windows Sandbox");
            bool sandboxStarted = await _processTracker.StartTrackingAsync(_currentWsbFilePath);
            
            if (!sandboxStarted)
            {
                _logger.LogError("Failed to start Windows Sandbox");
                await CleanupAfterFailureAsync();
                UpdateStatus(SandboxStatus.Error);
                return false;
            }

            // Step 8: Start file monitoring
            if (!string.IsNullOrWhiteSpace(config.BaitFolderPath))
            {
                _logger.LogInformation("Starting file system monitoring on: {Path}", config.BaitFolderPath);
                _fileMonitor.StartMonitoring(config.BaitFolderPath);
            }

            // Step 9: Start visual replay recording
            _logger.LogInformation("Starting visual replay recording");
            _visualReplayEngine.StartRecording();

            // Step 10: Start privilege monitoring
            if (_processTracker.SandboxProcessId.HasValue)
            {
                _logger.LogInformation("Starting privilege escalation monitoring");
                _privilegeMonitor.StartMonitoring(new List<int> { _processTracker.SandboxProcessId.Value });
            }

            // Store current configuration
            lock (_lockObject)
            {
                _currentConfiguration = config;
                UpdateStatus(SandboxStatus.Running);
            }

            _logger.LogInformation("Honeypot started successfully");
            _activityLogger.LogActivity(new AttackEvent
            {
                Timestamp = DateTime.UtcNow,
                EventType = AttackEventType.ProcessCreation,
                Description = "Honeypot system started",
                Severity = ThreatSeverity.Low
            });

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error starting honeypot");
            await CleanupAfterFailureAsync();
            UpdateStatus(SandboxStatus.Error);
            return false;
        }
    }

    /// <summary>
    /// Stops the currently running sandbox
    /// </summary>
    public async Task StopSandboxAsync()
    {
        lock (_lockObject)
        {
            if (_currentStatus == SandboxStatus.Stopped)
            {
                _logger.LogInformation("Sandbox is already stopped");
                return;
            }

            UpdateStatus(SandboxStatus.Stopping);
        }

        try
        {
            _logger.LogInformation("Stopping honeypot");

            // Step 1: Stop visual replay recording
            _logger.LogDebug("Stopping visual replay recording");
            _visualReplayEngine.StopRecording();

            // Step 2: Stop file monitoring
            _logger.LogDebug("Stopping file system monitoring");
            _fileMonitor.StopMonitoring();

            // Step 3: Stop privilege monitoring
            _logger.LogDebug("Stopping privilege monitoring");
            _privilegeMonitor.StopMonitoring();

            // Step 4: Stop sandbox process
            _logger.LogDebug("Stopping Windows Sandbox process");
            await _processTracker.StopTrackingAsync();

            // Step 5: Stop honey account server
            _logger.LogDebug("Stopping honey account server");
            await _honeyAccountSystem.StopFakeServerAsync();

            // Step 6: Stop fake processes
            _logger.LogDebug("Stopping fake processes");
            await _processCamouflage.StopAllFakeProcessesAsync();

            // Step 7: Restore network settings
            _logger.LogDebug("Restoring network settings");
            await _networkBlocker.RestoreFirewallRulesAsync();

            // Step 8: Restore deception settings
            _logger.LogDebug("Restoring system settings");
            await _deceptionEngine.RestoreOriginalSettingsAsync();

            // Step 9: Clean up temporary files
            if (!string.IsNullOrWhiteSpace(_currentWsbFilePath) && File.Exists(_currentWsbFilePath))
            {
                _logger.LogDebug("Cleaning up temporary .wsb file");
                try
                {
                    File.Delete(_currentWsbFilePath);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to delete temporary .wsb file: {Path}", _currentWsbFilePath);
                }
            }

            lock (_lockObject)
            {
                _currentConfiguration = null;
                _currentWsbFilePath = null;
                UpdateStatus(SandboxStatus.Stopped);
            }

            _logger.LogInformation("Honeypot stopped successfully");
            _activityLogger.LogActivity(new AttackEvent
            {
                Timestamp = DateTime.UtcNow,
                EventType = AttackEventType.ProcessCreation,
                Description = "Honeypot system stopped",
                Severity = ThreatSeverity.Low
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error stopping honeypot");
            UpdateStatus(SandboxStatus.Error);
            throw;
        }
    }

    /// <summary>
    /// Gets the current status of the sandbox
    /// </summary>
    public SandboxStatus GetSandboxStatus()
    {
        lock (_lockObject)
        {
            return _currentStatus;
        }
    }

    /// <summary>
    /// Registers an event handler for honeypot events
    /// </summary>
    public void RegisterEventHandler(IEventHandler handler)
    {
        if (handler == null)
            throw new ArgumentNullException(nameof(handler));

        lock (_lockObject)
        {
            if (!_eventHandlers.Contains(handler))
            {
                _eventHandlers.Add(handler);
                _logger.LogDebug("Event handler registered: {HandlerType}", handler.GetType().Name);
            }
        }
    }

    /// <summary>
    /// Updates the sandbox status and fires status changed event
    /// </summary>
    private void UpdateStatus(SandboxStatus newStatus)
    {
        SandboxStatus oldStatus;
        
        lock (_lockObject)
        {
            oldStatus = _currentStatus;
            _currentStatus = newStatus;
        }

        if (oldStatus != newStatus)
        {
            _logger.LogInformation("Sandbox status changed: {OldStatus} -> {NewStatus}", oldStatus, newStatus);
            
            SandboxStatusChanged?.Invoke(this, new SandboxStatusChangedEventArgs
            {
                OldStatus = oldStatus,
                NewStatus = newStatus
            });

            // Notify registered event handlers
            NotifyEventHandlers(new SandboxStatusChangedEventArgs
            {
                OldStatus = oldStatus,
                NewStatus = newStatus
            });
        }
    }

    /// <summary>
    /// Cleans up resources after a failed startup
    /// </summary>
    private async Task CleanupAfterFailureAsync()
    {
        _logger.LogWarning("Performing cleanup after failed startup");

        try
        {
            await _processTracker.StopTrackingAsync();
            await _honeyAccountSystem.StopFakeServerAsync();
            await _processCamouflage.StopAllFakeProcessesAsync();
            await _networkBlocker.RestoreFirewallRulesAsync();
            await _deceptionEngine.RestoreOriginalSettingsAsync();
            _fileMonitor.StopMonitoring();
            _visualReplayEngine.StopRecording();
            _privilegeMonitor.StopMonitoring();

            if (!string.IsNullOrWhiteSpace(_currentWsbFilePath) && File.Exists(_currentWsbFilePath))
            {
                File.Delete(_currentWsbFilePath);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during cleanup after failure");
        }
    }

    /// <summary>
    /// Generates default honey accounts for credential trapping
    /// </summary>
    private List<HoneyAccount> GenerateDefaultHoneyAccounts()
    {
        return new List<HoneyAccount>
        {
            new HoneyAccount
            {
                ServiceName = "Corporate Email",
                Username = "admin@company.local",
                Password = "P@ssw0rd123!",
                ServiceUrl = "http://localhost:8080/login/email"
            },
            new HoneyAccount
            {
                ServiceName = "Database Admin",
                Username = "dbadmin",
                Password = "DbP@ss2024",
                ServiceUrl = "http://localhost:8080/login/database"
            },
            new HoneyAccount
            {
                ServiceName = "VPN Access",
                Username = "vpn_user",
                Password = "Vpn$ecure99",
                ServiceUrl = "http://localhost:8080/login/vpn"
            }
        };
    }

    /// <summary>
    /// Notifies all registered event handlers
    /// </summary>
    private void NotifyEventHandlers(EventArgs eventArgs)
    {
        List<IEventHandler> handlers;
        
        lock (_lockObject)
        {
            handlers = new List<IEventHandler>(_eventHandlers);
        }

        foreach (var handler in handlers)
        {
            try
            {
                handler.HandleEventAsync(eventArgs).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in event handler: {HandlerType}", handler.GetType().Name);
            }
        }
    }

    #region Event Handlers

    private void OnFileAccessed(object? sender, FileEventArgs e)
    {
        _logger.LogInformation("File accessed: {FilePath} by {ProcessName} (PID: {ProcessId})",
            e.FilePath, e.ProcessName, e.ProcessId);

        var attackEvent = new AttackEvent
        {
            Timestamp = DateTime.UtcNow,
            EventType = AttackEventType.FileAccess,
            SourceProcess = e.ProcessName,
            ProcessId = e.ProcessId,
            TargetFile = e.FilePath,
            Description = $"File accessed: {Path.GetFileName(e.FilePath)}",
            Severity = ThreatSeverity.Medium
        };

        _intrusionAlertSystem.TriggerAlert(attackEvent);
        _activityLogger.LogActivity(attackEvent);
    }

    private void OnFileModified(object? sender, FileEventArgs e)
    {
        _logger.LogWarning("File modification attempt: {FilePath} by {ProcessName} (PID: {ProcessId})",
            e.FilePath, e.ProcessName, e.ProcessId);

        var attackEvent = new AttackEvent
        {
            Timestamp = DateTime.UtcNow,
            EventType = AttackEventType.FileModification,
            SourceProcess = e.ProcessName,
            ProcessId = e.ProcessId,
            TargetFile = e.FilePath,
            Description = $"File modification attempt blocked: {Path.GetFileName(e.FilePath)}",
            Severity = ThreatSeverity.High
        };

        _intrusionAlertSystem.TriggerAlert(attackEvent);
        _activityLogger.LogActivity(attackEvent);
        
        // Share threat intelligence
        ShareThreatIntelligence(attackEvent);
    }

    private void OnFileDeleted(object? sender, FileEventArgs e)
    {
        _logger.LogWarning("File deletion attempt: {FilePath} by {ProcessName} (PID: {ProcessId})",
            e.FilePath, e.ProcessName, e.ProcessId);

        var attackEvent = new AttackEvent
        {
            Timestamp = DateTime.UtcNow,
            EventType = AttackEventType.FileDeletion,
            SourceProcess = e.ProcessName,
            ProcessId = e.ProcessId,
            TargetFile = e.FilePath,
            Description = $"File deletion attempt: {Path.GetFileName(e.FilePath)}",
            Severity = ThreatSeverity.High
        };

        _intrusionAlertSystem.TriggerAlert(attackEvent);
        _activityLogger.LogActivity(attackEvent);
        
        // Share threat intelligence
        ShareThreatIntelligence(attackEvent);
    }

    private void OnFileRenamed(object? sender, FileRenamedEventArgs e)
    {
        _logger.LogWarning("File rename attempt: {OldName} -> {NewName} by {ProcessName} (PID: {ProcessId})",
            e.OldName, e.FilePath, e.ProcessName, e.ProcessId);

        var attackEvent = new AttackEvent
        {
            Timestamp = DateTime.UtcNow,
            EventType = AttackEventType.FileRename,
            SourceProcess = e.ProcessName,
            ProcessId = e.ProcessId,
            TargetFile = e.FilePath,
            Description = $"File rename attempt: {Path.GetFileName(e.OldName)} -> {Path.GetFileName(e.FilePath)}",
            Severity = ThreatSeverity.Medium
        };

        _intrusionAlertSystem.TriggerAlert(attackEvent);
        _activityLogger.LogActivity(attackEvent);
    }

    private void OnNetworkAttemptBlocked(object? sender, NetworkAttemptBlockedEventArgs e)
    {
        var destination = $"{e.NetworkAttempt.DestinationIP}:{e.NetworkAttempt.DestinationPort}";
        _logger.LogWarning("Network attempt blocked: {Destination} from {ProcessName}",
            destination, e.NetworkAttempt.ProcessName);

        var attackEvent = new AttackEvent
        {
            Timestamp = DateTime.UtcNow,
            EventType = AttackEventType.NetworkAttempt,
            SourceProcess = e.NetworkAttempt.ProcessName,
            TargetFile = destination,
            Description = $"Network connection blocked: {destination}",
            Severity = ThreatSeverity.High
        };

        _intrusionAlertSystem.TriggerAlert(attackEvent);
        _activityLogger.LogActivity(attackEvent);
        
        // Share threat intelligence
        ShareThreatIntelligence(attackEvent);
    }

    private void OnCredentialUsed(object? sender, CredentialAttemptEventArgs e)
    {
        _logger.LogCritical("Honey credential used: {Username} from {SourceIP} - Browser: {Browser}",
            e.Username, e.SourceIP, e.AttackerProfile.Browser);

        var attackEvent = new AttackEvent
        {
            Timestamp = e.Timestamp,
            EventType = AttackEventType.CredentialUsage,
            SourceProcess = e.AttackerProfile.Browser,
            TargetFile = e.Username,
            Description = $"Honey credentials accessed from {e.SourceIP}",
            Severity = ThreatSeverity.Critical
        };

        _intrusionAlertSystem.TriggerAlert(attackEvent);
        _activityLogger.LogActivity(attackEvent);
        
        // Share critical threat intelligence
        ShareThreatIntelligence(attackEvent, e.SourceIP);
    }

    private void OnSandboxProcessExited(object? sender, ProcessExitedEventArgs e)
    {
        _logger.LogWarning("Sandbox process exited unexpectedly (PID: {ProcessId})", e.ProcessId);

        // Trigger automatic cleanup
        Task.Run(async () =>
        {
            try
            {
                await StopSandboxAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during automatic cleanup after sandbox exit");
            }
        });
    }

    private void OnIntrusionDetectedInternal(object? sender, IntrusionDetectedEventArgs e)
    {
        // Forward intrusion detection event to external subscribers
        IntrusionDetected?.Invoke(this, e);
        
        // Notify registered event handlers
        NotifyEventHandlers(e);
    }

    private void OnThreatIntelligenceReceived(object? sender, ThreatIntelligenceReceivedEventArgs e)
    {
        _logger.LogInformation("Received {Count} threat indicators from community intelligence",
            e.ThreatIndicators.Count);

        // Process threat indicators and update local defenses
        foreach (var indicator in e.ThreatIndicators)
        {
            _logger.LogDebug("Processing threat indicator: {Type} - {Value}",
                indicator.Type, indicator.Value);
        }
    }

    #endregion

    /// <summary>
    /// Shares threat intelligence with the community
    /// </summary>
    private void ShareThreatIntelligence(AttackEvent attackEvent, string? attackerIp = null)
    {
        try
        {
            var threatData = new ThreatData
            {
                ThreatId = Guid.NewGuid().ToString(),
                AttackerIP = attackerIp ?? "Unknown",
                AttackPatterns = new List<string> { attackEvent.EventType.ToString() },
                DetectionTime = attackEvent.Timestamp,
                Severity = attackEvent.Severity,
                Indicators = new Dictionary<string, string>
                {
                    { "EventType", attackEvent.EventType.ToString() },
                    { "SourceProcess", attackEvent.SourceProcess },
                    { "TargetFile", attackEvent.TargetFile }
                }
            };

            // Share asynchronously without blocking
            Task.Run(async () =>
            {
                try
                {
                    await _communityIntelligence.ShareThreatDataAsync(threatData);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to share threat intelligence");
                }
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error preparing threat intelligence for sharing");
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _logger.LogInformation("Disposing HoneypotManager");

        // Unsubscribe from events
        _fileMonitor.FileAccessed -= OnFileAccessed;
        _fileMonitor.FileModified -= OnFileModified;
        _fileMonitor.FileDeleted -= OnFileDeleted;
        _fileMonitor.FileRenamed -= OnFileRenamed;
        _networkBlocker.NetworkAttemptBlocked -= OnNetworkAttemptBlocked;
        _honeyAccountSystem.CredentialUsed -= OnCredentialUsed;
        _processTracker.ProcessExited -= OnSandboxProcessExited;
        _intrusionAlertSystem.IntrusionDetected -= OnIntrusionDetectedInternal;
        _communityIntelligence.ThreatIntelligenceReceived -= OnThreatIntelligenceReceived;

        // Stop sandbox if running
        if (_currentStatus == SandboxStatus.Running)
        {
            try
            {
                StopSandboxAsync().GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error stopping sandbox during disposal");
            }
        }

        _disposed = true;
        _logger.LogInformation("HoneypotManager disposed");
    }
}
