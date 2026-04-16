using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.UI.ViewModels;

/// <summary>
/// Main ViewModel for the Windows Honeypot Dashboard
/// Implements MVVM pattern with data binding and commands
/// </summary>
public partial class MainViewModel : ObservableObject
{
    private readonly ILogger<MainViewModel> _logger;
    private readonly IHoneypotManager _honeypotManager;
    private readonly IHoneyAccountSystem _honeyAccountSystem;
    private readonly IFileMonitor _fileMonitor;
    private readonly INetworkBlocker _networkBlocker;
    private DateTime _startTime;
    private System.Windows.Threading.DispatcherTimer? _uptimeTimer;

    [ObservableProperty]
    private bool _isProtectionEnabled;

    [ObservableProperty]
    private int _attacksBlocked;

    [ObservableProperty]
    private int _filesMonitored;

    [ObservableProperty]
    private string _uptime = "00:00:00";

    [ObservableProperty]
    private string _statusMessage = "Ready - Honeypot system initialized";

    [ObservableProperty]
    private string _statusIndicator = "MONITORING";

    [ObservableProperty]
    private bool _isActive;

    [ObservableProperty]
    private SandboxStatus _sandboxStatus = SandboxStatus.Stopped;

    [ObservableProperty]
    private NetworkBlockStatus _networkStatus = NetworkBlockStatus.Inactive;

    [ObservableProperty]
    private string _systemStatus = "Ready";

    [ObservableProperty]
    private int _credentialAttemptsCount;

    [ObservableProperty]
    private string _searchText = string.Empty;

    [ObservableProperty]
    private AttackEventType? _selectedEventTypeFilter;

    [ObservableProperty]
    private ThreatSeverity? _selectedSeverityFilter;

    partial void OnSearchTextChanged(string value)
    {
        // Auto-apply filters when search text changes
        if (string.IsNullOrEmpty(value) || value.Length >= 2)
        {
            ApplyFilters();
        }
    }

    partial void OnSelectedEventTypeFilterChanged(AttackEventType? value)
    {
        ApplyFilters();
    }

    partial void OnSelectedSeverityFilterChanged(ThreatSeverity? value)
    {
        ApplyFilters();
    }

    private ObservableCollection<AttackEvent> _allAttackEvents;
    public ObservableCollection<AttackEvent> AttackEvents { get; }
    public ObservableCollection<CredentialAttemptViewModel> CredentialAttempts { get; }
    public ObservableCollection<AttackEventType> EventTypeFilters { get; }
    public ObservableCollection<ThreatSeverity> SeverityFilters { get; }

    public MainViewModel(
        ILogger<MainViewModel> logger,
        IHoneypotManager honeypotManager,
        IHoneyAccountSystem honeyAccountSystem,
        IFileMonitor fileMonitor,
        INetworkBlocker networkBlocker)
    {
        _logger = logger;
        _honeypotManager = honeypotManager;
        _honeyAccountSystem = honeyAccountSystem;
        _fileMonitor = fileMonitor;
        _networkBlocker = networkBlocker;
        _startTime = DateTime.Now;

        _allAttackEvents = new ObservableCollection<AttackEvent>();
        AttackEvents = new ObservableCollection<AttackEvent>();
        CredentialAttempts = new ObservableCollection<CredentialAttemptViewModel>();
        
        // Initialize filter collections
        EventTypeFilters = new ObservableCollection<AttackEventType>(
            Enum.GetValues<AttackEventType>());
        SeverityFilters = new ObservableCollection<ThreatSeverity>(
            Enum.GetValues<ThreatSeverity>());

        InitializeEventHandlers();
        StartUptimeTimer();
        AddSampleData();

        _logger.LogInformation("MainViewModel initialized successfully");
    }

    private void InitializeEventHandlers()
    {
        // Subscribe to honeypot manager events
        _honeypotManager.IntrusionDetected += OnIntrusionDetected;
        _honeypotManager.SandboxStatusChanged += OnSandboxStatusChanged;

        // Subscribe to honey account system events
        _honeyAccountSystem.CredentialUsed += OnCredentialUsed;

        // Subscribe to file monitor events
        _fileMonitor.FileAccessed += OnFileAccessed;
        _fileMonitor.FileModified += OnFileModified;
    }

    private void OnIntrusionDetected(object? sender, IntrusionDetectedEventArgs e)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            _allAttackEvents.Insert(0, e.AttackEvent);
            ApplyFilters();
            AttacksBlocked = _allAttackEvents.Count;
            StatusMessage = $"🚨 ALERT: {e.AttackEvent.Description}";
            IsActive = true;

            _logger.LogWarning("Intrusion detected: {EventType} - {Description}", 
                e.AttackEvent.EventType, e.AttackEvent.Description);
        });
    }

    private void OnSandboxStatusChanged(object? sender, SandboxStatusChangedEventArgs e)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            SandboxStatus = e.NewStatus;
            UpdateSystemStatus();

            _logger.LogInformation("Sandbox status changed to: {Status}", e.NewStatus);
        });
    }

    private void OnCredentialUsed(object? sender, CredentialAttemptEventArgs e)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            var viewModel = CredentialAttemptViewModel.FromAttackerProfile(e.AttackerProfile);
            CredentialAttempts.Insert(0, viewModel);
            CredentialAttemptsCount = CredentialAttempts.Count;

            // Add to main activity log
            var attackEvent = new AttackEvent
            {
                Timestamp = e.Timestamp,
                EventType = AttackEventType.CredentialUsage,
                SourceProcess = e.AttackerProfile.Browser,
                TargetFile = e.Username,
                Description = $"Honey credentials accessed from {e.SourceIP}",
                Severity = ThreatSeverity.Critical
            };

            _allAttackEvents.Insert(0, attackEvent);
            ApplyFilters();
            AttacksBlocked = _allAttackEvents.Count;
            StatusMessage = $"🚨 CRITICAL: Credential theft detected from {e.SourceIP}";
            IsActive = true;

            _logger.LogWarning("Credential attempt: {Username} from {IP}", e.Username, e.SourceIP);
        });
    }

    private void OnFileAccessed(object? sender, FileEventArgs e)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            var attackEvent = new AttackEvent
            {
                Timestamp = DateTime.Now,
                EventType = AttackEventType.FileAccess,
                SourceProcess = e.ProcessName,
                ProcessId = e.ProcessId,
                TargetFile = e.FilePath,
                Description = $"File accessed: {Path.GetFileName(e.FilePath)}",
                Severity = ThreatSeverity.Medium
            };

            _allAttackEvents.Insert(0, attackEvent);
            ApplyFilters();
            AttacksBlocked = _allAttackEvents.Count;
            StatusMessage = $"File access detected: {Path.GetFileName(e.FilePath)}";
        });
    }

    private void OnFileModified(object? sender, FileEventArgs e)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            var attackEvent = new AttackEvent
            {
                Timestamp = DateTime.Now,
                EventType = AttackEventType.FileModification,
                SourceProcess = e.ProcessName,
                ProcessId = e.ProcessId,
                TargetFile = e.FilePath,
                Description = $"File modification attempt: {Path.GetFileName(e.FilePath)}",
                Severity = ThreatSeverity.High
            };

            _allAttackEvents.Insert(0, attackEvent);
            ApplyFilters();
            AttacksBlocked = _allAttackEvents.Count;
            StatusMessage = $"🚨 File modification blocked: {Path.GetFileName(e.FilePath)}";
            IsActive = true;
        });
    }

    [RelayCommand]
    private async Task ToggleProtectionAsync()
    {
        try
        {
            if (!IsActive) // If honeypot is not currently active, start it
            {
                // Start honeypot
                StatusMessage = "Starting honeypot...";
                
                var config = new SandboxConfiguration
                {
                    BaitFolderPath = @"C:\BaitFolder",
                    NetworkingEnabled = false,
                    DeceptionLevel = DeceptionLevel.High
                };

                bool success = await _honeypotManager.StartSandboxAsync(config);
                
                if (success)
                {
                    StatusMessage = "✅ Honeypot active - Monitoring for threats";
                    StatusIndicator = "ACTIVE";
                    IsActive = true;
                    IsProtectionEnabled = true;
                    _logger.LogInformation("Honeypot started successfully");
                }
                else
                {
                    StatusMessage = "❌ Failed to start honeypot - Check if Windows Sandbox is enabled";
                    IsProtectionEnabled = false;
                    IsActive = false;
                    _logger.LogError("Failed to start honeypot");
                }
            }
            else
            {
                // Stop honeypot
                StatusMessage = "Stopping honeypot...";
                await _honeypotManager.StopSandboxAsync();
                StatusMessage = "Honeypot stopped";
                StatusIndicator = "MONITORING";
                IsActive = false;
                IsProtectionEnabled = false;
                _logger.LogInformation("Honeypot stopped");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error toggling protection");
            StatusMessage = $"❌ Error: {ex.Message}";
            IsProtectionEnabled = false;
            IsActive = false;
        }
    }

    [RelayCommand]
    private void ConfigureBaitFolder()
    {
        try
        {
            var dialog = new Microsoft.Win32.OpenFolderDialog
            {
                Title = "Select Bait Folder",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
            };

            if (dialog.ShowDialog() == true)
            {
                StatusMessage = $"Bait folder configured: {dialog.FolderName}";
                _logger.LogInformation("Bait folder configured: {Path}", dialog.FolderName);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error configuring bait folder");
            MessageBox.Show($"Error configuring bait folder: {ex.Message}", "Error", 
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    [RelayCommand]
    private void ViewLogs()
    {
        try
        {
            StatusMessage = "Opening logs viewer...";
            MessageBox.Show("Logs viewer functionality will be implemented here.\n\n" +
                          $"Total Events: {AttackEvents.Count}\n" +
                          $"Credential Attempts: {CredentialAttempts.Count}",
                          "Logs Viewer", MessageBoxButton.OK, MessageBoxImage.Information);
            _logger.LogInformation("Logs viewer opened");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error opening logs viewer");
        }
    }

    [RelayCommand]
    private void ExportReport()
    {
        try
        {
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Export Report",
                Filter = "PDF Files (*.pdf)|*.pdf|JSON Files (*.json)|*.json|CSV Files (*.csv)|*.csv",
                DefaultExt = ".pdf",
                FileName = $"HoneypotReport_{DateTime.Now:yyyyMMdd_HHmmss}"
            };

            if (dialog.ShowDialog() == true)
            {
                StatusMessage = $"Report exported: {Path.GetFileName(dialog.FileName)}";
                MessageBox.Show($"Report exported successfully to:\n{dialog.FileName}", 
                    "Export Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                _logger.LogInformation("Report exported: {Path}", dialog.FileName);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error exporting report");
            MessageBox.Show($"Error exporting report: {ex.Message}", "Error", 
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    [RelayCommand]
    private async Task EmergencyCleanupAsync()
    {
        try
        {
            var result = MessageBox.Show(
                "⚠️ WARNING: This will immediately stop all honeypot activities and clean up all data.\n\n" +
                "Are you sure you want to proceed with emergency cleanup?",
                "Emergency Cleanup Confirmation",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                StatusMessage = "🚨 Performing emergency cleanup...";
                
                // Stop honeypot if running
                if (IsProtectionEnabled)
                {
                    await _honeypotManager.StopSandboxAsync();
                }

                // Clear all data
                _allAttackEvents.Clear();
                AttackEvents.Clear();
                CredentialAttempts.Clear();
                AttacksBlocked = 0;
                CredentialAttemptsCount = 0;
                IsProtectionEnabled = false;
                IsActive = false;

                StatusMessage = "✅ Emergency cleanup completed";
                MessageBox.Show("Emergency cleanup completed successfully.\n\nAll honeypot data has been cleared.", 
                    "Cleanup Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                
                _logger.LogWarning("Emergency cleanup performed");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during emergency cleanup");
            MessageBox.Show($"Error during cleanup: {ex.Message}", "Error", 
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    [RelayCommand]
    private void SearchLogs()
    {
        try
        {
            ApplyFilters();
            
            var filteredCount = AttackEvents.Count;
            var totalCount = _allAttackEvents.Count;
            
            if (string.IsNullOrWhiteSpace(SearchText) && !SelectedEventTypeFilter.HasValue && !SelectedSeverityFilter.HasValue)
            {
                StatusMessage = $"Showing all {totalCount} events";
            }
            else
            {
                StatusMessage = $"Found {filteredCount} matching events out of {totalCount} total";
            }
            
            _logger.LogInformation("Search/filter applied: Query='{Query}', EventType={EventType}, Severity={Severity}, Results={Count}", 
                SearchText, SelectedEventTypeFilter, SelectedSeverityFilter, filteredCount);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error searching logs");
        }
    }

    [RelayCommand]
    private void ClearSearch()
    {
        SearchText = string.Empty;
        SelectedEventTypeFilter = null;
        SelectedSeverityFilter = null;
        ApplyFilters();
        StatusMessage = $"Search cleared - Showing all {_allAttackEvents.Count} events";
    }

    [RelayCommand]
    private void FilterByEventType(AttackEventType? eventType)
    {
        SelectedEventTypeFilter = eventType;
        ApplyFilters();
    }

    [RelayCommand]
    private void FilterBySeverity(ThreatSeverity? severity)
    {
        SelectedSeverityFilter = severity;
        ApplyFilters();
    }

    private void ApplyFilters()
    {
        AttackEvents.Clear();

        var filtered = _allAttackEvents.AsEnumerable();

        // Apply search text filter
        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            var searchLower = SearchText.ToLower();
            filtered = filtered.Where(e =>
                e.Description.ToLower().Contains(searchLower) ||
                e.SourceProcess.ToLower().Contains(searchLower) ||
                e.TargetFile.ToLower().Contains(searchLower));
        }

        // Apply event type filter
        if (SelectedEventTypeFilter.HasValue)
        {
            filtered = filtered.Where(e => e.EventType == SelectedEventTypeFilter.Value);
        }

        // Apply severity filter
        if (SelectedSeverityFilter.HasValue)
        {
            filtered = filtered.Where(e => e.Severity == SelectedSeverityFilter.Value);
        }

        // Add filtered results to observable collection
        foreach (var attackEvent in filtered)
        {
            AttackEvents.Add(attackEvent);
        }
    }

    private void StartUptimeTimer()
    {
        _uptimeTimer = new System.Windows.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _uptimeTimer.Tick += (s, e) =>
        {
            var uptime = DateTime.Now - _startTime;
            Uptime = $"{uptime.Hours:D2}:{uptime.Minutes:D2}:{uptime.Seconds:D2}";
        };
        _uptimeTimer.Start();
    }

    private void UpdateSystemStatus()
    {
        SystemStatus = SandboxStatus switch
        {
            SandboxStatus.Running => "✅ Running",
            SandboxStatus.Starting => "⏳ Starting...",
            SandboxStatus.Stopping => "⏳ Stopping...",
            SandboxStatus.Error => "❌ Error",
            _ => "⏸️ Stopped"
        };
    }

    private void AddSampleData()
    {
        // Initialize with clean state - no sample data
        ApplyFilters();
        AttacksBlocked = 0;
        FilesMonitored = 0;
    }

    public void Cleanup()
    {
        _uptimeTimer?.Stop();

        _honeypotManager.IntrusionDetected -= OnIntrusionDetected;
        _honeypotManager.SandboxStatusChanged -= OnSandboxStatusChanged;
        _honeyAccountSystem.CredentialUsed -= OnCredentialUsed;
        _fileMonitor.FileAccessed -= OnFileAccessed;
        _fileMonitor.FileModified -= OnFileModified;

        _logger.LogInformation("MainViewModel cleaned up");
    }
}
