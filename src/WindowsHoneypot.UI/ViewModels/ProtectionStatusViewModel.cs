using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.UI.ViewModels;

/// <summary>
/// ViewModel for unified protection status display.
/// Task 25.1: Extend WPF dashboard with protection status
/// </summary>
public class ProtectionStatusViewModel : INotifyPropertyChanged
{
    private readonly IRealTimeThreatMonitor? _threatMonitor;
    private readonly IAutomatedResponseSystem? _responseSystem;

    private bool _isProtectionActive;
    private bool _isEmailProtectionActive;
    private bool _isWebProtectionActive;
    private bool _isHardwareMonitoringActive;
    private int _totalThreatsBlocked;
    private string _protectionStatusText = "Protection Inactive";
    private string _protectionStatusColor = "#FF4444";

    public bool IsProtectionActive
    {
        get => _isProtectionActive;
        set { _isProtectionActive = value; OnPropertyChanged(); UpdateStatusDisplay(); }
    }

    public bool IsEmailProtectionActive
    {
        get => _isEmailProtectionActive;
        set { _isEmailProtectionActive = value; OnPropertyChanged(); }
    }

    public bool IsWebProtectionActive
    {
        get => _isWebProtectionActive;
        set { _isWebProtectionActive = value; OnPropertyChanged(); }
    }

    public bool IsHardwareMonitoringActive
    {
        get => _isHardwareMonitoringActive;
        set { _isHardwareMonitoringActive = value; OnPropertyChanged(); }
    }

    public int TotalThreatsBlocked
    {
        get => _totalThreatsBlocked;
        set { _totalThreatsBlocked = value; OnPropertyChanged(); }
    }

    public string ProtectionStatusText
    {
        get => _protectionStatusText;
        set { _protectionStatusText = value; OnPropertyChanged(); }
    }

    public string ProtectionStatusColor
    {
        get => _protectionStatusColor;
        set { _protectionStatusColor = value; OnPropertyChanged(); }
    }

    public ObservableCollection<ThreatNotification> RecentNotifications { get; } = new();
    public ObservableCollection<string> ActiveProtections { get; } = new();

    public ProtectionStatusViewModel(
        IRealTimeThreatMonitor? threatMonitor = null,
        IAutomatedResponseSystem? responseSystem = null)
    {
        _threatMonitor = threatMonitor;
        _responseSystem = responseSystem;

        if (_responseSystem != null)
            _responseSystem.NotificationRaised += OnNotificationRaised;
    }

    public void RefreshStatus()
    {
        if (_threatMonitor != null)
        {
            var status = _threatMonitor.GetProtectionStatus();
            IsProtectionActive = status.IsActive;
            var stats = _threatMonitor.GetStatistics();
            TotalThreatsBlocked = stats.TotalThreatsDetected;
        }

        UpdateActiveProtections();
    }

    private void UpdateActiveProtections()
    {
        ActiveProtections.Clear();
        if (IsProtectionActive) ActiveProtections.Add("Real-Time Threat Monitor");
        if (IsEmailProtectionActive) ActiveProtections.Add("Email Attachment Scanner");
        if (IsWebProtectionActive) ActiveProtections.Add("Web Browsing Protection");
        if (IsHardwareMonitoringActive) ActiveProtections.Add("Hardware Security Monitor");
    }

    private void UpdateStatusDisplay()
    {
        if (_isProtectionActive)
        {
            ProtectionStatusText = "Protection Active";
            ProtectionStatusColor = "#44FF44";
        }
        else
        {
            ProtectionStatusText = "Protection Inactive";
            ProtectionStatusColor = "#FF4444";
        }
    }

    private void OnNotificationRaised(object? sender, ThreatNotification notification)
    {
        System.Windows.Application.Current?.Dispatcher.Invoke(() =>
        {
            RecentNotifications.Insert(0, notification);
            if (RecentNotifications.Count > 50)
                RecentNotifications.RemoveAt(RecentNotifications.Count - 1);
        });
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
