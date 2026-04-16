using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.UI.ViewModels;

/// <summary>
/// ViewModel for protection policy configuration.
/// Task 25.2: Protection configuration interface
/// </summary>
public class ProtectionConfigViewModel : INotifyPropertyChanged
{
    private readonly IAutomatedResponseSystem? _responseSystem;
    private readonly IWebBrowsingProtection? _webProtection;

    private bool _autoQuarantineEnabled = true;
    private bool _autoTerminateProcessEnabled = true;
    private bool _autoIsolateNetworkEnabled;
    private bool _createRestorePointBeforeAction = true;
    private ThreatSeverity _minimumSeverityForAutoResponse = ThreatSeverity.High;
    private string _newBlocklistEntry = string.Empty;

    public bool AutoQuarantineEnabled
    {
        get => _autoQuarantineEnabled;
        set { _autoQuarantineEnabled = value; OnPropertyChanged(); SavePolicy(); }
    }

    public bool AutoTerminateProcessEnabled
    {
        get => _autoTerminateProcessEnabled;
        set { _autoTerminateProcessEnabled = value; OnPropertyChanged(); SavePolicy(); }
    }

    public bool AutoIsolateNetworkEnabled
    {
        get => _autoIsolateNetworkEnabled;
        set { _autoIsolateNetworkEnabled = value; OnPropertyChanged(); SavePolicy(); }
    }

    public bool CreateRestorePointBeforeAction
    {
        get => _createRestorePointBeforeAction;
        set { _createRestorePointBeforeAction = value; OnPropertyChanged(); SavePolicy(); }
    }

    public ThreatSeverity MinimumSeverityForAutoResponse
    {
        get => _minimumSeverityForAutoResponse;
        set { _minimumSeverityForAutoResponse = value; OnPropertyChanged(); SavePolicy(); }
    }

    public string NewBlocklistEntry
    {
        get => _newBlocklistEntry;
        set { _newBlocklistEntry = value; OnPropertyChanged(); }
    }

    public ObservableCollection<string> BlocklistedUrls { get; } = new();
    public IEnumerable<ThreatSeverity> SeverityOptions { get; } = Enum.GetValues<ThreatSeverity>();

    public ProtectionConfigViewModel(
        IAutomatedResponseSystem? responseSystem = null,
        IWebBrowsingProtection? webProtection = null)
    {
        _responseSystem = responseSystem;
        _webProtection = webProtection;
        LoadCurrentConfig();
    }

    public void AddToBlocklist()
    {
        if (string.IsNullOrWhiteSpace(NewBlocklistEntry)) return;
        _webProtection?.AddToBlocklist(NewBlocklistEntry);
        if (!BlocklistedUrls.Contains(NewBlocklistEntry))
            BlocklistedUrls.Add(NewBlocklistEntry);
        NewBlocklistEntry = string.Empty;
    }

    public void RemoveFromBlocklist(string url)
    {
        _webProtection?.RemoveFromBlocklist(url);
        BlocklistedUrls.Remove(url);
    }

    private void LoadCurrentConfig()
    {
        if (_responseSystem != null)
        {
            var policy = _responseSystem.GetResponsePolicy();
            _autoQuarantineEnabled = policy.AutoQuarantineEnabled;
            _autoTerminateProcessEnabled = policy.AutoTerminateProcessEnabled;
            _autoIsolateNetworkEnabled = policy.AutoIsolateNetworkEnabled;
            _createRestorePointBeforeAction = policy.CreateRestorePointBeforeAction;
            _minimumSeverityForAutoResponse = policy.MinimumSeverityForAutoResponse;
        }

        if (_webProtection != null)
        {
            foreach (var url in _webProtection.GetBlocklist())
                BlocklistedUrls.Add(url);
        }
    }

    private void SavePolicy()
    {
        _responseSystem?.ConfigureResponsePolicy(new ResponsePolicy
        {
            AutoQuarantineEnabled = _autoQuarantineEnabled,
            AutoTerminateProcessEnabled = _autoTerminateProcessEnabled,
            AutoIsolateNetworkEnabled = _autoIsolateNetworkEnabled,
            CreateRestorePointBeforeAction = _createRestorePointBeforeAction,
            MinimumSeverityForAutoResponse = _minimumSeverityForAutoResponse
        });
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
