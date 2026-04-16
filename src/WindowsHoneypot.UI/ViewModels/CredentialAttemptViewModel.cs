using System.ComponentModel;
using System.Runtime.CompilerServices;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.UI.ViewModels;

/// <summary>
/// ViewModel for displaying credential attempt information in the dashboard
/// </summary>
public class CredentialAttemptViewModel : INotifyPropertyChanged
{
    private string _timestamp = string.Empty;
    private string _username = string.Empty;
    private string _ipAddress = string.Empty;
    private string _browser = string.Empty;
    private string _operatingSystem = string.Empty;
    private string _location = string.Empty;
    private string _screenResolution = string.Empty;

    public string Timestamp
    {
        get => _timestamp;
        set { _timestamp = value; OnPropertyChanged(); }
    }

    public string Username
    {
        get => _username;
        set { _username = value; OnPropertyChanged(); }
    }

    public string IPAddress
    {
        get => _ipAddress;
        set { _ipAddress = value; OnPropertyChanged(); }
    }

    public string Browser
    {
        get => _browser;
        set { _browser = value; OnPropertyChanged(); }
    }

    public string OperatingSystem
    {
        get => _operatingSystem;
        set { _operatingSystem = value; OnPropertyChanged(); }
    }

    public string Location
    {
        get => _location;
        set { _location = value; OnPropertyChanged(); }
    }

    public string ScreenResolution
    {
        get => _screenResolution;
        set { _screenResolution = value; OnPropertyChanged(); }
    }

    public AttackerProfile AttackerProfile { get; set; } = new();

    public event PropertyChangedEventHandler? PropertyChanged;

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    public static CredentialAttemptViewModel FromAttackerProfile(AttackerProfile profile)
    {
        return new CredentialAttemptViewModel
        {
            Timestamp = profile.FirstSeen.ToString("yyyy-MM-dd HH:mm:ss"),
            Username = profile.AccessedCredentials.FirstOrDefault()?.Split(':').FirstOrDefault() ?? "Unknown",
            IPAddress = profile.IPAddress,
            Browser = profile.Browser,
            OperatingSystem = profile.OperatingSystem,
            Location = profile.GeographicLocation,
            ScreenResolution = profile.ScreenResolution,
            AttackerProfile = profile
        };
    }
}
