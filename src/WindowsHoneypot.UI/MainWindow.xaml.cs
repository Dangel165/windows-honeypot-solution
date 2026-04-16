using Microsoft.Extensions.Logging;
using System.Windows;
using System.Windows.Input;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.UI.ViewModels;

namespace WindowsHoneypot.UI;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    private readonly ILogger<MainWindow> _logger;
    private readonly MainViewModel _viewModel;

    public MainWindow(
        ILogger<MainWindow> logger,
        MainViewModel viewModel)
    {
        InitializeComponent();
        
        _logger = logger;
        _viewModel = viewModel;
        
        DataContext = _viewModel;

        _logger.LogInformation("Main window initialized successfully with MVVM pattern");
    }

    private void CredentialAttemptsDataGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (((System.Windows.Controls.DataGrid)sender).SelectedItem is CredentialAttemptViewModel selectedAttempt)
        {
            ShowAttackerProfileDetails(selectedAttempt.AttackerProfile);
        }
    }

    private async void ProtectionToggle_Toggled(object sender, RoutedEventArgs e)
    {
        // Execute the command from ViewModel
        if (_viewModel.ToggleProtectionCommand.CanExecute(null))
        {
            await _viewModel.ToggleProtectionCommand.ExecuteAsync(null);
        }
    }

    private void ShowAttackerProfileDetails(Core.Models.AttackerProfile profile)
    {
        var details = $"Attacker Profile Details\n" +
                     $"========================\n\n" +
                     $"Session ID: {profile.SessionId}\n" +
                     $"IP Address: {profile.IPAddress}\n" +
                     $"Browser: {profile.Browser}\n" +
                     $"Operating System: {profile.OperatingSystem}\n" +
                     $"User Agent: {profile.UserAgent}\n\n" +
                     $"Screen Resolution: {profile.ScreenResolution}\n" +
                     $"Color Depth: {profile.ColorDepth}\n" +
                     $"Platform: {profile.Platform}\n" +
                     $"Language: {profile.Language}\n" +
                     $"Timezone: {profile.Timezone}\n\n" +
                     $"Hardware Concurrency: {profile.HardwareConcurrency}\n" +
                     $"Device Memory: {profile.DeviceMemory}\n" +
                     $"Cookies Enabled: {profile.CookiesEnabled}\n" +
                     $"Do Not Track: {profile.DoNotTrack}\n\n" +
                     $"Canvas Fingerprint: {profile.CanvasFingerprint}\n" +
                     $"WebGL Vendor: {profile.WebGLVendor}\n" +
                     $"WebGL Renderer: {profile.WebGLRenderer}\n" +
                     $"Audio Fingerprint: {profile.AudioFingerprint}\n\n" +
                     $"Browser Plugins: {string.Join(", ", profile.BrowserPlugins)}\n\n" +
                     $"Accessed Credentials:\n{string.Join("\n", profile.AccessedCredentials)}\n\n" +
                     $"First Seen: {profile.FirstSeen:yyyy-MM-dd HH:mm:ss}\n" +
                     $"Data Hash: {profile.DataHash}\n";

        MessageBox.Show(details, "Attacker Profile", MessageBoxButton.OK, MessageBoxImage.Information);
        
        _logger.LogInformation("Displayed attacker profile details for session: {SessionId}", profile.SessionId);
    }

    protected override void OnClosed(EventArgs e)
    {
        _viewModel.Cleanup();
        _logger.LogInformation("Main window closing");
        base.OnClosed(e);
    }
}
