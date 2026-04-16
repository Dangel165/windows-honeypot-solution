using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Interfaces;

/// <summary>
/// Central orchestration and coordination of all honeypot activities
/// </summary>
public interface IHoneypotManager
{
    /// <summary>
    /// Starts the sandbox with the specified configuration
    /// </summary>
    /// <param name="config">Sandbox configuration settings</param>
    /// <returns>True if sandbox started successfully, false otherwise</returns>
    Task<bool> StartSandboxAsync(SandboxConfiguration config);

    /// <summary>
    /// Stops the currently running sandbox
    /// </summary>
    Task StopSandboxAsync();

    /// <summary>
    /// Gets the current status of the sandbox
    /// </summary>
    /// <returns>Current sandbox status</returns>
    SandboxStatus GetSandboxStatus();

    /// <summary>
    /// Registers an event handler for honeypot events
    /// </summary>
    /// <param name="handler">Event handler to register</param>
    void RegisterEventHandler(IEventHandler handler);

    /// <summary>
    /// Event fired when an intrusion is detected
    /// </summary>
    event EventHandler<IntrusionDetectedEventArgs>? IntrusionDetected;

    /// <summary>
    /// Event fired when sandbox status changes
    /// </summary>
    event EventHandler<SandboxStatusChangedEventArgs>? SandboxStatusChanged;
}