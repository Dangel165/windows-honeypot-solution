namespace WindowsHoneypot.Core.Interfaces;

/// <summary>
/// Base interface for event handlers in the honeypot system
/// </summary>
public interface IEventHandler
{
    /// <summary>
    /// Handles an event with the specified data
    /// </summary>
    /// <param name="eventData">Event data to handle</param>
    Task HandleEventAsync(object eventData);
}