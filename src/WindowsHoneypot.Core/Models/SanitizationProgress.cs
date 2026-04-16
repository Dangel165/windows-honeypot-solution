namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Progress information for sanitization operations
/// </summary>
public class SanitizationProgress
{
    /// <summary>
    /// Current operation being performed
    /// </summary>
    public SanitizationOperationType CurrentOperation { get; set; }

    /// <summary>
    /// Overall progress percentage (0-100)
    /// </summary>
    public int PercentComplete { get; set; }

    /// <summary>
    /// Current status message
    /// </summary>
    public string StatusMessage { get; set; } = string.Empty;

    /// <summary>
    /// Detailed description of current step
    /// </summary>
    public string DetailedMessage { get; set; } = string.Empty;

    /// <summary>
    /// Number of items processed in current operation
    /// </summary>
    public int ItemsProcessed { get; set; }

    /// <summary>
    /// Total number of items to process in current operation
    /// </summary>
    public int TotalItems { get; set; }
}
