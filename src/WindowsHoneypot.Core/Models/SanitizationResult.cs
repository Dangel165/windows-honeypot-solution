namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Result of a sanitization operation
/// </summary>
public class SanitizationResult
{
    /// <summary>
    /// Whether the sanitization was successful
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Total duration of the sanitization process
    /// </summary>
    public TimeSpan Duration { get; set; }

    /// <summary>
    /// Timestamp when sanitization started
    /// </summary>
    public DateTime StartTime { get; set; }

    /// <summary>
    /// Timestamp when sanitization completed
    /// </summary>
    public DateTime EndTime { get; set; }

    /// <summary>
    /// List of operations performed
    /// </summary>
    public List<SanitizationOperation> Operations { get; set; } = new();

    /// <summary>
    /// System state verification report
    /// </summary>
    public SystemStateReport? VerificationReport { get; set; }

    /// <summary>
    /// Any errors that occurred during sanitization
    /// </summary>
    public List<string> Errors { get; set; } = new();

    /// <summary>
    /// Any warnings generated during sanitization
    /// </summary>
    public List<string> Warnings { get; set; } = new();
}

/// <summary>
/// Represents a single sanitization operation
/// </summary>
public class SanitizationOperation
{
    /// <summary>
    /// Type of operation
    /// </summary>
    public SanitizationOperationType Type { get; set; }

    /// <summary>
    /// Whether the operation succeeded
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Duration of the operation
    /// </summary>
    public TimeSpan Duration { get; set; }

    /// <summary>
    /// Details about what was done
    /// </summary>
    public string Details { get; set; } = string.Empty;

    /// <summary>
    /// Error message if operation failed
    /// </summary>
    public string? ErrorMessage { get; set; }
}
