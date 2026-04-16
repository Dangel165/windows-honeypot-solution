namespace WindowsHoneypot.Core.Models;

/// <summary>
/// Configuration settings for Windows Sandbox
/// </summary>
public class SandboxConfiguration
{
    /// <summary>
    /// Path to the bait folder to mount in the sandbox
    /// </summary>
    public string BaitFolderPath { get; set; } = string.Empty;

    /// <summary>
    /// Whether networking is enabled in the sandbox (should be false for security)
    /// </summary>
    public bool NetworkingEnabled { get; set; } = false;

    /// <summary>
    /// List of additional folders to mount in the sandbox
    /// </summary>
    public List<string> MountedFolders { get; set; } = new();

    /// <summary>
    /// Level of deception to apply
    /// </summary>
    public DeceptionLevel DeceptionLevel { get; set; } = DeceptionLevel.Medium;

    /// <summary>
    /// List of fake processes to create
    /// </summary>
    public List<ProcessProfile> FakeProcesses { get; set; } = new();

    /// <summary>
    /// Memory allocation for the sandbox in MB
    /// </summary>
    public int MemoryInMB { get; set; } = 4096;

    /// <summary>
    /// vGPU support enabled
    /// </summary>
    public bool VGpuEnabled { get; set; } = false;

    /// <summary>
    /// Audio input enabled
    /// </summary>
    public bool AudioInputEnabled { get; set; } = false;

    /// <summary>
    /// Video input enabled
    /// </summary>
    public bool VideoInputEnabled { get; set; } = false;

    /// <summary>
    /// Protected client enabled
    /// </summary>
    public bool ProtectedClientEnabled { get; set; } = true;

    /// <summary>
    /// Printer redirection enabled
    /// </summary>
    public bool PrinterRedirectionEnabled { get; set; } = false;

    /// <summary>
    /// Clipboard redirection enabled
    /// </summary>
    public bool ClipboardRedirectionEnabled { get; set; } = false;
}