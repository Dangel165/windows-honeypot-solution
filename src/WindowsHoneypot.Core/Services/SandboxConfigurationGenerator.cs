using System.Text;
using System.Xml;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Generates Windows Sandbox configuration (.wsb) files
/// </summary>
public class SandboxConfigurationGenerator
{
    /// <summary>
    /// Generates a .wsb XML configuration file from the provided configuration
    /// </summary>
    /// <param name="config">Sandbox configuration settings</param>
    /// <returns>XML content as a string</returns>
    public string GenerateWsbXml(SandboxConfiguration config)
    {
        if (config == null)
            throw new ArgumentNullException(nameof(config));

        var settings = new XmlWriterSettings
        {
            Indent = true,
            IndentChars = "  ",
            NewLineChars = "\n",
            Encoding = Encoding.UTF8,
            OmitXmlDeclaration = false
        };

        using var stringWriter = new StringWriter();
        using (var writer = XmlWriter.Create(stringWriter, settings))
        {
            writer.WriteStartDocument();
            writer.WriteStartElement("Configuration");

            // Networking configuration (disabled by default for security)
            writer.WriteElementString("Networking", config.NetworkingEnabled ? "Enable" : "Disable");

            // vGPU configuration
            writer.WriteElementString("VGpu", config.VGpuEnabled ? "Enable" : "Disable");

            // Audio input configuration
            writer.WriteElementString("AudioInput", config.AudioInputEnabled ? "Enable" : "Disable");

            // Video input configuration
            writer.WriteElementString("VideoInput", config.VideoInputEnabled ? "Enable" : "Disable");

            // Protected client configuration
            writer.WriteElementString("ProtectedClient", config.ProtectedClientEnabled ? "Enable" : "Disable");

            // Printer redirection configuration
            writer.WriteElementString("PrinterRedirection", config.PrinterRedirectionEnabled ? "Enable" : "Disable");

            // Clipboard redirection configuration
            writer.WriteElementString("ClipboardRedirection", config.ClipboardRedirectionEnabled ? "Enable" : "Disable");

            // Memory configuration
            writer.WriteElementString("MemoryInMB", config.MemoryInMB.ToString());

            // Mapped folders configuration
            WriteMappedFolders(writer, config);

            writer.WriteEndElement(); // Configuration
            writer.WriteEndDocument();
        }

        return stringWriter.ToString();
    }

    /// <summary>
    /// Writes the MappedFolders section of the .wsb file
    /// </summary>
    private void WriteMappedFolders(XmlWriter writer, SandboxConfiguration config)
    {
        var foldersToMount = new List<string>();

        // Add bait folder if specified
        if (!string.IsNullOrWhiteSpace(config.BaitFolderPath))
        {
            foldersToMount.Add(config.BaitFolderPath);
        }

        // Add additional mounted folders
        if (config.MountedFolders != null && config.MountedFolders.Count > 0)
        {
            foldersToMount.AddRange(config.MountedFolders.Where(f => !string.IsNullOrWhiteSpace(f)));
        }

        // Only write MappedFolders section if there are folders to mount
        if (foldersToMount.Count > 0)
        {
            writer.WriteStartElement("MappedFolders");

            foreach (var folderPath in foldersToMount)
            {
                WriteMappedFolder(writer, folderPath);
            }

            writer.WriteEndElement(); // MappedFolders
        }
    }

    /// <summary>
    /// Writes a single MappedFolder element
    /// </summary>
    private void WriteMappedFolder(XmlWriter writer, string folderPath)
    {
        writer.WriteStartElement("MappedFolder");

        // Host folder path
        writer.WriteElementString("HostFolder", folderPath);

        // Mount as ReadOnly for security (prevents attacker from modifying bait files)
        writer.WriteElementString("ReadOnly", "true");

        writer.WriteEndElement(); // MappedFolder
    }

    /// <summary>
    /// Saves the .wsb configuration to a file
    /// </summary>
    /// <param name="config">Sandbox configuration settings</param>
    /// <param name="filePath">Path where the .wsb file should be saved</param>
    public async Task SaveWsbFileAsync(SandboxConfiguration config, string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("File path cannot be null or empty", nameof(filePath));

        var xmlContent = GenerateWsbXml(config);
        await File.WriteAllTextAsync(filePath, xmlContent, Encoding.UTF8);
    }

    /// <summary>
    /// Validates that a folder path exists and is accessible
    /// </summary>
    /// <param name="folderPath">Path to validate</param>
    /// <returns>True if the folder exists and is accessible</returns>
    public bool ValidateFolderPath(string folderPath)
    {
        if (string.IsNullOrWhiteSpace(folderPath))
            return false;

        try
        {
            return Directory.Exists(folderPath);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Checks if Windows Sandbox is available on the system
    /// </summary>
    /// <returns>True if Windows Sandbox is available and enabled</returns>
    public bool IsWindowsSandboxAvailable()
    {
        try
        {
            // Check if Windows Sandbox feature is enabled
            using var process = new System.Diagnostics.Process();
            process.StartInfo.FileName = "dism";
            process.StartInfo.Arguments = "/online /get-featureinfo /featurename:Containers-DisposableClientVM";
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.CreateNoWindow = true;
            
            process.Start();
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            
            // Check if the feature is enabled
            return output.Contains("State : Enabled", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Validates the entire sandbox configuration
    /// </summary>
    /// <param name="config">Configuration to validate</param>
    /// <returns>Validation result with any error messages</returns>
    public ValidationResult ValidateConfiguration(SandboxConfiguration config)
    {
        var result = new ValidationResult { IsValid = true };

        if (config == null)
        {
            result.IsValid = false;
            result.Errors.Add("Configuration cannot be null");
            return result;
        }

        // Check if Windows Sandbox is available
        if (!IsWindowsSandboxAvailable())
        {
            result.IsValid = false;
            result.Errors.Add("Windows Sandbox is not available or enabled on this system. Please enable the 'Windows Sandbox' feature in Windows Features.");
        }

        // Validate bait folder if specified
        if (!string.IsNullOrWhiteSpace(config.BaitFolderPath))
        {
            if (!ValidateFolderPath(config.BaitFolderPath))
            {
                result.IsValid = false;
                result.Errors.Add($"Bait folder path does not exist or is not accessible: {config.BaitFolderPath}");
            }
        }

        // Validate mounted folders
        if (config.MountedFolders != null)
        {
            foreach (var folder in config.MountedFolders.Where(f => !string.IsNullOrWhiteSpace(f)))
            {
                if (!ValidateFolderPath(folder))
                {
                    result.IsValid = false;
                    result.Errors.Add($"Mounted folder path does not exist or is not accessible: {folder}");
                }
            }
        }

        // Validate memory allocation
        if (config.MemoryInMB < 512)
        {
            result.IsValid = false;
            result.Errors.Add("Memory allocation must be at least 512 MB");
        }

        if (config.MemoryInMB > 16384)
        {
            result.Warnings.Add("Memory allocation exceeds 16 GB, which may impact host system performance");
        }

        return result;
    }
}


