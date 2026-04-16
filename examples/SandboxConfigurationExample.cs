using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;

namespace WindowsHoneypot.Examples;

/// <summary>
/// Example demonstrating how to use the SandboxConfigurationGenerator
/// </summary>
public class SandboxConfigurationExample
{
    public static async Task Main(string[] args)
    {
        var generator = new SandboxConfigurationGenerator();

        // Example 1: Minimal configuration with networking disabled
        var minimalConfig = new SandboxConfiguration
        {
            NetworkingEnabled = false,
            MemoryInMB = 4096
        };

        Console.WriteLine("=== Example 1: Minimal Configuration ===");
        var minimalXml = generator.GenerateWsbXml(minimalConfig);
        Console.WriteLine(minimalXml);
        Console.WriteLine();

        // Example 2: Configuration with bait folder
        var baitConfig = new SandboxConfiguration
        {
            BaitFolderPath = @"C:\BaitDocuments",
            NetworkingEnabled = false,
            MemoryInMB = 4096,
            DeceptionLevel = DeceptionLevel.High
        };

        Console.WriteLine("=== Example 2: Configuration with Bait Folder ===");
        
        // Validate configuration before generating
        var validationResult = generator.ValidateConfiguration(baitConfig);
        if (!validationResult.IsValid)
        {
            Console.WriteLine("Configuration validation failed:");
            foreach (var error in validationResult.Errors)
            {
                Console.WriteLine($"  - {error}");
            }
        }
        else
        {
            var baitXml = generator.GenerateWsbXml(baitConfig);
            Console.WriteLine(baitXml);
            
            // Save to file
            var outputPath = Path.Combine(Path.GetTempPath(), "honeypot.wsb");
            await generator.SaveWsbFileAsync(baitConfig, outputPath);
            Console.WriteLine($"\nConfiguration saved to: {outputPath}");
        }
        Console.WriteLine();

        // Example 3: Complete configuration with all features
        var completeConfig = new SandboxConfiguration
        {
            BaitFolderPath = @"C:\BaitDocuments",
            MountedFolders = new List<string>
            {
                @"C:\SharedFiles",
                @"C:\Projects"
            },
            NetworkingEnabled = false,
            DeceptionLevel = DeceptionLevel.Maximum,
            MemoryInMB = 8192,
            VGpuEnabled = true,
            AudioInputEnabled = false,
            VideoInputEnabled = false,
            ProtectedClientEnabled = true,
            PrinterRedirectionEnabled = false,
            ClipboardRedirectionEnabled = false
        };

        Console.WriteLine("=== Example 3: Complete Configuration ===");
        var completeXml = generator.GenerateWsbXml(completeConfig);
        Console.WriteLine(completeXml);
        Console.WriteLine();

        // Example 4: Validation examples
        Console.WriteLine("=== Example 4: Validation Examples ===");
        
        // Invalid: insufficient memory
        var invalidConfig1 = new SandboxConfiguration
        {
            MemoryInMB = 256
        };
        var result1 = generator.ValidateConfiguration(invalidConfig1);
        Console.WriteLine($"Insufficient memory validation: {(result1.IsValid ? "PASS" : "FAIL")}");
        if (!result1.IsValid)
        {
            Console.WriteLine($"  Error: {result1.Errors[0]}");
        }

        // Warning: excessive memory
        var warningConfig = new SandboxConfiguration
        {
            MemoryInMB = 20480 // 20 GB
        };
        var result2 = generator.ValidateConfiguration(warningConfig);
        Console.WriteLine($"Excessive memory validation: {(result2.IsValid ? "PASS" : "FAIL")}");
        if (result2.Warnings.Count > 0)
        {
            Console.WriteLine($"  Warning: {result2.Warnings[0]}");
        }
    }
}
