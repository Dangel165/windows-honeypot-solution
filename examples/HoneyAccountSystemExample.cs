using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;

namespace WindowsHoneypot.Examples;

/// <summary>
/// Example demonstrating the Honey Account System functionality
/// </summary>
public class HoneyAccountSystemExample
{
    public static async Task Main(string[] args)
    {
        // Setup dependency injection
        var services = new ServiceCollection();
        services.AddLogging(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Information);
        });
        services.AddSingleton<IHoneyAccountSystem, HoneyAccountSystem>();

        var serviceProvider = services.BuildServiceProvider();
        var honeyAccountSystem = serviceProvider.GetRequiredService<IHoneyAccountSystem>();

        Console.WriteLine("=== Windows Honeypot - Honey Account System Example ===\n");

        // Subscribe to credential usage events
        honeyAccountSystem.CredentialUsed += (sender, args) =>
        {
            Console.WriteLine("\n🚨 ALERT: Credential Theft Detected!");
            Console.WriteLine($"Username: {args.Username}");
            Console.WriteLine($"Password: {args.Password}");
            Console.WriteLine($"Source IP: {args.SourceIP}");
            Console.WriteLine($"User Agent: {args.UserAgent}");
            
            Console.WriteLine("\n📊 Enhanced Attacker Profile:");
            Console.WriteLine($"  Browser: {args.AttackerProfile.Browser}");
            Console.WriteLine($"  OS: {args.AttackerProfile.OperatingSystem}");
            Console.WriteLine($"  Screen Resolution: {args.AttackerProfile.ScreenResolution}");
            Console.WriteLine($"  Color Depth: {args.AttackerProfile.ColorDepth}");
            Console.WriteLine($"  Platform: {args.AttackerProfile.Platform}");
            Console.WriteLine($"  Timezone: {args.AttackerProfile.Timezone}");
            Console.WriteLine($"  Hardware Concurrency: {args.AttackerProfile.HardwareConcurrency}");
            Console.WriteLine($"  Device Memory: {args.AttackerProfile.DeviceMemory}");
            Console.WriteLine($"  Cookies Enabled: {args.AttackerProfile.CookiesEnabled}");
            Console.WriteLine($"  Do Not Track: {args.AttackerProfile.DoNotTrack}");
            
            Console.WriteLine("\n🔍 Advanced Fingerprinting:");
            Console.WriteLine($"  Canvas Fingerprint: {args.AttackerProfile.CanvasFingerprint}");
            Console.WriteLine($"  WebGL Vendor: {args.AttackerProfile.WebGLVendor}");
            Console.WriteLine($"  WebGL Renderer: {args.AttackerProfile.WebGLRenderer}");
            Console.WriteLine($"  Audio Fingerprint: {args.AttackerProfile.AudioFingerprint}");
            
            Console.WriteLine("\n🔒 Evidence Storage:");
            Console.WriteLine($"  Data Hash: {args.AttackerProfile.DataHash}");
            Console.WriteLine($"  Encrypted: {!string.IsNullOrEmpty(args.AttackerProfile.EncryptedData)}");
            
            Console.WriteLine($"\nTimestamp: {args.Timestamp:yyyy-MM-dd HH:mm:ss}");
        };

        // Create honey accounts
        var honeyAccounts = new List<HoneyAccount>
        {
            new HoneyAccount
            {
                Username = "admin@company.com",
                Password = "CompanyAdmin2024!",
                ServiceUrl = "http://localhost:5000/login",
                ServiceName = "Company Admin Portal",
                Description = "Main administrative access",
                PlantInBookmarks = true,
                PlantInTextFiles = true
            },
            new HoneyAccount
            {
                Username = "finance.manager",
                Password = "Finance$ecure123",
                ServiceUrl = "http://localhost:5000/finance",
                ServiceName = "Financial System",
                Description = "Finance department access",
                PlantInBookmarks = true,
                PlantInTextFiles = true
            },
            new HoneyAccount
            {
                Username = "hr.director@company.com",
                Password = "HRDir3ct0r!2024",
                ServiceUrl = "http://localhost:5000/hr",
                ServiceName = "HR Management System",
                Description = "Human resources portal",
                PlantInBookmarks = true,
                PlantInTextFiles = true
            }
        };

        try
        {
            // Step 1: Plant fake credentials
            Console.WriteLine("Step 1: Planting fake credentials...");
            await honeyAccountSystem.PlantCredentialsAsync(honeyAccounts);
            Console.WriteLine("✓ Credentials planted successfully!");
            Console.WriteLine($"  - Created passwords.txt on Desktop");
            Console.WriteLine($"  - Created Important_Bookmarks.txt on Desktop");
            Console.WriteLine($"  - Created account_info.txt in Documents");
            Console.WriteLine();

            // Step 2: Start fake login server
            Console.WriteLine("Step 2: Starting fake login server...");
            int port = 5000;
            await honeyAccountSystem.StartFakeServerAsync(port);
            Console.WriteLine($"✓ Fake server started on http://localhost:{port}");
            Console.WriteLine();

            // Display instructions
            Console.WriteLine("=== Server is Running ===");
            Console.WriteLine($"Visit http://localhost:{port}/login in your browser to test");
            Console.WriteLine("Try logging in with any of the planted credentials:");
            foreach (var account in honeyAccounts)
            {
                Console.WriteLine($"  - {account.Username} / {account.Password}");
            }
            Console.WriteLine();
            Console.WriteLine("The system will capture:");
            Console.WriteLine("  • IP Address");
            Console.WriteLine("  • Browser fingerprint (Canvas, WebGL, Audio)");
            Console.WriteLine("  • User-Agent string");
            Console.WriteLine("  • Screen resolution and color depth");
            Console.WriteLine("  • Timezone and language");
            Console.WriteLine("  • Browser plugins");
            Console.WriteLine("  • Operating system");
            Console.WriteLine("  • Hardware information (CPU cores, memory)");
            Console.WriteLine("  • Encrypted evidence with integrity hash");
            Console.WriteLine();
            Console.WriteLine("Press any key to stop the server...");
            Console.ReadKey();

            // Step 3: Stop the server
            Console.WriteLine("\n\nStep 3: Stopping fake server...");
            await honeyAccountSystem.StopFakeServerAsync();
            Console.WriteLine("✓ Server stopped successfully");
            Console.WriteLine();

            // Display summary
            Console.WriteLine("=== Summary ===");
            Console.WriteLine("The Honey Account System:");
            Console.WriteLine("1. Plants fake credentials in multiple locations");
            Console.WriteLine("2. Runs an internal fake login server");
            Console.WriteLine("3. Captures detailed attacker information");
            Console.WriteLine("4. Provides real-time alerts on credential usage");
            Console.WriteLine();
            Console.WriteLine("This allows security teams to:");
            Console.WriteLine("• Identify attackers before they cause damage");
            Console.WriteLine("• Collect forensic evidence");
            Console.WriteLine("• Profile attacker capabilities");
            Console.WriteLine("• Build threat intelligence");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error: {ex.Message}");
            Console.WriteLine($"Stack trace: {ex.StackTrace}");
        }
        finally
        {
            // Cleanup
            Console.WriteLine("\nCleaning up...");
            try
            {
                await honeyAccountSystem.StopFakeServerAsync();
            }
            catch
            {
                // Server might already be stopped
            }

            // Optionally clean up planted files
            Console.WriteLine("Note: Planted credential files remain for testing.");
            Console.WriteLine("Delete them manually if needed:");
            Console.WriteLine($"  - {Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "passwords.txt")}");
            Console.WriteLine($"  - {Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "Important_Bookmarks.txt")}");
            Console.WriteLine($"  - {Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "account_info.txt")}");
        }

        Console.WriteLine("\nExample completed. Press any key to exit...");
        Console.ReadKey();
    }
}
