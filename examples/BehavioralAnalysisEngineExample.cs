using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;

namespace WindowsHoneypot.Examples;

/// <summary>
/// Example usage of BehavioralAnalysisEngine
/// Demonstrates Task 19.1: Time-delayed malware detection system
/// </summary>
public class BehavioralAnalysisEngineExample
{
    public static async Task RunExamplesAsync()
    {
        Console.WriteLine("=== Behavioral Analysis Engine Examples ===\n");

        var engine = new BehavioralAnalysisEngine();

        // Subscribe to suspicious behavior events
        engine.SuspiciousBehaviorDetected += (sender, args) =>
        {
            Console.WriteLine($"[ALERT] Suspicious behavior detected!");
            Console.WriteLine($"  Type: {args.Indicator.Type}");
            Console.WriteLine($"  Severity: {args.Severity}");
            Console.WriteLine($"  Description: {args.Description}");
            Console.WriteLine();
        };

        // Example 1: Analyze scheduled tasks for malicious patterns
        await Example1_AnalyzeScheduledTasks(engine);

        // Example 2: Analyze registry persistence mechanisms
        await Example2_AnalyzeRegistryPersistence(engine);

        // Example 3: Detect time-delayed threats in files
        await Example3_DetectTimeDelayedThreats(engine);

        // Example 4: Detect VM-aware malware
        await Example4_DetectVMAwareMalware(engine);

        // Example 5: Monitor file behavior over time
        await Example5_MonitorFileBehavior(engine);

        // Example 6: Analyze process behavior
        await Example6_AnalyzeProcess(engine);

        // Example 7: Update behavioral model with training data
        await Example7_UpdateBehavioralModel(engine);

        // Example 8: Get all suspicious activities
        await Example8_GetSuspiciousActivities(engine);

        Console.WriteLine("\n=== Examples Complete ===");
    }

    private static async Task Example1_AnalyzeScheduledTasks(BehavioralAnalysisEngine engine)
    {
        Console.WriteLine("Example 1: Analyzing Scheduled Tasks");
        Console.WriteLine("-------------------------------------");

        try
        {
            var indicators = await engine.AnalyzeScheduledTasksAsync();

            Console.WriteLine($"Found {indicators.Count} suspicious scheduled tasks");

            foreach (var indicator in indicators.Take(5)) // Show first 5
            {
                Console.WriteLine($"  - Task: {indicator.ProcessName}");
                Console.WriteLine($"    Severity: {indicator.Severity}");
                Console.WriteLine($"    Description: {indicator.Description}");
                
                if (indicator.BehaviorMetadata.ContainsKey("ExecutablePath"))
                {
                    Console.WriteLine($"    Executable: {indicator.BehaviorMetadata["ExecutablePath"]}");
                }
                
                Console.WriteLine();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }

        Console.WriteLine();
    }

    private static async Task Example2_AnalyzeRegistryPersistence(BehavioralAnalysisEngine engine)
    {
        Console.WriteLine("Example 2: Analyzing Registry Persistence");
        Console.WriteLine("------------------------------------------");

        try
        {
            var indicators = await engine.AnalyzeRegistryPersistenceAsync();

            Console.WriteLine($"Found {indicators.Count} suspicious registry entries");

            foreach (var indicator in indicators.Take(5)) // Show first 5
            {
                Console.WriteLine($"  - Entry: {indicator.ProcessName}");
                Console.WriteLine($"    Registry Key: {indicator.RegistryKey}");
                Console.WriteLine($"    File Path: {indicator.FilePath}");
                Console.WriteLine($"    Severity: {indicator.Severity}");
                Console.WriteLine();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }

        Console.WriteLine();
    }

    private static async Task Example3_DetectTimeDelayedThreats(BehavioralAnalysisEngine engine)
    {
        Console.WriteLine("Example 3: Detecting Time-Delayed Threats");
        Console.WriteLine("------------------------------------------");

        // Create a test file with time-delay patterns
        var testFile = Path.Combine(Path.GetTempPath(), "test_malware.txt");
        
        try
        {
            await File.WriteAllTextAsync(testFile, @"
                // Malicious code with time delay
                Thread.Sleep(5000);
                Task.Delay(10000).Wait();
                Timer timer = new Timer(ExecuteMaliciousCode, null, 60000, 0);
            ");

            Console.WriteLine($"Analyzing file: {testFile}");

            var isTimeDelayed = await engine.DetectTimeDelayedThreatAsync(testFile);

            if (isTimeDelayed)
            {
                Console.WriteLine("✓ Time-delayed threat detected!");
                Console.WriteLine("  The file contains patterns indicating delayed execution.");
            }
            else
            {
                Console.WriteLine("✗ No time-delayed threat detected.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
        finally
        {
            if (File.Exists(testFile))
                File.Delete(testFile);
        }

        Console.WriteLine();
    }

    private static async Task Example4_DetectVMAwareMalware(BehavioralAnalysisEngine engine)
    {
        Console.WriteLine("Example 4: Detecting VM-Aware Malware");
        Console.WriteLine("--------------------------------------");

        // Create a test file with VM detection strings
        var testFile = Path.Combine(Path.GetTempPath(), "test_vm_aware.txt");
        
        try
        {
            await File.WriteAllTextAsync(testFile, @"
                // Check for virtual machine
                if (IsVMware() || IsVirtualBox() || IsQEMU())
                {
                    // Exit if running in VM
                    Environment.Exit(0);
                }
            ");

            Console.WriteLine($"Analyzing file: {testFile}");

            var isVMAware = await engine.DetectVMAwareMalwareAsync(testFile);

            if (isVMAware)
            {
                Console.WriteLine("✓ VM-aware malware detected!");
                Console.WriteLine("  The file contains VM detection patterns.");
            }
            else
            {
                Console.WriteLine("✗ No VM-aware malware detected.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
        finally
        {
            if (File.Exists(testFile))
                File.Delete(testFile);
        }

        Console.WriteLine();
    }

    private static async Task Example5_MonitorFileBehavior(BehavioralAnalysisEngine engine)
    {
        Console.WriteLine("Example 5: Monitoring File Behavior Over Time");
        Console.WriteLine("----------------------------------------------");

        var testFile = Path.Combine(Path.GetTempPath(), "test_behavior.txt");
        
        try
        {
            await File.WriteAllTextAsync(testFile, "Test file for behavior monitoring");

            Console.WriteLine($"Monitoring file: {testFile}");
            Console.WriteLine("Monitoring period: 2 seconds");

            var monitoringPeriod = TimeSpan.FromSeconds(2);
            var result = await engine.AnalyzeFileBehaviorAsync(testFile, monitoringPeriod);

            Console.WriteLine($"\nAnalysis Results:");
            Console.WriteLine($"  Suspicious: {result.IsSuspicious}");
            Console.WriteLine($"  Suspicion Score: {result.SuspicionScore:F2}");
            Console.WriteLine($"  Time-Delayed: {result.IsTimeDelayed}");
            Console.WriteLine($"  VM-Aware: {result.IsVMAware}");
            Console.WriteLine($"  Indicators Found: {result.Indicators.Count}");
            Console.WriteLine($"  Recommended Action: {result.RecommendedAction}");
            Console.WriteLine($"  Recommendation: {result.Recommendation}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
        finally
        {
            if (File.Exists(testFile))
                File.Delete(testFile);
        }

        Console.WriteLine();
    }

    private static async Task Example6_AnalyzeProcess(BehavioralAnalysisEngine engine)
    {
        Console.WriteLine("Example 6: Analyzing Process Behavior");
        Console.WriteLine("--------------------------------------");

        try
        {
            // Analyze current process as an example
            var currentProcessId = Environment.ProcessId;
            
            Console.WriteLine($"Analyzing process ID: {currentProcessId}");

            var assessment = await engine.AnalyzeProcessAsync(currentProcessId);

            Console.WriteLine($"\nThreat Assessment:");
            Console.WriteLine($"  Is Threat: {assessment.IsThreat}");
            Console.WriteLine($"  Severity: {assessment.Severity}");
            Console.WriteLine($"  Confidence: {assessment.ConfidenceScore:F2}");
            Console.WriteLine($"  Recommended Action: {assessment.RecommendedAction}");
            Console.WriteLine($"  Behavioral Indicators: {assessment.BehavioralIndicators.Count}");

            if (assessment.BehavioralIndicators.Any())
            {
                Console.WriteLine("\n  Detected Behaviors:");
                foreach (var indicator in assessment.BehavioralIndicators)
                {
                    Console.WriteLine($"    - {indicator.Type}: {indicator.Description}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }

        Console.WriteLine();
    }

    private static async Task Example7_UpdateBehavioralModel(BehavioralAnalysisEngine engine)
    {
        Console.WriteLine("Example 7: Updating Behavioral Model");
        Console.WriteLine("-------------------------------------");

        try
        {
            // Create sample threat data for training
            var trainingData = new ThreatData
            {
                ThreatId = "example-threat-001",
                AttackerIP = "192.168.1.100",
                Severity = ThreatSeverity.High,
                AttackPatterns = new List<string>
                {
                    "Time-delayed execution",
                    "Registry persistence",
                    "Scheduled task creation"
                },
                Indicators = new Dictionary<string, string>
                {
                    ["FileHash"] = "abc123def456",
                    ["ProcessName"] = "malware.exe",
                    ["Behavior"] = "Dormant for 24 hours before activation"
                }
            };

            Console.WriteLine("Adding training data to behavioral model...");
            engine.UpdateBehavioralModel(trainingData);

            Console.WriteLine("✓ Behavioral model updated successfully");
            Console.WriteLine($"  Threat ID: {trainingData.ThreatId}");
            Console.WriteLine($"  Severity: {trainingData.Severity}");
            Console.WriteLine($"  Patterns: {string.Join(", ", trainingData.AttackPatterns)}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }

        Console.WriteLine();
    }

    private static async Task Example8_GetSuspiciousActivities(BehavioralAnalysisEngine engine)
    {
        Console.WriteLine("Example 8: Getting All Suspicious Activities");
        Console.WriteLine("---------------------------------------------");

        try
        {
            var activities = engine.GetSuspiciousActivities();

            Console.WriteLine($"Total suspicious activities detected: {activities.Count}");

            if (activities.Any())
            {
                Console.WriteLine("\nRecent Activities:");
                
                foreach (var activity in activities.OrderByDescending(a => a.DetectedAt).Take(10))
                {
                    Console.WriteLine($"\n  [{activity.DetectedAt:yyyy-MM-dd HH:mm:ss}]");
                    Console.WriteLine($"  Type: {activity.Type}");
                    Console.WriteLine($"  Severity: {activity.Severity}");
                    Console.WriteLine($"  Description: {activity.Description}");
                    
                    if (activity.ProcessId.HasValue)
                    {
                        Console.WriteLine($"  Process: {activity.ProcessName} (PID: {activity.ProcessId})");
                    }
                    
                    if (!string.IsNullOrEmpty(activity.FilePath))
                    {
                        Console.WriteLine($"  File: {activity.FilePath}");
                    }
                    
                    if (activity.ObservedActions.Any())
                    {
                        Console.WriteLine($"  Actions: {string.Join(", ", activity.ObservedActions)}");
                    }
                }
            }
            else
            {
                Console.WriteLine("No suspicious activities detected yet.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }

        Console.WriteLine();
    }
}
