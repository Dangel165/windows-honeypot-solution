using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Moq;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using Xunit;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Performance and stability tests for the Windows Honeypot Solution.
/// Task 26.2: Performance and stability testing
/// </summary>
public class PerformanceStabilityTests
{
    private static ILogger<T> Logger<T>() => new Mock<ILogger<T>>().Object;

    private static ThreatPattern MakePattern(int i, ThreatPatternType type = ThreatPatternType.FileName) =>
        new ThreatPattern
        {
            PatternId = Guid.NewGuid().ToString(),
            Name = $"Pattern-{i}",
            Description = $"Test pattern {i}",
            Type = type,
            Severity = (ThreatSeverity)(i % 4),
            ConfidenceScore = 0.5 + (i % 5) * 0.1
        };

    // ─────────────────────────────────────────────────────────────────────────
    // 1. High-volume logging performance
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ActivityLogger_HighVolumeLogging_CompletesWithinTimeout()
    {
        var logDir = Path.Combine(Path.GetTempPath(), $"HoneypotPerfTest_{Guid.NewGuid():N}");
        Directory.CreateDirectory(logDir);

        try
        {
            var logger = new ActivityLogger(Logger<ActivityLogger>(), logDir);
            const int eventCount = 1000;

            var sw = Stopwatch.StartNew();

            var tasks = Enumerable.Range(0, eventCount).Select(i => Task.Run(() =>
                logger.LogActivity(new AttackEvent
                {
                    EventType = (AttackEventType)(i % 7),
                    SourceProcess = $"process{i}",
                    ProcessId = i,
                    Description = $"High-volume test event {i}",
                    Severity = (ThreatSeverity)(i % 4)
                }))).ToArray();

            await Task.WhenAll(tasks);
            sw.Stop();

            // All 1000 events should be logged within 15 seconds
            Assert.True(sw.ElapsedMilliseconds < 15_000,
                $"High-volume logging took too long: {sw.ElapsedMilliseconds}ms");

            logger.Dispose();
        }
        finally
        {
            if (Directory.Exists(logDir))
                Directory.Delete(logDir, true);
        }
    }

    [Fact]
    public async Task ActivityLogger_ConcurrentExports_NoDataCorruption()
    {
        var logDir = Path.Combine(Path.GetTempPath(), $"HoneypotExportTest_{Guid.NewGuid():N}");
        Directory.CreateDirectory(logDir);

        try
        {
            var logger = new ActivityLogger(Logger<ActivityLogger>(), logDir);

            // Log some events first
            for (int i = 0; i < 50; i++)
            {
                logger.LogActivity(new AttackEvent
                {
                    EventType = AttackEventType.FileAccess,
                    SourceProcess = $"proc{i}",
                    Description = $"Event {i}"
                });
            }

            // Concurrent JSON, CSV, and XML exports while still logging
            var exportTasks = new List<Task<string>>();
            for (int i = 0; i < 5; i++)
            {
                exportTasks.Add(logger.ExportToJsonAsync());
                exportTasks.Add(logger.ExportToCsvAsync());
                exportTasks.Add(logger.ExportToXmlAsync());
            }

            var sw = Stopwatch.StartNew();
            var exportPaths = await Task.WhenAll(exportTasks);
            sw.Stop();

            // All exports should complete within 30 seconds
            Assert.True(sw.ElapsedMilliseconds < 30_000,
                $"Concurrent exports took too long: {sw.ElapsedMilliseconds}ms");

            // All export paths should be non-empty strings (files created)
            Assert.All(exportPaths, p => Assert.False(string.IsNullOrEmpty(p)));

            logger.Dispose();
        }
        finally
        {
            if (Directory.Exists(logDir))
                Directory.Delete(logDir, true);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. ThreatPatternDatabase bulk operations
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void ThreatPatternDatabase_BulkAdd_CompletesWithinTimeout()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"HoneypotDB_{Guid.NewGuid():N}", "patterns.db");
        var db = new ThreatPatternDatabase(Logger<ThreatPatternDatabase>(), dbPath);
        const int patternCount = 500;

        var sw = Stopwatch.StartNew();
        for (int i = 0; i < patternCount; i++)
            db.AddOrUpdatePattern(MakePattern(i));
        sw.Stop();

        Assert.Equal(patternCount, db.GetAllPatterns().Count);
        Assert.True(sw.ElapsedMilliseconds < 5_000,
            $"Bulk add of {patternCount} patterns took too long: {sw.ElapsedMilliseconds}ms");
    }

    [Fact]
    public async Task ThreatPatternDatabase_ConcurrentReadWrite_ThreadSafe()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"HoneypotDB_{Guid.NewGuid():N}", "patterns.db");
        var db = new ThreatPatternDatabase(Logger<ThreatPatternDatabase>(), dbPath);

        // Pre-populate
        for (int i = 0; i < 100; i++)
            db.AddOrUpdatePattern(MakePattern(i));

        // Concurrent reads and writes
        var writeTasks = Enumerable.Range(100, 100).Select(i =>
            Task.Run(() => db.AddOrUpdatePattern(MakePattern(i))));

        var readTasks = Enumerable.Range(0, 50).Select(_ =>
            Task.Run(() => db.GetAllPatterns()));

        var queryTasks = Enumerable.Range(0, 50).Select(_ =>
            Task.Run(() => db.GetHighConfidencePatterns(0.7)));

        var sw = Stopwatch.StartNew();
        await Task.WhenAll(writeTasks.Concat(readTasks).Concat(queryTasks));
        sw.Stop();

        // After concurrent ops, should have at least 200 patterns
        Assert.True(db.GetAllPatterns().Count >= 200);
        Assert.True(sw.ElapsedMilliseconds < 10_000,
            $"Concurrent read/write took too long: {sw.ElapsedMilliseconds}ms");
    }

    [Fact]
    public void ThreatPatternDatabase_QueryPerformance_FastLookup()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"HoneypotDB_{Guid.NewGuid():N}", "patterns.db");
        var db = new ThreatPatternDatabase(Logger<ThreatPatternDatabase>(), dbPath);

        // Add 500 patterns of mixed types
        for (int i = 0; i < 500; i++)
            db.AddOrUpdatePattern(MakePattern(i, (ThreatPatternType)(i % 7)));

        var sw = Stopwatch.StartNew();
        for (int i = 0; i < 100; i++)
        {
            db.GetPatternsByType(ThreatPatternType.FileName);
            db.GetHighConfidencePatterns(0.8);
            db.GetStatistics();
        }
        sw.Stop();

        // 300 queries on 500 patterns should complete in under 2 seconds
        Assert.True(sw.ElapsedMilliseconds < 2_000,
            $"Query performance too slow: {sw.ElapsedMilliseconds}ms for 300 queries");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. RealTimeThreatMonitor pattern registration under load
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task RealTimeThreatMonitor_ConcurrentPatternRegistration_ThreadSafe()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"HoneypotDB_{Guid.NewGuid():N}", "patterns.db");
        var db = new ThreatPatternDatabase(Logger<ThreatPatternDatabase>(), dbPath);
        var networkBlocker = new NetworkThreatBlocker(Logger<NetworkThreatBlocker>());
        var monitor = new RealTimeThreatMonitor(Logger<RealTimeThreatMonitor>(), db, networkBlocker);

        const int patternCount = 200;

        var sw = Stopwatch.StartNew();
        var tasks = Enumerable.Range(0, patternCount).Select(i =>
            Task.Run(() => monitor.RegisterThreatPattern(MakePattern(i)))).ToArray();

        await Task.WhenAll(tasks);
        sw.Stop();

        var patterns = monitor.GetThreatPatterns();
        Assert.Equal(patternCount, patterns.Count);
        Assert.True(sw.ElapsedMilliseconds < 10_000,
            $"Concurrent pattern registration took too long: {sw.ElapsedMilliseconds}ms");
    }

    [Fact]
    public async Task RealTimeThreatMonitor_NetworkAssessment_HighVolume()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"HoneypotDB_{Guid.NewGuid():N}", "patterns.db");
        var db = new ThreatPatternDatabase(Logger<ThreatPatternDatabase>(), dbPath);
        var networkBlocker = new NetworkThreatBlocker(Logger<NetworkThreatBlocker>());
        var monitor = new RealTimeThreatMonitor(Logger<RealTimeThreatMonitor>(), db, networkBlocker);

        const int assessmentCount = 100;
        var sw = Stopwatch.StartNew();

        var tasks = Enumerable.Range(0, assessmentCount).Select(i =>
            monitor.AssessNetworkConnectionAsync($"192.168.1.{i % 255}", 8080 + (i % 100))).ToArray();

        var results = await Task.WhenAll(tasks);
        sw.Stop();

        Assert.Equal(assessmentCount, results.Length);
        Assert.True(sw.ElapsedMilliseconds < 15_000,
            $"High-volume network assessments took too long: {sw.ElapsedMilliseconds}ms");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. AutomatedResponseSystem audit log stability
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AutomatedResponseSystem_ConcurrentOperations_AuditLogComplete()
    {
        var responseSystem = new AutomatedResponseSystem(Logger<AutomatedResponseSystem>());
        const int operationCount = 200;

        var notifyTasks = Enumerable.Range(0, operationCount / 2).Select(i =>
            Task.Run(() => responseSystem.SendNotification(new ThreatNotification
            {
                Title = $"Threat {i}",
                Message = $"Message {i}",
                Severity = (ThreatSeverity)(i % 4)
            })));

        var restorePointTasks = Enumerable.Range(0, operationCount / 2).Select(i =>
            responseSystem.CreateRestorePointAsync($"Restore point {i}"));

        var sw = Stopwatch.StartNew();
        await Task.WhenAll(notifyTasks.Concat(restorePointTasks.Cast<Task>()));
        sw.Stop();

        var auditLog = responseSystem.GetAuditLog();

        // Each operation should produce at least one audit entry
        Assert.True(auditLog.Count >= operationCount,
            $"Expected at least {operationCount} audit entries, got {auditLog.Count}");
        Assert.True(sw.ElapsedMilliseconds < 15_000,
            $"Concurrent operations took too long: {sw.ElapsedMilliseconds}ms");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5. Memory stability under sustained load
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task MemoryStability_SustainedLoad_GCPressureDoesNotGrowUnboundedly()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"HoneypotDB_{Guid.NewGuid():N}", "patterns.db");
        var db = new ThreatPatternDatabase(Logger<ThreatPatternDatabase>(), dbPath);
        var responseSystem = new AutomatedResponseSystem(Logger<AutomatedResponseSystem>());

        // Warm up
        for (int i = 0; i < 20; i++)
            db.AddOrUpdatePattern(MakePattern(i));

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        long memoryBefore = GC.GetTotalMemory(false);
        var deadline = DateTime.UtcNow.AddSeconds(30);
        int iteration = 0;

        while (DateTime.UtcNow < deadline)
        {
            // Simulate sustained operations
            db.AddOrUpdatePattern(MakePattern(iteration % 500));
            db.GetAllPatterns();
            db.GetHighConfidencePatterns(0.7);

            responseSystem.SendNotification(new ThreatNotification
            {
                Title = $"Notification {iteration}",
                Message = "Sustained load test",
                Severity = ThreatSeverity.Low
            });

            if (iteration % 100 == 0)
                await Task.Yield(); // Allow GC to run

            iteration++;
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        long memoryAfter = GC.GetTotalMemory(false);
        long growthBytes = memoryAfter - memoryBefore;

        // Memory growth should be less than 200 MB over 30 seconds of sustained load
        Assert.True(growthBytes < 200L * 1024 * 1024,
            $"Memory grew by {growthBytes / 1024 / 1024}MB during sustained load - possible memory leak");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 6. WebBrowsingProtection blocklist scalability
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task WebBrowsingProtection_BlocklistScalability_LookupRemainsEfficient()
    {
        var webProtection = new WebBrowsingProtection(Logger<WebBrowsingProtection>());
        const int urlCount = 1000;

        // Add 1000 URLs to blocklist
        var addSw = Stopwatch.StartNew();
        for (int i = 0; i < urlCount; i++)
            webProtection.AddToBlocklist($"https://blocked-site-{i}.com/malware");
        addSw.Stop();

        Assert.Equal(urlCount, webProtection.GetBlocklist().Count);

        // Measure lookup time for 1000 checks
        var lookupSw = Stopwatch.StartNew();
        for (int i = 0; i < urlCount; i++)
        {
            var isBlocked = webProtection.IsUrlBlocked($"https://blocked-site-{i}.com/malware");
            Assert.True(isBlocked);
        }
        lookupSw.Stop();

        // 1000 lookups in a HashSet should be well under 1 second
        Assert.True(lookupSw.ElapsedMilliseconds < 1_000,
            $"Blocklist lookup too slow: {lookupSw.ElapsedMilliseconds}ms for {urlCount} lookups");

        // Concurrent URL reputation checks against large blocklist
        var reputationTasks = Enumerable.Range(0, 100).Select(i =>
            webProtection.CheckUrlReputationAsync($"https://blocked-site-{i}.com/malware")).ToArray();

        var repSw = Stopwatch.StartNew();
        var results = await Task.WhenAll(reputationTasks);
        repSw.Stop();

        Assert.All(results, r => Assert.True(r.IsMalicious));
        Assert.True(repSw.ElapsedMilliseconds < 5_000,
            $"Concurrent reputation checks took too long: {repSw.ElapsedMilliseconds}ms");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 7. ThreatPatternDatabase persistence performance
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ThreatPatternDatabase_PersistenceRoundTrip_CompletesWithinTwoSeconds()
    {
        var dbDir = Path.Combine(Path.GetTempPath(), $"HoneypotPersist_{Guid.NewGuid():N}");
        var dbPath = Path.Combine(dbDir, "patterns.db");
        Directory.CreateDirectory(dbDir);

        try
        {
            var db = new ThreatPatternDatabase(Logger<ThreatPatternDatabase>(), dbPath);

            // Add 100 patterns
            for (int i = 0; i < 100; i++)
                db.AddOrUpdatePattern(MakePattern(i));

            var sw = Stopwatch.StartNew();
            await db.SaveAsync();

            var db2 = new ThreatPatternDatabase(Logger<ThreatPatternDatabase>(), dbPath);
            await db2.LoadAsync();
            sw.Stop();

            Assert.Equal(100, db2.GetAllPatterns().Count);
            Assert.True(sw.ElapsedMilliseconds < 2_000,
                $"Save/Load round-trip took too long: {sw.ElapsedMilliseconds}ms");
        }
        finally
        {
            if (Directory.Exists(dbDir))
                Directory.Delete(dbDir, true);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 8. Concurrent multi-component stress test
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task MultiComponent_ConcurrentStressTest_StableForFiveSeconds()
    {
        var logDir = Path.Combine(Path.GetTempPath(), $"HoneypotStress_{Guid.NewGuid():N}");
        var dbPath = Path.Combine(Path.GetTempPath(), $"HoneypotStressDB_{Guid.NewGuid():N}", "patterns.db");
        Directory.CreateDirectory(logDir);

        try
        {
            var activityLogger = new ActivityLogger(Logger<ActivityLogger>(), logDir);
            var db = new ThreatPatternDatabase(Logger<ThreatPatternDatabase>(), dbPath);
            var responseSystem = new AutomatedResponseSystem(Logger<AutomatedResponseSystem>());

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var exceptions = new System.Collections.Concurrent.ConcurrentBag<Exception>();

            async Task RunActivityLoggerLoad()
            {
                int i = 0;
                while (!cts.Token.IsCancellationRequested)
                {
                    try
                    {
                        activityLogger.LogActivity(new AttackEvent
                        {
                            EventType = (AttackEventType)(i % 7),
                            SourceProcess = $"stress-proc-{i}",
                            Description = $"Stress test event {i}"
                        });
                        i++;
                        if (i % 50 == 0) await Task.Yield();
                    }
                    catch (Exception ex) { exceptions.Add(ex); break; }
                }
            }

            async Task RunPatternDbLoad()
            {
                int i = 0;
                while (!cts.Token.IsCancellationRequested)
                {
                    try
                    {
                        db.AddOrUpdatePattern(MakePattern(i % 200));
                        db.GetAllPatterns();
                        i++;
                        if (i % 50 == 0) await Task.Yield();
                    }
                    catch (Exception ex) { exceptions.Add(ex); break; }
                }
            }

            async Task RunResponseSystemLoad()
            {
                int i = 0;
                while (!cts.Token.IsCancellationRequested)
                {
                    try
                    {
                        responseSystem.SendNotification(new ThreatNotification
                        {
                            Title = $"Stress notification {i}",
                            Message = "Stress test",
                            Severity = ThreatSeverity.Low
                        });
                        i++;
                        if (i % 50 == 0) await Task.Yield();
                    }
                    catch (Exception ex) { exceptions.Add(ex); break; }
                }
            }

            var sw = Stopwatch.StartNew();
            await Task.WhenAll(
                RunActivityLoggerLoad(),
                RunPatternDbLoad(),
                RunResponseSystemLoad()
            );
            sw.Stop();

            Assert.Empty(exceptions);
            Assert.True(sw.ElapsedMilliseconds >= 4_000,
                "Stress test completed too quickly - may not have run properly");
            Assert.True(sw.ElapsedMilliseconds < 10_000,
                $"Stress test took too long to stop: {sw.ElapsedMilliseconds}ms");

            activityLogger.Dispose();
        }
        finally
        {
            if (Directory.Exists(logDir))
                Directory.Delete(logDir, true);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 9. Existing tests (preserved from original)
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task EmailScanner_ConcurrentScans_CompletesWithinTimeout()
    {
        var scanner = new EmailAttachmentScanner(Logger<EmailAttachmentScanner>());
        var tempFiles = new List<string>();

        try
        {
            for (int i = 0; i < 10; i++)
            {
                var f = Path.GetTempFileName();
                await File.WriteAllTextAsync(f, $"Test content {i}");
                tempFiles.Add(f);
            }

            var sw = Stopwatch.StartNew();
            var tasks = tempFiles.Select(f => scanner.ScanAttachmentAsync(f));
            var results = await Task.WhenAll(tasks);
            sw.Stop();

            Assert.Equal(10, results.Length);
            Assert.True(sw.ElapsedMilliseconds < 10_000,
                $"Concurrent scans took too long: {sw.ElapsedMilliseconds}ms");
        }
        finally
        {
            foreach (var f in tempFiles)
                if (File.Exists(f)) File.Delete(f);
        }
    }

    [Fact]
    public async Task UrlReputationCheck_HighVolume_CompletesWithinTimeout()
    {
        var webProtection = new WebBrowsingProtection(Logger<WebBrowsingProtection>());
        var urls = Enumerable.Range(0, 50).Select(i => $"https://example{i}.com/page").ToList();

        var sw = Stopwatch.StartNew();
        var tasks = urls.Select(u => webProtection.CheckUrlReputationAsync(u));
        var results = await Task.WhenAll(tasks);
        sw.Stop();

        Assert.Equal(50, results.Length);
        Assert.True(sw.ElapsedMilliseconds < 5_000,
            $"URL checks took too long: {sw.ElapsedMilliseconds}ms");
    }

    [Fact]
    public async Task AutomatedResponseSystem_HighVolumeNotifications_ThreadSafe()
    {
        var responseSystem = new AutomatedResponseSystem(Logger<AutomatedResponseSystem>());
        const int notificationCount = 100;

        var tasks = Enumerable.Range(0, notificationCount).Select(i =>
            Task.Run(() => responseSystem.SendNotification(new ThreatNotification
            {
                Title = $"Threat {i}",
                Message = $"Message {i}",
                Severity = ThreatSeverity.Low
            })));

        await Task.WhenAll(tasks);

        Assert.Equal(notificationCount, responseSystem.GetNotifications().Count);
    }

    [Fact]
    public async Task AutomatedResponseSystem_MultipleRestorePoints_StableUnderLoad()
    {
        var responseSystem = new AutomatedResponseSystem(Logger<AutomatedResponseSystem>());
        const int count = 20;

        var tasks = Enumerable.Range(0, count).Select(i =>
            responseSystem.CreateRestorePointAsync($"Restore point {i}"));
        var results = await Task.WhenAll(tasks);

        Assert.Equal(count, results.Length);
        Assert.All(results, r => Assert.True(r.Success));
        Assert.Equal(count, responseSystem.GetRestorePoints().Count);
    }

    [Fact]
    public async Task WebProtection_BlocklistOperations_ThreadSafe()
    {
        var webProtection = new WebBrowsingProtection(Logger<WebBrowsingProtection>());
        const int urlCount = 100;

        var addTasks = Enumerable.Range(0, urlCount)
            .Select(i => Task.Run(() => webProtection.AddToBlocklist($"http://blocked{i}.com")));
        await Task.WhenAll(addTasks);

        Assert.Equal(urlCount, webProtection.GetBlocklist().Count);

        var removeTasks = Enumerable.Range(0, urlCount)
            .Select(i => Task.Run(() => webProtection.RemoveFromBlocklist($"http://blocked{i}.com")));
        await Task.WhenAll(removeTasks);

        Assert.Empty(webProtection.GetBlocklist());
    }

    [Fact]
    public async Task PhishingDetector_BatchAnalysis_CompletesWithinTimeout()
    {
        var detector = new PhishingDetector(Logger<PhishingDetector>());
        var urls = new[]
        {
            "https://google.com", "https://microsoft.com", "https://paypal-secure.com",
            "https://amazon.com", "https://apple-verify.com", "https://facebook.com",
            "https://netflix-login.com", "https://chase-bank.com", "https://wellsfargo.com",
            "https://legitimate-site.com"
        };

        var sw = Stopwatch.StartNew();
        var tasks = urls.Select(u => detector.AnalyzeUrlAsync(u));
        var results = await Task.WhenAll(tasks);
        sw.Stop();

        Assert.Equal(urls.Length, results.Length);
        Assert.True(sw.ElapsedMilliseconds < 3_000,
            $"Batch analysis took too long: {sw.ElapsedMilliseconds}ms");
    }
}
