using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Hardware security monitor for detecting hardware-level attacks.
/// Monitors BIOS/UEFI firmware, bootkits, rootkits, DMA attacks, and hardware keyloggers.
/// Task 19.3: Hardware-level attack detection
/// </summary>
public class HardwareSecurityMonitor : IHardwareSecurityMonitor, IDisposable
{
    private readonly ILogger<HardwareSecurityMonitor> _logger;
    private readonly List<HardwareAttackIndicator> _detectedAttacks = new();
    private readonly object _lock = new();

    private ManagementEventWatcher? _deviceCreationWatcher;
    private ManagementEventWatcher? _deviceDeletionWatcher;
    private bool _monitoring;
    private bool _disposed;

    // Baseline hashes stored on first run
    private string? _firmwareBaselineHash;
    private string? _mbrBaselineHash;

    // Known-good keyboard device IDs (populated on first run)
    private readonly HashSet<string> _knownKeyboardDevices = new(StringComparer.OrdinalIgnoreCase);

    // Known PCILeech / DMA-attack VendorID:ProductID pairs
    private static readonly HashSet<string> KnownDmaAttackSignatures = new(StringComparer.OrdinalIgnoreCase)
    {
        "1D6B:0001", // PCILeech FPGA
        "1D6B:0002",
        "1209:4711", // PCILeech generic
        "0403:6010", // FTDI FT2232H (common in DMA boards)
        "0403:6011",
    };

    // P/Invoke for raw disk access
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(
        IntPtr hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    public event EventHandler<HardwareAttackEventArgs>? HardwareAttackDetected;

    public HardwareSecurityMonitor(ILogger<HardwareSecurityMonitor> logger)
    {
        _logger = logger;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BIOS/UEFI Firmware Integrity
    // ─────────────────────────────────────────────────────────────────────────

    public async Task<FirmwareIntegrityStatus> CheckFirmwareIntegrityAsync()
    {
        return await Task.Run(() =>
        {
            var status = new FirmwareIntegrityStatus();
            try
            {
                PopulateBiosInfo(status);
                PopulateSecureBootInfo(status);
                PopulateTpmInfo(status);
                ValidateFirmwareHash(status);
                DetermineIntegrity(status);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error checking firmware integrity (may require admin rights)");
                status.DetectedIssues.Add($"Integrity check error: {ex.Message}");
                status.Severity = ThreatSeverity.Low;
            }
            return status;
        });
    }

    private void PopulateBiosInfo(FirmwareIntegrityStatus status)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BIOS");
            foreach (ManagementObject obj in searcher.Get())
            {
                status.Version = obj["SMBIOSBIOSVersion"]?.ToString() ?? string.Empty;
                status.Manufacturer = obj["Manufacturer"]?.ToString() ?? string.Empty;
                if (DateTime.TryParse(obj["ReleaseDate"]?.ToString(), out var releaseDate))
                    status.LastModified = releaseDate;
                break;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "WMI Win32_BIOS query failed");
        }

        // Supplement with registry
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            if (key != null)
            {
                if (string.IsNullOrEmpty(status.Manufacturer))
                    status.Manufacturer = key.GetValue("BIOSVendor")?.ToString() ?? string.Empty;
                if (string.IsNullOrEmpty(status.Version))
                    status.Version = key.GetValue("BIOSVersion")?.ToString() ?? string.Empty;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Registry BIOS read failed");
        }

        // Determine BIOS vs UEFI
        status.FirmwareType = IsUefi() ? "UEFI" : "BIOS";
    }

    private static bool IsUefi()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            return key != null;
        }
        catch { return false; }
    }

    private void PopulateSecureBootInfo(FirmwareIntegrityStatus status)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            if (key != null)
            {
                status.SecureBootSupported = true;
                var val = key.GetValue("UEFISecureBootEnabled");
                status.SecureBootEnabled = val is int i && i == 1;
                if (!status.SecureBootEnabled)
                    status.DetectedIssues.Add("Secure Boot is disabled");
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Secure Boot registry read failed");
        }
    }

    private void PopulateTpmInfo(FirmwareIntegrityStatus status)
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\CIMv2\Security\MicrosoftTpm");
            scope.Connect();
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM Win32_Tpm"));
            foreach (ManagementObject obj in searcher.Get())
            {
                status.TPMAvailable = true;
                status.TPMEnabled = obj["IsEnabled_InitialValue"] is bool enabled && enabled;
                status.TPMVersion = obj["SpecVersion"]?.ToString();
                status.TPMValidationPassed = status.TPMEnabled;
                break;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "TPM WMI query failed (may require admin)");
        }
    }

    private void ValidateFirmwareHash(FirmwareIntegrityStatus status)
    {
        var hashInput = $"{status.FirmwareType}|{status.Version}|{status.Manufacturer}";
        var currentHash = ComputeSha256(hashInput);
        status.ActualHash = currentHash;

        if (_firmwareBaselineHash == null)
        {
            _firmwareBaselineHash = currentHash;
            _logger.LogInformation("Firmware baseline hash established: {Hash}", currentHash);
        }

        status.ExpectedHash = _firmwareBaselineHash;
        status.HashMatches = string.Equals(status.ExpectedHash, status.ActualHash, StringComparison.OrdinalIgnoreCase);

        if (!status.HashMatches)
            status.DetectedIssues.Add("Firmware hash mismatch detected – possible modification");
    }

    private static void DetermineIntegrity(FirmwareIntegrityStatus status)
    {
        status.IsIntact = status.HashMatches && status.DetectedIssues.Count == 0;
        status.Severity = status.DetectedIssues.Count == 0
            ? ThreatSeverity.Low
            : status.DetectedIssues.Count == 1
                ? ThreatSeverity.Medium
                : ThreatSeverity.High;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Bootkit Detection
    // ─────────────────────────────────────────────────────────────────────────

    public async Task<bool> DetectBootkitAsync()
    {
        return await Task.Run(() =>
        {
            bool detected = false;
            detected |= CheckMbrIntegrity();
            detected |= CheckBootExecuteRegistry();
            detected |= CheckSuspiciousBcdEntries();
            return detected;
        });
    }

    private bool CheckMbrIntegrity()
    {
        try
        {
            var mbrBytes = ReadMbr();
            if (mbrBytes == null) return false;

            var currentHash = ComputeSha256(mbrBytes);
            if (_mbrBaselineHash == null)
            {
                _mbrBaselineHash = currentHash;
                _logger.LogInformation("MBR baseline hash established: {Hash}", currentHash);
                return false;
            }

            if (!string.Equals(_mbrBaselineHash, currentHash, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("MBR hash mismatch – possible bootkit");
                RecordAttack(HardwareAttackType.MBRModification, "MBR hash mismatch detected", ThreatSeverity.Critical, 0.9);
                return true;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "MBR read failed (requires admin)");
        }
        return false;
    }

    private static byte[]? ReadMbr()
    {
        var handle = CreateFile(
            @"\\.\PhysicalDrive0",
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            0,
            IntPtr.Zero);

        if (handle == INVALID_HANDLE_VALUE) return null;

        try
        {
            var buffer = new byte[512];
            if (ReadFile(handle, buffer, 512, out uint bytesRead, IntPtr.Zero) && bytesRead == 512)
                return buffer;
        }
        finally
        {
            CloseHandle(handle);
        }
        return null;
    }

    private bool CheckBootExecuteRegistry()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager");
            if (key == null) return false;

            var bootExecute = key.GetValue("BootExecute") as string[];
            if (bootExecute == null) return false;

            foreach (var entry in bootExecute)
            {
                if (!string.IsNullOrWhiteSpace(entry) &&
                    !entry.Equals("autocheck autochk *", StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning("Suspicious BootExecute entry: {Entry}", entry);
                    RecordAttack(HardwareAttackType.BootkitInstallation,
                        $"Suspicious BootExecute entry: {entry}", ThreatSeverity.High, 0.75);
                    return true;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "BootExecute registry check failed");
        }
        return false;
    }

    private bool CheckSuspiciousBcdEntries()
    {
        try
        {
            var psi = new ProcessStartInfo("bcdedit", "/enum all")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return false;

            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            // Look for suspicious testsigning or nointegritychecks flags
            if (output.Contains("testsigning", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("nointegritychecks", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Suspicious BCD entry detected (test signing or integrity checks disabled)");
                RecordAttack(HardwareAttackType.SecureBootBypass,
                    "BCD has test signing or integrity checks disabled", ThreatSeverity.High, 0.8);
                return true;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "bcdedit check failed");
        }
        return false;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Rootkit Detection
    // ─────────────────────────────────────────────────────────────────────────

    public async Task<bool> DetectRootkitAsync()
    {
        return await Task.Run(() =>
        {
            bool detected = false;
            detected |= CompareProcessLists();
            detected |= CheckHiddenDrivers();
            return detected;
        });
    }

    private bool CompareProcessLists()
    {
        try
        {
            var dotnetProcessIds = new HashSet<int>(
                Process.GetProcesses().Select(p => p.Id));

            var wmiProcessIds = new HashSet<int>();
            using var searcher = new ManagementObjectSearcher("SELECT ProcessId FROM Win32_Process");
            foreach (ManagementObject obj in searcher.Get())
            {
                if (obj["ProcessId"] is uint pid)
                    wmiProcessIds.Add((int)pid);
            }

            // Processes visible in WMI but not in .NET (hidden from API)
            var hiddenFromApi = wmiProcessIds.Except(dotnetProcessIds).ToList();
            // Processes visible in .NET but not in WMI (hidden from WMI)
            var hiddenFromWmi = dotnetProcessIds.Except(wmiProcessIds).ToList();

            if (hiddenFromApi.Count > 0 || hiddenFromWmi.Count > 0)
            {
                _logger.LogWarning(
                    "Process list discrepancy: {HiddenFromApi} hidden from API, {HiddenFromWmi} hidden from WMI",
                    hiddenFromApi.Count, hiddenFromWmi.Count);
                RecordAttack(HardwareAttackType.RootkitDetected,
                    $"Process list discrepancy detected ({hiddenFromApi.Count + hiddenFromWmi.Count} hidden processes)",
                    ThreatSeverity.Critical, 0.85);
                return true;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Process list comparison failed");
        }
        return false;
    }

    private bool CheckHiddenDrivers()
    {
        try
        {
            // Get drivers from registry
            var registryDrivers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using var servicesKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services");
            if (servicesKey != null)
            {
                foreach (var subKeyName in servicesKey.GetSubKeyNames())
                {
                    using var subKey = servicesKey.OpenSubKey(subKeyName);
                    var serviceType = subKey?.GetValue("Type");
                    if (serviceType is int type && (type == 1 || type == 2)) // Kernel/File system driver
                        registryDrivers.Add(subKeyName);
                }
            }

            // Get drivers from sc query
            var scDrivers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var psi = new ProcessStartInfo("sc", "query type= driver state= all")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(5000);
                foreach (var line in output.Split('\n'))
                {
                    if (line.TrimStart().StartsWith("SERVICE_NAME:", StringComparison.OrdinalIgnoreCase))
                        scDrivers.Add(line.Split(':')[1].Trim());
                }
            }

            // Drivers in registry but not in sc output may be hidden
            var hiddenDrivers = registryDrivers.Except(scDrivers).ToList();
            if (hiddenDrivers.Count > 5) // Allow some tolerance
            {
                _logger.LogWarning("Possible hidden drivers detected: {Count}", hiddenDrivers.Count);
                RecordAttack(HardwareAttackType.KernelDriverManipulation,
                    $"Possible hidden kernel drivers: {string.Join(", ", hiddenDrivers.Take(5))}",
                    ThreatSeverity.High, 0.7);
                return true;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Hidden driver check failed");
        }
        return false;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Secure Boot Validation
    // ─────────────────────────────────────────────────────────────────────────

    public async Task<bool> ValidateSecureBootAsync()
    {
        return await Task.Run(() =>
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
                if (key == null) return false; // Not UEFI or not accessible

                var val = key.GetValue("UEFISecureBootEnabled");
                return val is int i && i == 1;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Secure Boot validation failed");
                return false;
            }
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DMA Attack Detection
    // ─────────────────────────────────────────────────────────────────────────

    public async Task<bool> DetectDMAAttackAsync()
    {
        return await Task.Run(() =>
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'PCI%' OR DeviceID LIKE 'USB%'");

                foreach (ManagementObject obj in searcher.Get())
                {
                    var deviceId = obj["DeviceID"]?.ToString() ?? string.Empty;
                    var name = obj["Name"]?.ToString() ?? string.Empty;

                    // Check for known DMA attack signatures
                    var vidPid = ExtractVidPid(deviceId);
                    if (vidPid != null && KnownDmaAttackSignatures.Contains(vidPid))
                    {
                        _logger.LogWarning("Known DMA attack device detected: {DeviceId}", deviceId);
                        RecordAttack(HardwareAttackType.PCILeechDetected,
                            $"Known DMA attack device: {name} ({deviceId})",
                            ThreatSeverity.Critical, 0.95,
                            deviceId: deviceId, deviceName: name);
                        return true;
                    }

                    // Check for Thunderbolt / FireWire (DMA-capable)
                    if (name.Contains("Thunderbolt", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("FireWire", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("1394", StringComparison.OrdinalIgnoreCase))
                    {
                        _logger.LogInformation("DMA-capable device present: {Name}", name);
                        // Not necessarily an attack, just log
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "DMA attack detection failed");
            }
            return false;
        });
    }

    private static string? ExtractVidPid(string deviceId)
    {
        // DeviceID format: USB\VID_1D6B&PID_0001\...
        var vidMatch = System.Text.RegularExpressions.Regex.Match(deviceId, @"VID_([0-9A-Fa-f]{4})");
        var pidMatch = System.Text.RegularExpressions.Regex.Match(deviceId, @"PID_([0-9A-Fa-f]{4})");
        if (vidMatch.Success && pidMatch.Success)
            return $"{vidMatch.Groups[1].Value.ToUpper()}:{pidMatch.Groups[1].Value.ToUpper()}";
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Hardware Keylogger Detection
    // ─────────────────────────────────────────────────────────────────────────

    public async Task<bool> DetectHardwareKeyloggerAsync()
    {
        return await Task.Run(() =>
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'HID%'");

                foreach (ManagementObject obj in searcher.Get())
                {
                    var deviceId = obj["DeviceID"]?.ToString() ?? string.Empty;
                    var name = obj["Name"]?.ToString() ?? string.Empty;
                    var description = obj["Description"]?.ToString() ?? string.Empty;

                    // Skip already-known devices
                    if (_knownKeyboardDevices.Contains(deviceId)) continue;

                    // Check for keyboard-like HID devices with unknown vendor
                    bool isKeyboardLike = name.Contains("Keyboard", StringComparison.OrdinalIgnoreCase) ||
                                         description.Contains("Keyboard", StringComparison.OrdinalIgnoreCase) ||
                                         name.Contains("HID", StringComparison.OrdinalIgnoreCase);

                    var vidPid = ExtractVidPid(deviceId);
                    bool unknownVendor = vidPid == null ||
                                        vidPid.StartsWith("0000:", StringComparison.OrdinalIgnoreCase);

                    if (isKeyboardLike && unknownVendor)
                    {
                        _logger.LogWarning("Suspicious HID keyboard device: {DeviceId}", deviceId);
                        RecordAttack(HardwareAttackType.HardwareKeylogger,
                            $"Suspicious keyboard HID device with unknown vendor: {name}",
                            ThreatSeverity.High, 0.75,
                            deviceId: deviceId, deviceName: name);
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Hardware keylogger detection failed");
            }
            return false;
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Hardware Change Monitoring
    // ─────────────────────────────────────────────────────────────────────────

    public void MonitorHardwareChanges()
    {
        if (_monitoring) return;

        try
        {
            var creationQuery = new WqlEventQuery(
                "__InstanceCreationEvent",
                TimeSpan.FromSeconds(2),
                "TargetInstance ISA 'Win32_PnPEntity'");

            _deviceCreationWatcher = new ManagementEventWatcher(creationQuery);
            _deviceCreationWatcher.EventArrived += OnDeviceCreated;
            _deviceCreationWatcher.Start();

            var deletionQuery = new WqlEventQuery(
                "__InstanceDeletionEvent",
                TimeSpan.FromSeconds(2),
                "TargetInstance ISA 'Win32_PnPEntity'");

            _deviceDeletionWatcher = new ManagementEventWatcher(deletionQuery);
            _deviceDeletionWatcher.EventArrived += OnDeviceRemoved;
            _deviceDeletionWatcher.Start();

            _monitoring = true;
            _logger.LogInformation("Hardware change monitoring started");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to start hardware change monitoring (may require admin)");
        }
    }

    public void StopMonitoring()
    {
        _monitoring = false;
        try
        {
            _deviceCreationWatcher?.Stop();
            _deviceDeletionWatcher?.Stop();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error stopping hardware watchers");
        }
        _logger.LogInformation("Hardware change monitoring stopped");
    }

    private void OnDeviceCreated(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var target = e.NewEvent["TargetInstance"] as ManagementBaseObject;
            if (target == null) return;

            var deviceId = target["DeviceID"]?.ToString() ?? string.Empty;
            var name = target["Name"]?.ToString() ?? string.Empty;

            _logger.LogInformation("New hardware device connected: {Name} ({DeviceId})", name, deviceId);

            // Run async checks and raise event if suspicious
            Task.Run(async () =>
            {
                bool dma = await DetectDMAAttackAsync();
                bool keylogger = await DetectHardwareKeyloggerAsync();

                if (dma || keylogger)
                {
                    var indicator = new HardwareAttackIndicator
                    {
                        AttackType = dma ? HardwareAttackType.DMAAttack : HardwareAttackType.HardwareKeylogger,
                        Description = $"Suspicious device connected: {name}",
                        Severity = ThreatSeverity.High,
                        ConfidenceScore = 0.8,
                        DeviceId = deviceId,
                        DeviceName = name,
                        DeviceConnectedAt = DateTime.UtcNow
                    };

                    RaiseHardwareAttackEvent(indicator);
                }
            });
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error processing device creation event");
        }
    }

    private void OnDeviceRemoved(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var target = e.NewEvent["TargetInstance"] as ManagementBaseObject;
            if (target == null) return;
            var name = target["Name"]?.ToString() ?? string.Empty;
            _logger.LogInformation("Hardware device removed: {Name}", name);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error processing device removal event");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    public List<HardwareAttackIndicator> GetDetectedAttacks()
    {
        lock (_lock)
        {
            return new List<HardwareAttackIndicator>(_detectedAttacks);
        }
    }

    private void RecordAttack(
        HardwareAttackType type,
        string description,
        ThreatSeverity severity,
        double confidence,
        string deviceId = "",
        string deviceName = "")
    {
        var indicator = new HardwareAttackIndicator
        {
            AttackType = type,
            Description = description,
            Severity = severity,
            ConfidenceScore = confidence,
            DeviceId = deviceId,
            DeviceName = deviceName
        };

        lock (_lock)
        {
            _detectedAttacks.Add(indicator);
        }

        RaiseHardwareAttackEvent(indicator);
    }

    private void RaiseHardwareAttackEvent(HardwareAttackIndicator indicator)
    {
        try
        {
            HardwareAttackDetected?.Invoke(this, new HardwareAttackEventArgs
            {
                Indicator = indicator,
                Description = indicator.Description,
                Severity = indicator.Severity,
                DetectedAt = indicator.DetectedAt
            });
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error raising HardwareAttackDetected event");
        }
    }

    private static string ComputeSha256(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes);
    }

    private static string ComputeSha256(byte[] input)
    {
        var bytes = SHA256.HashData(input);
        return Convert.ToHexString(bytes);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IDisposable
    // ─────────────────────────────────────────────────────────────────────────

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        StopMonitoring();
        _deviceCreationWatcher?.Dispose();
        _deviceDeletionWatcher?.Dispose();
    }
}
