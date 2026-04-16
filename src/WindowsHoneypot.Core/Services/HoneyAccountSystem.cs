using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using WindowsHoneypot.Core.Interfaces;
using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Implements honey account system for collecting attacker information through fake credentials
/// </summary>
public class HoneyAccountSystem : IHoneyAccountSystem
{
    private readonly ILogger<HoneyAccountSystem> _logger;
    private readonly ConcurrentDictionary<string, AttackerProfile> _attackerProfiles = new();
    private readonly ConcurrentDictionary<string, HoneyAccount> _plantedAccounts = new();
    private IHost? _webHost;
    private CancellationTokenSource? _serverCts;

    public event EventHandler<CredentialAttemptEventArgs>? CredentialUsed;

    public HoneyAccountSystem(ILogger<HoneyAccountSystem> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Plants fake credentials in browser bookmarks and notepad files
    /// </summary>
    public async Task PlantCredentialsAsync(List<HoneyAccount> accounts)
    {
        if (accounts == null || accounts.Count == 0)
        {
            _logger.LogWarning("No accounts provided for planting");
            return;
        }

        _logger.LogInformation("Planting {Count} honey accounts", accounts.Count);

        foreach (var account in accounts)
        {
            _plantedAccounts[account.Id.ToString()] = account;

            try
            {
                if (account.PlantInBookmarks)
                {
                    await PlantInBrowserBookmarksAsync(account);
                }

                if (account.PlantInTextFiles)
                {
                    await PlantInTextFilesAsync(account);
                }

                _logger.LogInformation("Successfully planted account: {ServiceName}", account.ServiceName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to plant account: {ServiceName}", account.ServiceName);
            }
        }
    }

    /// <summary>
    /// Plants credentials in browser bookmarks (Chrome format)
    /// </summary>
    private async Task PlantInBrowserBookmarksAsync(HoneyAccount account)
    {
        try
        {
            // Get user's local app data folder
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var chromeBookmarksPath = Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Bookmarks");

            // Create directory if it doesn't exist
            var bookmarksDir = Path.GetDirectoryName(chromeBookmarksPath);
            if (bookmarksDir != null && !Directory.Exists(bookmarksDir))
            {
                Directory.CreateDirectory(bookmarksDir);
            }

            // Read existing bookmarks or create new structure
            JsonDocument? bookmarksDoc = null;
            if (File.Exists(chromeBookmarksPath))
            {
                var bookmarksJson = await File.ReadAllTextAsync(chromeBookmarksPath);
                bookmarksDoc = JsonDocument.Parse(bookmarksJson);
            }

            // Create a simple bookmark entry
            var bookmarkEntry = new
            {
                date_added = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                guid = Guid.NewGuid().ToString(),
                id = Random.Shared.Next(1000, 9999).ToString(),
                name = $"{account.ServiceName} - {account.Username}",
                type = "url",
                url = account.ServiceUrl
            };

            // For simplicity, also create a text file with bookmark info
            var bookmarksTextPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                "Important_Bookmarks.txt"
            );

            var bookmarkText = $"\n[{account.ServiceName}]\nURL: {account.ServiceUrl}\nUsername: {account.Username}\nPassword: {account.Password}\nAdded: {DateTime.Now:yyyy-MM-dd}\n";
            await File.AppendAllTextAsync(bookmarksTextPath, bookmarkText);

            _logger.LogInformation("Planted bookmark for {ServiceName}", account.ServiceName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to plant bookmark for {ServiceName}", account.ServiceName);
            throw;
        }
    }

    /// <summary>
    /// Plants credentials in text files (notepad)
    /// </summary>
    private async Task PlantInTextFilesAsync(HoneyAccount account)
    {
        try
        {
            // Create credentials file on desktop
            var desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            var credentialsFilePath = Path.Combine(desktopPath, "passwords.txt");

            var credentialText = $"\n=== {account.ServiceName} ===\n" +
                                $"Website: {account.ServiceUrl}\n" +
                                $"Username: {account.Username}\n" +
                                $"Password: {account.Password}\n" +
                                $"Notes: {account.Description}\n" +
                                $"Last Updated: {DateTime.Now:yyyy-MM-dd HH:mm}\n";

            await File.AppendAllTextAsync(credentialsFilePath, credentialText);

            // Also create in Documents folder
            var documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            var documentsCredPath = Path.Combine(documentsPath, "account_info.txt");
            await File.AppendAllTextAsync(documentsCredPath, credentialText);

            _logger.LogInformation("Planted text file credentials for {ServiceName}", account.ServiceName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to plant text file for {ServiceName}", account.ServiceName);
            throw;
        }
    }

    /// <summary>
    /// Starts the internal fake login server
    /// </summary>
    public async Task StartFakeServerAsync(int port)
    {
        if (_webHost != null)
        {
            _logger.LogWarning("Fake server is already running");
            return;
        }

        _logger.LogInformation("Starting fake login server on port {Port}", port);

        _serverCts = new CancellationTokenSource();

        try
        {
            _webHost = Host.CreateDefaultBuilder()
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseKestrel();
                    webBuilder.UseUrls($"http://localhost:{port}");
                    webBuilder.Configure(app =>
                    {
                        app.Run(async context => await HandleRequestAsync(context));
                    });
                })
                .Build();

            await _webHost.StartAsync(_serverCts.Token);
            _logger.LogInformation("Fake server started successfully on port {Port}", port);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start fake server on port {Port}", port);
            throw;
        }
    }

    /// <summary>
    /// Handles incoming HTTP requests to the fake server
    /// </summary>
    private async Task HandleRequestAsync(HttpContext context)
    {
        var sessionId = Guid.NewGuid().ToString();
        var request = context.Request;

        // Collect attacker fingerprint
        var attackerProfile = new AttackerProfile
        {
            SessionId = sessionId,
            IPAddress = context.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
            UserAgent = request.Headers["User-Agent"].ToString(),
            Language = request.Headers["Accept-Language"].ToString(),
            FirstSeen = DateTime.UtcNow
        };

        // Collect additional fingerprinting data
        attackerProfile.FingerprintData["Referer"] = request.Headers["Referer"].ToString();
        attackerProfile.FingerprintData["Accept"] = request.Headers["Accept"].ToString();
        attackerProfile.FingerprintData["Accept-Encoding"] = request.Headers["Accept-Encoding"].ToString();
        attackerProfile.FingerprintData["Connection"] = request.Headers["Connection"].ToString();
        attackerProfile.FingerprintData["Host"] = request.Headers["Host"].ToString();

        // Parse User-Agent for browser and OS info
        var userAgent = attackerProfile.UserAgent;
        if (!string.IsNullOrEmpty(userAgent))
        {
            attackerProfile.Browser = ExtractBrowserInfo(userAgent);
            attackerProfile.OperatingSystem = ExtractOSInfo(userAgent);
        }

        _attackerProfiles[sessionId] = attackerProfile;

        _logger.LogWarning("Attacker accessed fake server - IP: {IP}, UserAgent: {UA}",
            attackerProfile.IPAddress, attackerProfile.UserAgent);

        // Handle different request paths
        if (request.Path == "/" || request.Path == "/login")
        {
            await ServeLoginPageAsync(context, sessionId);
        }
        else if (request.Path == "/authenticate" && request.Method == "POST")
        {
            await HandleLoginAttemptAsync(context, sessionId, attackerProfile);
        }
        else
        {
            context.Response.StatusCode = 404;
            await context.Response.WriteAsync("Not Found");
        }
    }

    /// <summary>
    /// Serves the fake login page
    /// </summary>
    private async Task ServeLoginPageAsync(HttpContext context, string sessionId)
    {
        context.Response.ContentType = "text/html";

        var html = $@"
<!DOCTYPE html>
<html>
<head>
    <title>Secure Login</title>
    <meta charset=""utf-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1"">
    <style>
        body {{
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }}
        .login-container {{
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
        }}
        h2 {{
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }}
        .form-group {{
            margin-bottom: 20px;
        }}
        label {{
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: bold;
        }}
        input[type=""text""], input[type=""password""] {{
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-sizing: border-box;
            font-size: 14px;
        }}
        button {{
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: background 0.3s;
        }}
        button:hover {{
            background: #5568d3;
        }}
        .footer {{
            text-align: center;
            margin-top: 20px;
            color: #888;
            font-size: 12px;
        }}
    </style>
    <script>
        // Collect comprehensive fingerprinting data
        window.onload = function() {{
            var fingerprint = {{
                screenResolution: screen.width + 'x' + screen.height,
                availScreenResolution: screen.availWidth + 'x' + screen.availHeight,
                colorDepth: screen.colorDepth,
                pixelDepth: screen.pixelDepth,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                timezoneOffset: new Date().getTimezoneOffset(),
                platform: navigator.platform,
                language: navigator.language,
                languages: navigator.languages ? navigator.languages.join(',') : '',
                plugins: Array.from(navigator.plugins).map(p => p.name).join(','),
                hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
                deviceMemory: navigator.deviceMemory || 'unknown',
                maxTouchPoints: navigator.maxTouchPoints || 0,
                cookieEnabled: navigator.cookieEnabled,
                doNotTrack: navigator.doNotTrack || 'unknown',
                sessionId: '{sessionId}',
                canvasFingerprint: getCanvasFingerprint(),
                webglVendor: getWebGLInfo().vendor,
                webglRenderer: getWebGLInfo().renderer,
                audioFingerprint: getAudioFingerprint()
            }};
            
            // Store in hidden field
            document.getElementById('fingerprint').value = JSON.stringify(fingerprint);
        }};

        // Canvas fingerprinting
        function getCanvasFingerprint() {{
            try {{
                var canvas = document.createElement('canvas');
                var ctx = canvas.getContext('2d');
                var txt = 'Honeypot<Canvas>Fingerprint123!@#';
                ctx.textBaseline = 'top';
                ctx.font = '14px Arial';
                ctx.textBaseline = 'alphabetic';
                ctx.fillStyle = '#f60';
                ctx.fillRect(125, 1, 62, 20);
                ctx.fillStyle = '#069';
                ctx.fillText(txt, 2, 15);
                ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
                ctx.fillText(txt, 4, 17);
                return canvas.toDataURL().substring(0, 100);
            }} catch(e) {{
                return 'error';
            }}
        }}

        // WebGL fingerprinting
        function getWebGLInfo() {{
            try {{
                var canvas = document.createElement('canvas');
                var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                if (!gl) return {{ vendor: 'none', renderer: 'none' }};
                var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                return {{
                    vendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'unknown',
                    renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown'
                }};
            }} catch(e) {{
                return {{ vendor: 'error', renderer: 'error' }};
            }}
        }}

        // Audio fingerprinting
        function getAudioFingerprint() {{
            try {{
                var audioContext = new (window.AudioContext || window.webkitAudioContext)();
                var oscillator = audioContext.createOscillator();
                var analyser = audioContext.createAnalyser();
                var gainNode = audioContext.createGain();
                var scriptProcessor = audioContext.createScriptProcessor(4096, 1, 1);
                
                gainNode.gain.value = 0;
                oscillator.connect(analyser);
                analyser.connect(scriptProcessor);
                scriptProcessor.connect(gainNode);
                gainNode.connect(audioContext.destination);
                
                oscillator.start(0);
                var hash = 0;
                scriptProcessor.onaudioprocess = function(event) {{
                    var output = event.outputBuffer.getChannelData(0);
                    for (var i = 0; i < output.length; i++) {{
                        hash += Math.abs(output[i]);
                    }}
                }};
                
                return hash.toString().substring(0, 20);
            }} catch(e) {{
                return 'error';
            }}
        }}
    </script>
</head>
<body>
    <div class=""login-container"">
        <h2>🔐 Secure Login</h2>
        <form method=""POST"" action=""/authenticate"">
            <input type=""hidden"" id=""fingerprint"" name=""fingerprint"" value="""">
            <div class=""form-group"">
                <label for=""username"">Username</label>
                <input type=""text"" id=""username"" name=""username"" required>
            </div>
            <div class=""form-group"">
                <label for=""password"">Password</label>
                <input type=""password"" id=""password"" name=""password"" required>
            </div>
            <button type=""submit"">Login</button>
        </form>
        <div class=""footer"">
            Secure Connection Established
        </div>
    </div>
</body>
</html>";

        await context.Response.WriteAsync(html);
    }

    /// <summary>
    /// Handles login attempt and collects credentials
    /// </summary>
    private async Task HandleLoginAttemptAsync(HttpContext context, string sessionId, AttackerProfile profile)
    {
        try
        {
            var form = await context.Request.ReadFormAsync();
            var username = form["username"].ToString();
            var password = form["password"].ToString();
            var fingerprintJson = form["fingerprint"].ToString();

            // Parse additional fingerprint data
            if (!string.IsNullOrEmpty(fingerprintJson))
            {
                try
                {
                    var fingerprintData = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(fingerprintJson);
                    if (fingerprintData != null)
                    {
                        foreach (var kvp in fingerprintData)
                        {
                            profile.FingerprintData[kvp.Key] = kvp.Value.ToString();
                        }

                        // Extract specific fingerprint fields
                        if (fingerprintData.ContainsKey("screenResolution"))
                            profile.ScreenResolution = fingerprintData["screenResolution"].GetString() ?? "";
                        
                        if (fingerprintData.ContainsKey("timezone"))
                            profile.Timezone = fingerprintData["timezone"].GetString() ?? "";
                        
                        if (fingerprintData.ContainsKey("plugins"))
                        {
                            var plugins = fingerprintData["plugins"].GetString() ?? "";
                            profile.BrowserPlugins = plugins.Split(',').Where(p => !string.IsNullOrWhiteSpace(p)).ToList();
                        }

                        if (fingerprintData.ContainsKey("canvasFingerprint"))
                            profile.CanvasFingerprint = fingerprintData["canvasFingerprint"].GetString() ?? "";
                        
                        if (fingerprintData.ContainsKey("webglVendor"))
                            profile.WebGLVendor = fingerprintData["webglVendor"].GetString() ?? "";
                        
                        if (fingerprintData.ContainsKey("webglRenderer"))
                            profile.WebGLRenderer = fingerprintData["webglRenderer"].GetString() ?? "";
                        
                        if (fingerprintData.ContainsKey("audioFingerprint"))
                            profile.AudioFingerprint = fingerprintData["audioFingerprint"].GetString() ?? "";
                        
                        if (fingerprintData.ContainsKey("hardwareConcurrency"))
                            profile.HardwareConcurrency = fingerprintData["hardwareConcurrency"].GetString() ?? "";
                        
                        if (fingerprintData.ContainsKey("deviceMemory"))
                            profile.DeviceMemory = fingerprintData["deviceMemory"].GetString() ?? "";
                        
                        if (fingerprintData.ContainsKey("platform"))
                            profile.Platform = fingerprintData["platform"].GetString() ?? "";
                        
                        if (fingerprintData.ContainsKey("colorDepth"))
                            profile.ColorDepth = fingerprintData["colorDepth"].GetString() ?? "";
                        
                        if (fingerprintData.ContainsKey("cookieEnabled"))
                            profile.CookiesEnabled = fingerprintData["cookieEnabled"].GetBoolean();
                        
                        if (fingerprintData.ContainsKey("doNotTrack"))
                            profile.DoNotTrack = fingerprintData["doNotTrack"].GetString() ?? "";
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to parse fingerprint data");
                }
            }

            profile.AccessedCredentials.Add($"{username}:{password}");

            // Encrypt and store attacker profile as evidence
            try
            {
                var profileJson = JsonSerializer.Serialize(profile, new JsonSerializerOptions { WriteIndented = true });
                profile.EncryptedData = EncryptData(profileJson);
                profile.DataHash = ComputeHash(profileJson);
                
                _logger.LogInformation("Attacker profile encrypted and stored with hash: {Hash}", profile.DataHash);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to encrypt attacker profile");
            }

            _logger.LogCritical("CREDENTIAL THEFT DETECTED! Username: {Username}, Password: {Password}, IP: {IP}, Browser: {Browser}, OS: {OS}",
                username, password, profile.IPAddress, profile.Browser, profile.OperatingSystem);

            // Fire credential used event
            var eventArgs = new CredentialAttemptEventArgs
            {
                Username = username,
                Password = password,
                SourceIP = profile.IPAddress,
                UserAgent = profile.UserAgent,
                Timestamp = DateTime.UtcNow,
                AttackerProfile = profile
            };

            CredentialUsed?.Invoke(this, eventArgs);

            // Serve a fake "success" page to keep attacker engaged
            context.Response.ContentType = "text/html";
            var successHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>Login Successful</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .success-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            text-align: center;
        }
        .success-icon {
            font-size: 64px;
            color: #4CAF50;
        }
        h2 {
            color: #333;
            margin: 20px 0;
        }
        p {
            color: #666;
        }
    </style>
</head>
<body>
    <div class=""success-container"">
        <div class=""success-icon"">✓</div>
        <h2>Login Successful</h2>
        <p>You have been authenticated successfully.</p>
        <p>Redirecting to dashboard...</p>
    </div>
    <script>
        setTimeout(function() {
            window.location.href = '/';
        }, 3000);
    </script>
</body>
</html>";

            await context.Response.WriteAsync(successHtml);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling login attempt");
            context.Response.StatusCode = 500;
            await context.Response.WriteAsync("Internal Server Error");
        }
    }

    /// <summary>
    /// Encrypts data using AES encryption
    /// </summary>
    private string EncryptData(string plainText)
    {
        using var aes = System.Security.Cryptography.Aes.Create();
        aes.Key = DeriveKey("HoneypotEncryptionKey2024!@#$");
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var msEncrypt = new MemoryStream();
        
        // Write IV to the beginning of the stream
        msEncrypt.Write(aes.IV, 0, aes.IV.Length);
        
        using (var csEncrypt = new System.Security.Cryptography.CryptoStream(msEncrypt, encryptor, System.Security.Cryptography.CryptoStreamMode.Write))
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(plainText);
        }

        return Convert.ToBase64String(msEncrypt.ToArray());
    }

    /// <summary>
    /// Derives a 256-bit key from a passphrase
    /// </summary>
    private byte[] DeriveKey(string passphrase)
    {
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        return sha256.ComputeHash(Encoding.UTF8.GetBytes(passphrase));
    }

    /// <summary>
    /// Computes SHA256 hash of data for integrity verification
    /// </summary>
    private string ComputeHash(string data)
    {
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(data));
        return Convert.ToBase64String(hashBytes);
    }

    /// <summary>
    /// Extracts browser information from User-Agent string
    /// </summary>
    private string ExtractBrowserInfo(string userAgent)
    {
        if (userAgent.Contains("Chrome") && !userAgent.Contains("Edg"))
            return "Chrome";
        if (userAgent.Contains("Firefox"))
            return "Firefox";
        if (userAgent.Contains("Safari") && !userAgent.Contains("Chrome"))
            return "Safari";
        if (userAgent.Contains("Edg"))
            return "Edge";
        if (userAgent.Contains("MSIE") || userAgent.Contains("Trident"))
            return "Internet Explorer";

        return "Unknown";
    }

    /// <summary>
    /// Extracts OS information from User-Agent string
    /// </summary>
    private string ExtractOSInfo(string userAgent)
    {
        if (userAgent.Contains("Windows NT 10.0"))
            return "Windows 10/11";
        if (userAgent.Contains("Windows NT 6.3"))
            return "Windows 8.1";
        if (userAgent.Contains("Windows NT 6.2"))
            return "Windows 8";
        if (userAgent.Contains("Windows NT 6.1"))
            return "Windows 7";
        if (userAgent.Contains("Mac OS X"))
            return "macOS";
        if (userAgent.Contains("Linux"))
            return "Linux";
        if (userAgent.Contains("Android"))
            return "Android";
        if (userAgent.Contains("iOS"))
            return "iOS";

        return "Unknown";
    }

    /// <summary>
    /// Stops the fake server
    /// </summary>
    public async Task StopFakeServerAsync()
    {
        if (_webHost == null)
        {
            _logger.LogWarning("Fake server is not running");
            return;
        }

        _logger.LogInformation("Stopping fake login server");

        try
        {
            _serverCts?.Cancel();
            await _webHost.StopAsync();
            _webHost.Dispose();
            _webHost = null;
            _serverCts?.Dispose();
            _serverCts = null;

            _logger.LogInformation("Fake server stopped successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error stopping fake server");
            throw;
        }
    }

    /// <summary>
    /// Gets the attacker profile for a specific session
    /// </summary>
    public AttackerProfile? GetAttackerProfile(string sessionId)
    {
        return _attackerProfiles.TryGetValue(sessionId, out var profile) ? profile : null;
    }

    /// <summary>
    /// Gets all attacker profiles collected
    /// </summary>
    public List<AttackerProfile> GetAllAttackerProfiles()
    {
        return _attackerProfiles.Values.ToList();
    }

    /// <summary>
    /// Gets the count of credential attempts
    /// </summary>
    public int GetCredentialAttemptCount()
    {
        return _attackerProfiles.Values.Sum(p => p.AccessedCredentials.Count);
    }
}
