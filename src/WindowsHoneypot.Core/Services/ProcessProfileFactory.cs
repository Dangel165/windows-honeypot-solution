using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Factory for creating predefined process profiles for common business applications
/// </summary>
public static class ProcessProfileFactory
{
    /// <summary>
    /// Gets a list of default business application process profiles
    /// </summary>
    public static List<ProcessProfile> GetDefaultBusinessProfiles()
    {
        return new List<ProcessProfile>
        {
            CreateSlackProfile(),
            CreateTeamsProfile(),
            CreateChromeProfile(),
            CreateZoomProfile(),
            CreateNotionProfile(),
            CreateOutlookProfile(),
            CreateVSCodeProfile(),
            CreateSpotifyProfile()
        };
    }

    /// <summary>
    /// Creates a Slack process profile
    /// </summary>
    public static ProcessProfile CreateSlackProfile()
    {
        return new ProcessProfile
        {
            ProcessName = "slack.exe",
            Description = "Slack - Team Communication",
            CompanyName = "Slack Technologies, Inc.",
            ProductVersion = "4.35.131",
            FakeCpuUsage = 2,
            FakeMemoryUsage = 350 * 1024 * 1024, // 350 MB
            SimulateNetworkActivity = true,
            VariableCpuUsage = true,
            FakeNetworkConnections = new List<string>
            {
                "slack.com:443",
                "files.slack.com:443",
                "wss-primary.slack.com:443"
            },
            CreateFakeService = false
        };
    }

    /// <summary>
    /// Creates a Microsoft Teams process profile
    /// </summary>
    public static ProcessProfile CreateTeamsProfile()
    {
        return new ProcessProfile
        {
            ProcessName = "Teams.exe",
            Description = "Microsoft Teams",
            CompanyName = "Microsoft Corporation",
            ProductVersion = "1.6.00.4472",
            FakeCpuUsage = 3,
            FakeMemoryUsage = 450 * 1024 * 1024, // 450 MB
            SimulateNetworkActivity = true,
            VariableCpuUsage = true,
            FakeNetworkConnections = new List<string>
            {
                "teams.microsoft.com:443",
                "api.teams.microsoft.com:443",
                "presence.teams.microsoft.com:443"
            },
            CreateFakeService = false
        };
    }

    /// <summary>
    /// Creates a Google Chrome process profile
    /// </summary>
    public static ProcessProfile CreateChromeProfile()
    {
        return new ProcessProfile
        {
            ProcessName = "chrome.exe",
            Description = "Google Chrome",
            CompanyName = "Google LLC",
            ProductVersion = "120.0.6099.130",
            FakeCpuUsage = 5,
            FakeMemoryUsage = 600 * 1024 * 1024, // 600 MB
            SimulateNetworkActivity = true,
            VariableCpuUsage = true,
            FakeNetworkConnections = new List<string>
            {
                "www.google.com:443",
                "accounts.google.com:443",
                "mail.google.com:443",
                "drive.google.com:443"
            },
            CreateFakeService = false
        };
    }

    /// <summary>
    /// Creates a Zoom process profile
    /// </summary>
    public static ProcessProfile CreateZoomProfile()
    {
        return new ProcessProfile
        {
            ProcessName = "Zoom.exe",
            Description = "Zoom Video Communications",
            CompanyName = "Zoom Video Communications, Inc.",
            ProductVersion = "5.16.10.26186",
            FakeCpuUsage = 1,
            FakeMemoryUsage = 280 * 1024 * 1024, // 280 MB
            SimulateNetworkActivity = true,
            VariableCpuUsage = true,
            FakeNetworkConnections = new List<string>
            {
                "zoom.us:443",
                "us04web.zoom.us:443"
            },
            CreateFakeService = true
        };
    }

    /// <summary>
    /// Creates a Notion process profile
    /// </summary>
    public static ProcessProfile CreateNotionProfile()
    {
        return new ProcessProfile
        {
            ProcessName = "Notion.exe",
            Description = "Notion - Notes, Docs, Tasks",
            CompanyName = "Notion Labs, Inc.",
            ProductVersion = "2.2.3",
            FakeCpuUsage = 2,
            FakeMemoryUsage = 320 * 1024 * 1024, // 320 MB
            SimulateNetworkActivity = true,
            VariableCpuUsage = true,
            FakeNetworkConnections = new List<string>
            {
                "www.notion.so:443",
                "api.notion.com:443"
            },
            CreateFakeService = false
        };
    }

    /// <summary>
    /// Creates a Microsoft Outlook process profile
    /// </summary>
    public static ProcessProfile CreateOutlookProfile()
    {
        return new ProcessProfile
        {
            ProcessName = "OUTLOOK.EXE",
            Description = "Microsoft Outlook",
            CompanyName = "Microsoft Corporation",
            ProductVersion = "16.0.16827.20166",
            FakeCpuUsage = 2,
            FakeMemoryUsage = 400 * 1024 * 1024, // 400 MB
            SimulateNetworkActivity = true,
            VariableCpuUsage = true,
            FakeNetworkConnections = new List<string>
            {
                "outlook.office365.com:443",
                "smtp.office365.com:587"
            },
            CreateFakeService = false
        };
    }

    /// <summary>
    /// Creates a Visual Studio Code process profile
    /// </summary>
    public static ProcessProfile CreateVSCodeProfile()
    {
        return new ProcessProfile
        {
            ProcessName = "Code.exe",
            Description = "Visual Studio Code",
            CompanyName = "Microsoft Corporation",
            ProductVersion = "1.85.1",
            FakeCpuUsage = 4,
            FakeMemoryUsage = 500 * 1024 * 1024, // 500 MB
            SimulateNetworkActivity = true,
            VariableCpuUsage = true,
            FakeNetworkConnections = new List<string>
            {
                "vscode.dev:443",
                "marketplace.visualstudio.com:443"
            },
            CreateFakeService = false
        };
    }

    /// <summary>
    /// Creates a Spotify process profile
    /// </summary>
    public static ProcessProfile CreateSpotifyProfile()
    {
        return new ProcessProfile
        {
            ProcessName = "Spotify.exe",
            Description = "Spotify - Music and Podcasts",
            CompanyName = "Spotify AB",
            ProductVersion = "1.2.26.1187",
            FakeCpuUsage = 1,
            FakeMemoryUsage = 250 * 1024 * 1024, // 250 MB
            SimulateNetworkActivity = true,
            VariableCpuUsage = true,
            FakeNetworkConnections = new List<string>
            {
                "api.spotify.com:443",
                "spclient.wg.spotify.com:443"
            },
            CreateFakeService = false
        };
    }

    /// <summary>
    /// Creates a custom process profile with specified parameters
    /// </summary>
    public static ProcessProfile CreateCustomProfile(
        string processName,
        string description,
        string companyName,
        int cpuUsage,
        long memoryUsageMB,
        List<string>? networkConnections = null)
    {
        return new ProcessProfile
        {
            ProcessName = processName,
            Description = description,
            CompanyName = companyName,
            ProductVersion = "1.0.0.0",
            FakeCpuUsage = cpuUsage,
            FakeMemoryUsage = memoryUsageMB * 1024 * 1024,
            SimulateNetworkActivity = networkConnections != null && networkConnections.Count > 0,
            VariableCpuUsage = true,
            FakeNetworkConnections = networkConnections ?? new List<string>(),
            CreateFakeService = false
        };
    }

    /// <summary>
    /// Gets a subset of profiles based on a business scenario
    /// </summary>
    public static List<ProcessProfile> GetProfilesForScenario(string scenario)
    {
        return scenario.ToLowerInvariant() switch
        {
            "developer" => new List<ProcessProfile>
            {
                CreateVSCodeProfile(),
                CreateChromeProfile(),
                CreateSlackProfile(),
                CreateSpotifyProfile()
            },
            "office" => new List<ProcessProfile>
            {
                CreateOutlookProfile(),
                CreateTeamsProfile(),
                CreateChromeProfile(),
                CreateNotionProfile()
            },
            "remote" => new List<ProcessProfile>
            {
                CreateZoomProfile(),
                CreateTeamsProfile(),
                CreateSlackProfile(),
                CreateChromeProfile()
            },
            "minimal" => new List<ProcessProfile>
            {
                CreateChromeProfile(),
                CreateOutlookProfile()
            },
            _ => GetDefaultBusinessProfiles()
        };
    }
}
