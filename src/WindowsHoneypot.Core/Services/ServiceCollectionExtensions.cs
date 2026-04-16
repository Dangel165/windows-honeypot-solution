using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;
using WindowsHoneypot.Core.Interfaces;

namespace WindowsHoneypot.Core.Services;

/// <summary>
/// Extension methods for configuring dependency injection
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds all core honeypot services to the dependency injection container
    /// </summary>
    /// <param name="services">Service collection to configure</param>
    /// <returns>Configured service collection</returns>
    public static IServiceCollection AddHoneypotCore(this IServiceCollection services)
    {
        // Configure Serilog logging
        Log.Logger = new LoggerConfiguration()
            .WriteTo.Console()
            .WriteTo.File("logs/honeypot-.log", rollingInterval: RollingInterval.Day)
            .CreateLogger();

        services.AddLogging(builder =>
        {
            builder.ClearProviders();
            builder.AddSerilog();
        });

        // Register services
        services.AddSingleton<SandboxConfigurationGenerator>();
        services.AddTransient<ProcessTracker>();
        services.AddSingleton<PrivilegeMonitor>();
        services.AddSingleton<ActivityLogger>();
        services.AddSingleton<ThreatPatternDatabase>();
        services.AddSingleton<NetworkThreatBlocker>();
        services.AddSingleton<HoneypotIntelligenceIntegration>();

        // Register core interfaces
        services.AddSingleton<IHoneypotManager, HoneypotManager>();
        services.AddSingleton<IFileMonitor, FileMonitor>();
        services.AddSingleton<IIntrusionAlertSystem, IntrusionAlertSystem>();
        services.AddSingleton<INetworkBlocker, NetworkBlocker>();
        services.AddSingleton<IDeceptionEngine, DeceptionEngine>();
        services.AddSingleton<IConfigurationManager, HoneypotConfigurationManager>();
        services.AddSingleton<IProcessCamouflage, ProcessCamouflage>();
        services.AddSingleton<IHoneyAccountSystem, HoneyAccountSystem>();
        services.AddSingleton<IVisualReplayEngine, VisualReplayEngine>();
        services.AddSingleton<IInstantSanitization, InstantSanitization>();
        services.AddSingleton<IRealTimeThreatMonitor, RealTimeThreatMonitor>();
        services.AddSingleton<IBehavioralAnalysisEngine, BehavioralAnalysisEngine>();
        services.AddSingleton<IHardwareSecurityMonitor, HardwareSecurityMonitor>();
        services.AddSingleton<IEmailAttachmentScanner, EmailAttachmentScanner>();
        services.AddSingleton<IWebBrowsingProtection, WebBrowsingProtection>();
        services.AddSingleton<IPhishingDetector, PhishingDetector>();
        
        services.AddSingleton<IAutomatedResponseSystem, AutomatedResponseSystem>();

        // Register Community Intelligence with configuration factory
        services.AddSingleton<ICommunityIntelligence>(provider =>
        {
            var logger = provider.GetRequiredService<ILogger<CommunityIntelligence>>();
            var configManager = provider.GetRequiredService<IConfigurationManager>();
            var config = configManager.GetCurrentConfiguration();
            return new CommunityIntelligence(logger, config.CommunitySettings);
        });

        return services;
    }
}