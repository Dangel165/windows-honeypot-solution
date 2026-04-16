using FsCheck;
using FsCheck.Xunit;
using FluentAssertions;
using WindowsHoneypot.Core.Models;
using WindowsHoneypot.Core.Services;
using System.Xml;

namespace WindowsHoneypot.Tests.CoreTests;

/// <summary>
/// Property-based tests for SandboxConfigurationGenerator
/// **Feature: windows-honeypot-solution, Property 1: Sandbox Configuration Generation**
/// </summary>
public class SandboxConfigurationGeneratorPropertyTests
{
    private readonly SandboxConfigurationGenerator _generator;

    public SandboxConfigurationGeneratorPropertyTests()
    {
        _generator = new SandboxConfigurationGenerator();
    }

    /// <summary>
    /// Custom generator for valid SandboxConfiguration instances
    /// </summary>
    private static Arbitrary<SandboxConfiguration> ValidSandboxConfigurationGenerator()
    {
        var gen = from networkingEnabled in Arb.Generate<bool>()
                  from memoryInMB in Gen.Choose(512, 16384)
                  from vGpuEnabled in Arb.Generate<bool>()
                  from audioInputEnabled in Arb.Generate<bool>()
                  from videoInputEnabled in Arb.Generate<bool>()
                  from protectedClientEnabled in Arb.Generate<bool>()
                  from printerRedirectionEnabled in Arb.Generate<bool>()
                  from clipboardRedirectionEnabled in Arb.Generate<bool>()
                  from baitFolderPath in Gen.Elements(string.Empty, @"C:\BaitFolder", @"C:\TestData", @"D:\Honeypot")
                  from mountedFoldersCount in Gen.Choose(0, 5)
                  from mountedFolders in Gen.ListOf(mountedFoldersCount, Gen.Elements(@"C:\Folder1", @"C:\Folder2", @"D:\Data", string.Empty))
                  select new SandboxConfiguration
                  {
                      NetworkingEnabled = networkingEnabled,
                      MemoryInMB = memoryInMB,
                      VGpuEnabled = vGpuEnabled,
                      AudioInputEnabled = audioInputEnabled,
                      VideoInputEnabled = videoInputEnabled,
                      ProtectedClientEnabled = protectedClientEnabled,
                      PrinterRedirectionEnabled = printerRedirectionEnabled,
                      ClipboardRedirectionEnabled = clipboardRedirectionEnabled,
                      BaitFolderPath = baitFolderPath,
                      MountedFolders = mountedFolders.ToList()
                  };

        return Arb.From(gen);
    }

    /// <summary>
    /// Property 1: For any valid sandbox configuration input, the Honeypot Manager SHALL generate 
    /// a corresponding .wsb file with correct networking disabled and folder mount settings.
    /// **Validates: Requirements 1.1, 1.2, 2.1**
    /// </summary>
    [Property(MaxTest = 100, Arbitrary = new[] { typeof(Generators) })]
    public Property GenerateWsbXml_WithAnyValidConfiguration_ProducesValidXml()
    {
        return Prop.ForAll(
            ValidSandboxConfigurationGenerator(),
            config =>
            {
                // Act
                var xml = _generator.GenerateWsbXml(config);

                // Assert - XML should be well-formed
                xml.Should().NotBeNullOrEmpty();
                
                // Verify XML can be parsed
                var xmlDoc = new XmlDocument();
                Action parseAction = () => xmlDoc.LoadXml(xml);
                parseAction.Should().NotThrow("XML should be well-formed");

                // Verify root element
                xmlDoc.DocumentElement.Should().NotBeNull();
                xmlDoc.DocumentElement!.Name.Should().Be("Configuration");

                return true;
            });
    }

    /// <summary>
    /// Property 1.1: For any valid configuration, networking setting SHALL be correctly represented
    /// **Validates: Requirements 1.1, 1.2**
    /// </summary>
    [Property(MaxTest = 100, Arbitrary = new[] { typeof(Generators) })]
    public Property GenerateWsbXml_WithAnyConfiguration_ContainsCorrectNetworkingSetting()
    {
        return Prop.ForAll(
            ValidSandboxConfigurationGenerator(),
            config =>
            {
                // Act
                var xml = _generator.GenerateWsbXml(config);

                // Assert - Networking setting should match configuration
                var expectedNetworking = config.NetworkingEnabled ? "Enable" : "Disable";
                xml.Should().Contain($"<Networking>{expectedNetworking}</Networking>");

                return true;
            });
    }

    /// <summary>
    /// Property 1.2: For any configuration with folders, all folders SHALL be mounted as ReadOnly
    /// **Validates: Requirements 2.1**
    /// </summary>
    [Property(MaxTest = 100, Arbitrary = new[] { typeof(Generators) })]
    public Property GenerateWsbXml_WithFolders_MountsAllFoldersAsReadOnly()
    {
        return Prop.ForAll(
            ValidSandboxConfigurationGenerator(),
            config =>
            {
                // Act
                var xml = _generator.GenerateWsbXml(config);

                // Count expected folders (non-empty bait folder + non-empty mounted folders)
                var expectedFolderCount = 0;
                if (!string.IsNullOrWhiteSpace(config.BaitFolderPath))
                    expectedFolderCount++;
                
                if (config.MountedFolders != null)
                    expectedFolderCount += config.MountedFolders.Count(f => !string.IsNullOrWhiteSpace(f));

                // Assert - If there are folders, verify MappedFolders section exists
                if (expectedFolderCount > 0)
                {
                    xml.Should().Contain("<MappedFolders>");
                    xml.Should().Contain("</MappedFolders>");
                    
                    // Count ReadOnly tags - should match folder count
                    var readOnlyCount = System.Text.RegularExpressions.Regex.Matches(xml, "<ReadOnly>true</ReadOnly>").Count;
                    readOnlyCount.Should().Be(expectedFolderCount, 
                        $"All {expectedFolderCount} folders should be mounted as ReadOnly");
                }
                else
                {
                    // No folders means no MappedFolders section
                    xml.Should().NotContain("<MappedFolders>");
                }

                return true;
            });
    }

    /// <summary>
    /// Property 1.3: For any configuration, memory setting SHALL be correctly represented
    /// **Validates: Requirements 1.1**
    /// </summary>
    [Property(MaxTest = 100, Arbitrary = new[] { typeof(Generators) })]
    public Property GenerateWsbXml_WithAnyConfiguration_ContainsCorrectMemorySetting()
    {
        return Prop.ForAll(
            ValidSandboxConfigurationGenerator(),
            config =>
            {
                // Act
                var xml = _generator.GenerateWsbXml(config);

                // Assert - Memory setting should match configuration
                xml.Should().Contain($"<MemoryInMB>{config.MemoryInMB}</MemoryInMB>");

                return true;
            });
    }

    /// <summary>
    /// Property 1.4: For any configuration, all boolean settings SHALL be correctly represented
    /// **Validates: Requirements 1.1**
    /// </summary>
    [Property(MaxTest = 100, Arbitrary = new[] { typeof(Generators) })]
    public Property GenerateWsbXml_WithAnyConfiguration_ContainsAllBooleanSettings()
    {
        return Prop.ForAll(
            ValidSandboxConfigurationGenerator(),
            config =>
            {
                // Act
                var xml = _generator.GenerateWsbXml(config);

                // Assert - All boolean settings should be present
                xml.Should().Contain($"<VGpu>{(config.VGpuEnabled ? "Enable" : "Disable")}</VGpu>");
                xml.Should().Contain($"<AudioInput>{(config.AudioInputEnabled ? "Enable" : "Disable")}</AudioInput>");
                xml.Should().Contain($"<VideoInput>{(config.VideoInputEnabled ? "Enable" : "Disable")}</VideoInput>");
                xml.Should().Contain($"<ProtectedClient>{(config.ProtectedClientEnabled ? "Enable" : "Disable")}</ProtectedClient>");
                xml.Should().Contain($"<PrinterRedirection>{(config.PrinterRedirectionEnabled ? "Enable" : "Disable")}</PrinterRedirection>");
                xml.Should().Contain($"<ClipboardRedirection>{(config.ClipboardRedirectionEnabled ? "Enable" : "Disable")}</ClipboardRedirection>");

                return true;
            });
    }

    /// <summary>
    /// Property 1.5: For any configuration with bait folder, the bait folder SHALL be included in MappedFolders
    /// **Validates: Requirements 2.1**
    /// </summary>
    [Property(MaxTest = 100, Arbitrary = new[] { typeof(Generators) })]
    public Property GenerateWsbXml_WithBaitFolder_IncludesBaitFolderInMappedFolders()
    {
        return Prop.ForAll(
            ValidSandboxConfigurationGenerator().Filter(c => !string.IsNullOrWhiteSpace(c.BaitFolderPath)),
            config =>
            {
                // Act
                var xml = _generator.GenerateWsbXml(config);

                // Assert - Bait folder should be in the XML
                xml.Should().Contain($"<HostFolder>{config.BaitFolderPath}</HostFolder>");

                return true;
            });
    }

    /// <summary>
    /// Property 1.6: For any configuration with mounted folders, all non-empty folders SHALL be included
    /// **Validates: Requirements 2.1**
    /// </summary>
    [Property(MaxTest = 100, Arbitrary = new[] { typeof(Generators) })]
    public Property GenerateWsbXml_WithMountedFolders_IncludesAllNonEmptyFolders()
    {
        return Prop.ForAll(
            ValidSandboxConfigurationGenerator().Filter(c => c.MountedFolders != null && c.MountedFolders.Any(f => !string.IsNullOrWhiteSpace(f))),
            config =>
            {
                // Act
                var xml = _generator.GenerateWsbXml(config);

                // Assert - All non-empty mounted folders should be in the XML
                var nonEmptyFolders = config.MountedFolders.Where(f => !string.IsNullOrWhiteSpace(f)).ToList();
                foreach (var folder in nonEmptyFolders)
                {
                    xml.Should().Contain($"<HostFolder>{folder}</HostFolder>",
                        $"Mounted folder '{folder}' should be included in the XML");
                }

                return true;
            });
    }

    /// <summary>
    /// Property 1.7: Generated XML SHALL always have proper structure with Configuration root element
    /// **Validates: Requirements 1.1**
    /// </summary>
    [Property(MaxTest = 100, Arbitrary = new[] { typeof(Generators) })]
    public Property GenerateWsbXml_WithAnyConfiguration_HasProperXmlStructure()
    {
        return Prop.ForAll(
            ValidSandboxConfigurationGenerator(),
            config =>
            {
                // Act
                var xml = _generator.GenerateWsbXml(config);

                // Assert - XML should have proper structure
                xml.Should().StartWith("<?xml");
                xml.Should().Contain("<Configuration>");
                xml.Should().Contain("</Configuration>");
                xml.Should().EndWith("</Configuration>");

                return true;
            });
    }

    /// <summary>
    /// Property 1.8: For any configuration, the generated XML SHALL be parseable by XmlDocument
    /// **Validates: Requirements 1.1**
    /// </summary>
    [Property(MaxTest = 100, Arbitrary = new[] { typeof(Generators) })]
    public Property GenerateWsbXml_WithAnyConfiguration_ProducesParseableXml()
    {
        return Prop.ForAll(
            ValidSandboxConfigurationGenerator(),
            config =>
            {
                // Act
                var xml = _generator.GenerateWsbXml(config);

                // Assert - XML should be parseable
                var xmlDoc = new XmlDocument();
                Action parseAction = () => xmlDoc.LoadXml(xml);
                parseAction.Should().NotThrow("Generated XML should always be parseable");

                // Verify we can query the document
                var configNode = xmlDoc.SelectSingleNode("/Configuration");
                configNode.Should().NotBeNull("Configuration root element should exist");

                return true;
            });
    }

    /// <summary>
    /// Generators class for FsCheck
    /// </summary>
    public static class Generators
    {
        public static Arbitrary<SandboxConfiguration> SandboxConfiguration()
        {
            return ValidSandboxConfigurationGenerator();
        }
    }
}
