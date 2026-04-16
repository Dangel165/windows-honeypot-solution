using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Interfaces;

/// <summary>
/// Create realistic business environment with fake processes
/// </summary>
public interface IProcessCamouflage
{
    /// <summary>
    /// Starts fake processes based on the provided profiles
    /// </summary>
    /// <param name="profiles">List of process profiles to create</param>
    Task StartFakeProcessesAsync(List<ProcessProfile> profiles);

    /// <summary>
    /// Stops all fake processes
    /// </summary>
    Task StopAllFakeProcessesAsync();

    /// <summary>
    /// Updates process metrics to simulate realistic usage
    /// </summary>
    void UpdateProcessMetrics();

    /// <summary>
    /// Gets the list of currently active fake processes
    /// </summary>
    /// <returns>List of active fake processes</returns>
    List<FakeProcess> GetActiveProcesses();
}