using WindowsHoneypot.Core.Models;

namespace WindowsHoneypot.Core.Interfaces;

/// <summary>
/// Collect attacker information through fake credential usage
/// </summary>
public interface IHoneyAccountSystem
{
    /// <summary>
    /// Plants fake credentials in browser bookmarks and files
    /// </summary>
    /// <param name="accounts">List of honey accounts to plant</param>
    Task PlantCredentialsAsync(List<HoneyAccount> accounts);

    /// <summary>
    /// Starts the internal fake server on the specified port
    /// </summary>
    /// <param name="port">Port to run the fake server on</param>
    Task StartFakeServerAsync(int port);

    /// <summary>
    /// Stops the fake server
    /// </summary>
    Task StopFakeServerAsync();

    /// <summary>
    /// Gets the attacker profile for a specific session
    /// </summary>
    /// <param name="sessionId">Session ID to get profile for</param>
    /// <returns>Attacker profile information</returns>
    AttackerProfile? GetAttackerProfile(string sessionId);

    /// <summary>
    /// Gets all attacker profiles collected
    /// </summary>
    /// <returns>List of all attacker profiles</returns>
    List<AttackerProfile> GetAllAttackerProfiles();

    /// <summary>
    /// Gets the count of credential attempts
    /// </summary>
    /// <returns>Total number of credential attempts</returns>
    int GetCredentialAttemptCount();

    /// <summary>
    /// Event fired when credentials are used by an attacker
    /// </summary>
    event EventHandler<CredentialAttemptEventArgs>? CredentialUsed;
}