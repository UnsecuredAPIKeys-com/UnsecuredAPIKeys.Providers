using System.Net;

namespace UnsecuredAPIKeys.Providers.Core;

/// <summary>
/// Defines the contract for an API key provider, responsible for
/// identifying and validating keys for a specific service.
/// </summary>
public interface IApiKeyProvider
{
    /// <summary>
    /// Gets the unique name of the provider (e.g., "OpenAI", "Anthropic").
    /// </summary>
    string ProviderName { get; }

    /// <summary>
    /// Gets the corresponding ApiTypeEnum value for this provider.
    /// </summary>
    ApiTypeEnum ApiType { get; }

    /// <summary>
    /// Gets the list of regex patterns used to identify potential keys for this provider.
    /// </summary>
    IEnumerable<string> RegexPatterns { get; }

    /// <summary>
    /// Asynchronously validates the given API key against the provider's service.
    /// </summary>
    /// <param name="apiKey">The API key string to validate.</param>
    /// <param name="httpClientFactory">The IHttpClientFactory for creating HttpClient instances.</param>
    /// <param name="proxy">Optional WebProxy to use for the validation request.</param>
    /// <returns>A ValidationResult indicating the outcome of the validation attempt.</returns>
    Task<ValidationResult> ValidateKeyAsync(string apiKey, IHttpClientFactory httpClientFactory, WebProxy? proxy);
}
