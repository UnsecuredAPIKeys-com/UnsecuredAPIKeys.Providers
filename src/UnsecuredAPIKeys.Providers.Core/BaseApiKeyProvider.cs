using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;

namespace UnsecuredAPIKeys.Providers.Core;

/// <summary>
/// Base class for API key providers with common functionality, retry logic, and proper resource management.
/// </summary>
public abstract class BaseApiKeyProvider(ILogger? logger = null) : IApiKeyProvider
{
    protected const int DEFAULT_MAX_RETRIES = 3;
    protected const int DEFAULT_TIMEOUT_SECONDS = 30;

    protected readonly ILogger? _logger = logger;

    public abstract string ProviderName { get; }
    public abstract ApiTypeEnum ApiType { get; }
    public abstract IEnumerable<string> RegexPatterns { get; }

    /// <summary>
    /// Validates an API key with retry logic and proper resource management.
    /// </summary>
    public async Task<ValidationResult> ValidateKeyAsync(string apiKey, IHttpClientFactory httpClientFactory, WebProxy? proxy)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return ValidationResult.HasProviderSpecificError("API key is null or whitespace.");
        }

        // Clean the API key
        apiKey = CleanApiKey(apiKey);

        // Validate format if implemented
        if (!IsValidKeyFormat(apiKey))
        {
            return ValidationResult.HasProviderSpecificError("API key format is invalid.");
        }

        Exception? lastException = null;

        for (int retry = 0; retry < GetMaxRetries(); retry++)
        {
            if (retry > 0)
            {
                var delay = TimeSpan.FromSeconds(Math.Pow(2, retry - 1));
                _logger?.LogDebug("Retrying {Provider} validation after {Delay}ms (attempt {Retry}/{MaxRetries})",
                    ProviderName, delay.TotalMilliseconds, retry + 1, GetMaxRetries());
                await Task.Delay(delay);
            }

            try
            {
                using var httpClient = CreateHttpClient(httpClientFactory, proxy);
                var result = await ValidateKeyWithHttpClientAsync(apiKey, httpClient);

                if (result.Status != ValidationAttemptStatus.NetworkError)
                {
                    return result;
                }

                // Continue retrying on network errors
                lastException = new Exception(result.Detail);
            }
            catch (HttpRequestException ex)
            {
                lastException = ex;
                _logger?.LogWarning(ex, "HTTP request failed on attempt {Retry}/{MaxRetries} for {Provider}",
                    retry + 1, GetMaxRetries(), ProviderName);

                if (retry == GetMaxRetries() - 1)
                {
                    return ValidationResult.HasNetworkError($"HTTP request failed after {GetMaxRetries()} retries: {ex.Message}");
                }
            }
            catch (TaskCanceledException ex)
            {
                lastException = ex;
                _logger?.LogWarning(ex, "Request timeout on attempt {Retry}/{MaxRetries} for {Provider}",
                    retry + 1, GetMaxRetries(), ProviderName);

                if (retry == GetMaxRetries() - 1)
                {
                    return ValidationResult.HasNetworkError($"Request timeout after {GetMaxRetries()} retries: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Unexpected error during {Provider} key validation", ProviderName);
                return ValidationResult.HasProviderSpecificError($"Unexpected error: {ex.Message}");
            }
        }

        return ValidationResult.HasNetworkError($"Failed after {GetMaxRetries()} retries. Last error: {lastException?.Message ?? "Unknown error"}");
    }

    /// <summary>
    /// Abstract method for provider-specific validation logic.
    /// </summary>
    protected abstract Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient);

    /// <summary>
    /// Creates an HttpClient with proper configuration and resource management.
    /// </summary>
    protected virtual HttpClient CreateHttpClient(IHttpClientFactory httpClientFactory, WebProxy? proxy)
    {
        // Prefer using the factory if available and no proxy is needed
        if (proxy == null && httpClientFactory != null)
        {
            try
            {
                var client = httpClientFactory.CreateClient(ProviderName.ToLowerInvariant().Replace(" ", ""));
                client.Timeout = TimeSpan.FromSeconds(GetTimeoutSeconds());
                return client;
            }
            catch
            {
                // Fall back to manual creation if factory fails
            }
        }

        // Manual creation with proxy support
        var handler = new HttpClientHandler();
        if (proxy != null)
        {
            handler.Proxy = proxy;
            handler.UseProxy = true;
        }

        return new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(GetTimeoutSeconds())
        };
    }

    /// <summary>
    /// Cleans the API key by removing common prefixes and whitespace.
    /// Uses span-based prefix checking to minimize allocations.
    /// </summary>
    protected virtual string CleanApiKey(string apiKey)
    {
        return StringHelper.CleanApiKey(apiKey);
    }

    /// <summary>
    /// Validates the API key format. Override in derived classes for specific validation.
    /// </summary>
    protected virtual bool IsValidKeyFormat(string apiKey)
    {
        return !string.IsNullOrWhiteSpace(apiKey) && apiKey.Length >= 10;
    }

    /// <summary>
    /// Gets the maximum number of retries. Override in derived classes if needed.
    /// </summary>
    protected virtual int GetMaxRetries() => DEFAULT_MAX_RETRIES;

    /// <summary>
    /// Gets the timeout in seconds. Override in derived classes if needed.
    /// </summary>
    protected virtual int GetTimeoutSeconds() => DEFAULT_TIMEOUT_SECONDS;

    /// <summary>
    /// Common method to check if response body contains any of the specified indicators.
    /// Uses optimized span-based matching for better performance.
    /// </summary>
    protected static bool ContainsAny(string text, HashSet<string> indicators)
    {
        return StringHelper.ContainsAnyOrdinalIgnoreCase(text, indicators);
    }

    /// <summary>
    /// Truncates response text for logging purposes.
    /// Uses string.Create for zero intermediate allocations.
    /// </summary>
    protected static string TruncateResponse(string response, int maxLength = 200)
    {
        return StringHelper.Truncate(response, maxLength);
    }

    /// <summary>
    /// Checks if the status code indicates success.
    /// </summary>
    protected static bool IsSuccessStatusCode(HttpStatusCode statusCode)
    {
        return (int)statusCode >= 200 && (int)statusCode < 300;
    }

    /// <summary>
    /// Common quota/billing indicators across providers.
    /// </summary>
    protected static readonly HashSet<string> QuotaIndicators = new(StringComparer.OrdinalIgnoreCase)
    {
        "credit", "quota", "billing", "insufficient_funds", "payment", "exceeded", "balance", "limit",
        "insufficient_quota", "exceeded_quota", "rate_limit", "rate_limit_exceeded", "RESOURCE_EXHAUSTED"
    };

    /// <summary>
    /// Common unauthorized indicators across providers.
    /// </summary>
    protected static readonly HashSet<string> UnauthorizedIndicators = new(StringComparer.OrdinalIgnoreCase)
    {
        "invalid_api_key", "authentication_error", "unauthorized", "invalid x-api-key", "API_KEY_INVALID",
        "API key not valid", "API key expired", "invalid token", "authentication failed"
    };

    /// <summary>
    /// Common permission indicators across providers.
    /// </summary>
    protected static readonly HashSet<string> PermissionIndicators = new(StringComparer.OrdinalIgnoreCase)
    {
        "permission", "access", "not_authorized_for_model", "forbidden", "read-only", "Pro service"
    };
}
