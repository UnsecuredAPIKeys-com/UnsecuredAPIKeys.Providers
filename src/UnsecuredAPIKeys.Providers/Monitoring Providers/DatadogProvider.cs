using System.Net;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.Monitoring_Providers
{
    /// <summary>
    /// Provider implementation for handling Datadog API keys.
    /// DEPRECATED: Datadog keys are generic 32/40 hex characters with no unique prefix.
    /// These patterns match many other key types (SHA hashes, other hex tokens).
    /// Too many false positives to reliably validate.
    /// </summary>
    [ApiProvider(scraperUse: false, verificationUse: false, DisplayInUI = false, Category = ProviderCategory.Monitoring)]
    public class DatadogProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Datadog";
        public override ApiTypeEnum ApiType => ApiTypeEnum.Datadog;

        public override IEnumerable<string> RegexPatterns =>
        [
            // Datadog API keys (32 hex characters)
            @"\b[a-f0-9]{32}\b",
            // Application keys (40 hex characters)
            @"\b[a-f0-9]{40}\b"
        ];

        public DatadogProvider() : base()
        {
        }

        public DatadogProvider(ILogger<DatadogProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Use Datadog's validate endpoint
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.datadoghq.com/api/v1/validate");
            request.Headers.Add("DD-API-KEY", apiKey);

            var response = await httpClient.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("Datadog API response: Status={StatusCode}, Body={Body}",
                response.StatusCode, TruncateResponse(responseBody));

            if (IsSuccessStatusCode(response.StatusCode))
            {
                if (responseBody.Contains("\"valid\":true") || responseBody.Contains("\"valid\": true"))
                {
                    return ValidationResult.Success(response.StatusCode);
                }
                return ValidationResult.Success(response.StatusCode);
            }
            else if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                return ValidationResult.IsUnauthorized(response.StatusCode);
            }
            else if ((int)response.StatusCode == 429)
            {
                return ValidationResult.Success(response.StatusCode);
            }
            else
            {
                return ValidationResult.HasHttpError(response.StatusCode,
                    $"API request failed with status {response.StatusCode}. Response: {TruncateResponse(responseBody)}");
            }
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            if (string.IsNullOrWhiteSpace(apiKey))
                return false;

            // Datadog API keys are 32 hex characters
            // Application keys are 40 hex characters
            return apiKey.Length is 32 or 40 &&
                   apiKey.All(c => char.IsAsciiHexDigitLower(c));
        }
    }
}
