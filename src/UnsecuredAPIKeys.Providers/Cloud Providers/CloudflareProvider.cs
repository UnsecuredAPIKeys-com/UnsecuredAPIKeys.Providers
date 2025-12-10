using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.Cloud_Providers
{
    /// <summary>
    /// Provider implementation for handling Cloudflare API tokens.
    /// Cloudflare tokens provide access to DNS, CDN, security, and worker services.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.CloudInfrastructure)]
    public class CloudflareProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Cloudflare";
        public override ApiTypeEnum ApiType => ApiTypeEnum.Cloudflare;

        public override IEnumerable<string> RegexPatterns =>
        [
            // Only scrape tokens with explicit Cloudflare prefix
            // Generic 40-char and 37-hex patterns removed - too many false positives
            @"\bcf_[A-Za-z0-9_-]{37,}\b"
        ];

        public CloudflareProvider() : base()
        {
        }

        public CloudflareProvider(ILogger<CloudflareProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Use Cloudflare's token verification endpoint
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.cloudflare.com/client/v4/user/tokens/verify");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

            var response = await httpClient.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("Cloudflare API response: Status={StatusCode}, Body={Body}",
                response.StatusCode, TruncateResponse(responseBody));

            if (IsSuccessStatusCode(response.StatusCode))
            {
                // Check if the response indicates a valid token
                if (responseBody.Contains("\"status\":\"active\"") || responseBody.Contains("\"success\":true"))
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
                // Rate limited but token is valid (authentication passed)
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

            // Only accept tokens with Cloudflare prefix
            return apiKey.StartsWith("cf_") && apiKey.Length >= 40;
        }
    }
}
