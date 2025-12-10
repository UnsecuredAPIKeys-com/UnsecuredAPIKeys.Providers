using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.Cloud_Providers
{
    /// <summary>
    /// Provider implementation for handling DigitalOcean API tokens.
    /// DigitalOcean tokens provide access to cloud infrastructure including droplets, databases, and storage.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.CloudInfrastructure)]
    public class DigitalOceanProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "DigitalOcean";
        public override ApiTypeEnum ApiType => ApiTypeEnum.DigitalOcean;

        public override IEnumerable<string> RegexPatterns =>
        [
            // Personal access tokens (v1) - modern format with prefix
            @"\bdop_v1_[a-f0-9]{64}\b",
            // OAuth tokens - modern format with prefix
            @"\bdoo_v1_[a-f0-9]{64}\b",
            // Legacy 64-char hex tokens removed - too generic (matches SHA-256 hashes, etc.)
            // Only scrape tokens with explicit DigitalOcean prefixes
        ];

        public DigitalOceanProvider() : base()
        {
        }

        public DigitalOceanProvider(ILogger<DigitalOceanProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Use DigitalOcean's account endpoint for validation (lightweight check)
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.digitalocean.com/v2/account");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

            var response = await httpClient.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("DigitalOcean API response: Status={StatusCode}, Body={Body}",
                response.StatusCode, TruncateResponse(responseBody));

            if (IsSuccessStatusCode(response.StatusCode))
            {
                return ValidationResult.Success(response.StatusCode);
            }
            else if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                return ValidationResult.IsUnauthorized(response.StatusCode);
            }
            else if ((int)response.StatusCode == 429)
            {
                // Rate limited but key is valid
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

            // Only accept tokens with DigitalOcean prefixes
            // Legacy 64-char hex tokens are too generic and match SHA-256 hashes, other keys, etc.
            if (apiKey.StartsWith("dop_v1_") || apiKey.StartsWith("doo_v1_"))
            {
                // prefix (7) + 64 hex chars = 71 total
                if (apiKey.Length < 71)
                    return false;

                // Verify the hex portion after prefix
                string hexPart = apiKey.Substring(7);
                return hexPart.Length == 64 && hexPart.All(c => char.IsAsciiHexDigit(c));
            }

            return false;
        }
    }
}
