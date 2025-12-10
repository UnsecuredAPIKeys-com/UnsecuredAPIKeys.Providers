using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.Database_Providers
{
    /// <summary>
    /// Provider implementation for handling PlanetScale API tokens.
    /// PlanetScale tokens provide access to serverless MySQL databases.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.DatabaseBackend)]
    public class PlanetScaleProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "PlanetScale";
        public override ApiTypeEnum ApiType => ApiTypeEnum.PlanetScale;

        public override IEnumerable<string> RegexPatterns =>
        [
            // PlanetScale service tokens
            @"\bpscale_tkn_[a-zA-Z0-9_]{30,}\b",
            // PlanetScale OAuth tokens
            @"\bpscale_oauth_[a-zA-Z0-9_]{30,}\b",
            // Database connection passwords
            @"\bpscale_pw_[a-zA-Z0-9_]{30,}\b"
        ];

        public PlanetScaleProvider() : base()
        {
        }

        public PlanetScaleProvider(ILogger<PlanetScaleProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Use PlanetScale's organizations endpoint for validation
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.planetscale.com/v1/organizations");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

            var response = await httpClient.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("PlanetScale API response: Status={StatusCode}, Body={Body}",
                response.StatusCode, TruncateResponse(responseBody));

            if (IsSuccessStatusCode(response.StatusCode))
            {
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

            // PlanetScale tokens start with pscale_ prefix
            return apiKey.StartsWith("pscale_tkn_") ||
                   apiKey.StartsWith("pscale_oauth_") ||
                   apiKey.StartsWith("pscale_pw_");
        }
    }
}
