using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.Cloud_Providers
{
    /// <summary>
    /// Provider implementation for handling Vercel API tokens.
    /// Vercel tokens provide access to deployments, domains, and serverless functions.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.CloudInfrastructure)]
    public class VercelProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Vercel";
        public override ApiTypeEnum ApiType => ApiTypeEnum.Vercel;

        public override IEnumerable<string> RegexPatterns =>
        [
            // Only scrape tokens with explicit Vercel prefix
            // Generic 24-char patterns removed - too many false positives
            @"\bvercel_[A-Za-z0-9]{20,}\b"
        ];

        public VercelProvider() : base()
        {
        }

        public VercelProvider(ILogger<VercelProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Use Vercel's user endpoint for validation
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.vercel.com/v2/user");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

            var response = await httpClient.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("Vercel API response: Status={StatusCode}, Body={Body}",
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
                // Rate limited but token is valid
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

            // Only accept tokens with Vercel prefix
            return apiKey.StartsWith("vercel_") && apiKey.Length >= 27;
        }
    }
}
