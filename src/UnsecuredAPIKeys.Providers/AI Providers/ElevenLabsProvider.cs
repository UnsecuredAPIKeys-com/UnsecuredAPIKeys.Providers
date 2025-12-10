using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.AI_Providers
{
    /// <summary>
    /// Provider implementation for handling ElevenLabs API keys.
    /// </summary>
    [ApiProvider(scraperUse: true, verificationUse: false, Category = ProviderCategory.AI_LLM)]
    public class ElevenLabsProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "ElevenLabs";
        public override ApiTypeEnum ApiType => ApiTypeEnum.ElevenLabs;

        public override IEnumerable<string> RegexPatterns =>
        [
            // More specific patterns to reduce false positives
            @"sk_[a-f0-9]{32}",
            @"xi-api-key:[a-f0-9]{32}",
            @"\b[a-f0-9]{32}\b"  // Only match 32-char hex with word boundaries
        ];

        public ElevenLabsProvider() : base()
        {
        }

        public ElevenLabsProvider(ILogger<ElevenLabsProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Clean xi-api-key prefix if present
            if (apiKey.StartsWith("xi-api-key:", StringComparison.OrdinalIgnoreCase))
            {
                apiKey = apiKey.Substring(11).Trim();
            }

            // Use ElevenLabs user endpoint for validation
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.elevenlabs.io/v1/user");
            request.Headers.Add("xi-api-key", apiKey);
            
            var response = await httpClient.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("ElevenLabs API response: Status={StatusCode}, Body={Body}",
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
                return ValidationResult.Success(response.StatusCode);
            }
            else if (ContainsAny(responseBody, QuotaIndicators))
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
            // Clean prefix if present
            if (apiKey.StartsWith("xi-api-key:", StringComparison.OrdinalIgnoreCase))
            {
                apiKey = apiKey.Substring(11).Trim();
            }
            else if (apiKey.StartsWith("sk_"))
            {
                return apiKey.Length == 35; // sk_ + 32 hex chars
            }

            // Must be exactly 32 hex characters
            return apiKey.Length == 32 && 
                   apiKey.All(c => char.IsDigit(c) || c is >= 'a' and <= 'f' || c is >= 'A' and <= 'F');
        }
    }
}
