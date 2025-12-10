using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.AI_Providers
{
    /// <summary>
    /// Provider implementation for handling Stability AI API keys.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.AI_LLM)]
    public class StabilityAIProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Stability AI";
        public override ApiTypeEnum ApiType => ApiTypeEnum.StabilityAI;

        // Regex patterns specific to Stability AI keys
        public override IEnumerable<string> RegexPatterns =>
        [
            @"sk-[a-zA-Z0-9]{48}"  // Stability AI keys (similar format to OpenAI)
        ];

        public StabilityAIProvider() : base()
        {
        }

        public StabilityAIProvider(ILogger<StabilityAIProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Use ONLY the lightweight engines endpoint for validation
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.stability.ai/v1/engines/list");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            
            var response = await httpClient.SendAsync(request);
            var responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("Stability AI engines API response: Status={StatusCode}, Body={Body}",
                response.StatusCode, TruncateResponse(responseBody));

            if (IsSuccessStatusCode(response.StatusCode))
            {
                // Engines list success is sufficient validation - no need for expensive image generation
                return ValidationResult.Success(response.StatusCode);
            }
            else if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                return ValidationResult.IsUnauthorized(response.StatusCode);
            }
            else if ((int)response.StatusCode == 429)
            {
                // Rate limited means the key is valid
                return ValidationResult.Success(response.StatusCode);
            }
            else if (response.StatusCode == HttpStatusCode.PaymentRequired)
            {
                // Payment required means valid key but no credits
                return ValidationResult.Success(response.StatusCode);
            }
            else
            {
                // Check for quota/billing/permission issues
                if (ContainsAny(responseBody, QuotaIndicators) || 
                    ContainsAny(responseBody, PermissionIndicators) ||
                    responseBody.Contains("insufficient_credit", StringComparison.OrdinalIgnoreCase))
                {
                    return ValidationResult.Success(response.StatusCode);
                }
                
                return ValidationResult.HasHttpError(response.StatusCode, 
                    $"API request failed with status {response.StatusCode}. Response: {TruncateResponse(responseBody)}");
            }
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            return !string.IsNullOrWhiteSpace(apiKey) && 
                   apiKey.StartsWith("sk-") && 
                   apiKey.Length >= 51; // sk- + 48 chars
        }
    }
}
