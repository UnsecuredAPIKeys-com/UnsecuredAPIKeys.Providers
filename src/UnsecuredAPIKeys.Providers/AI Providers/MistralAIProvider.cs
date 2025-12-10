using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.AI_Providers
{
    /// <summary>
    /// Provider implementation for handling Mistral AI API keys.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.AI_LLM)]
    public class MistralAIProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Mistral AI";
        public override ApiTypeEnum ApiType => ApiTypeEnum.MistralAI;

        // Regex patterns specific to Mistral AI keys
        public override IEnumerable<string> RegexPatterns =>
        [
            @"mis_[a-zA-Z0-9]{32,}"  // Mistral AI keys start with "mis_"
        ];

        public MistralAIProvider() : base()
        {
        }

        public MistralAIProvider(ILogger<MistralAIProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Use ONLY the lightweight models endpoint for validation
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.mistral.ai/v1/models");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            
            var response = await httpClient.SendAsync(request);
            var responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("Mistral AI models API response: Status={StatusCode}, Body={Body}",
                response.StatusCode, TruncateResponse(responseBody));

            if (IsSuccessStatusCode(response.StatusCode))
            {
                // Models list success is sufficient validation - no need for expensive completion generation
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
                    responseBody.Contains("insufficient_quota", StringComparison.OrdinalIgnoreCase) ||
                    responseBody.Contains("billing_required", StringComparison.OrdinalIgnoreCase))
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
                   apiKey.StartsWith("mis_") && 
                   apiKey.Length >= 36; // mis_ + at least 32 chars
        }
    }
}
