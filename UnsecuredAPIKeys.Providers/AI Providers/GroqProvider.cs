using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.AI_Providers
{
    /// <summary>
    /// Provider implementation for handling Groq API keys.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.AI_LLM)]
    public class GroqProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Groq";
        public override ApiTypeEnum ApiType => ApiTypeEnum.Groq;

        public override IEnumerable<string> RegexPatterns =>
        [
            @"gsk_[a-zA-Z0-9]{52,56}",
            @"groq_[a-zA-Z0-9]{32,64}"
        ];

        public GroqProvider() : base()
        {
        }

        public GroqProvider(ILogger<GroqProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Use Groq's models endpoint for validation (lightweight check)
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.groq.com/openai/v1/models");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
            
            var response = await httpClient.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("Groq API response: Status={StatusCode}, Body={Body}",
                response.StatusCode, TruncateResponse(responseBody));

            if (IsSuccessStatusCode(response.StatusCode))
            {
                // For Groq, models endpoint success is sufficient validation
                // Completion test would be too expensive for bulk verification
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
            else if (response.StatusCode == HttpStatusCode.PaymentRequired ||
                     ContainsAny(responseBody, QuotaIndicators))
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
            return !string.IsNullOrWhiteSpace(apiKey) && 
                   apiKey.Length >= 20 && 
                   (apiKey.StartsWith("gsk_") || apiKey.StartsWith("groq_"));
        }
    }
}
