using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.AI_Providers
{
    /// <summary>
    /// Provider implementation for handling Perplexity AI API keys.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.AI_LLM)]
    public class PerplexityAIProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Perplexity AI";
        public override ApiTypeEnum ApiType => ApiTypeEnum.PerplexityAI;

        public override IEnumerable<string> RegexPatterns =>
        [
            @"pplx-[a-zA-Z0-9]{48,56}",
            @"pplx-[a-f0-9]{48}"
        ];

        public PerplexityAIProvider() : base()
        {
        }

        public PerplexityAIProvider(ILogger<PerplexityAIProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Use Perplexity's models endpoint for validation
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.perplexity.ai/models");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
            
            var response = await httpClient.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("Perplexity API response: Status={StatusCode}, Body={Body}",
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
                // Rate limited means the key is valid
                return ValidationResult.Success(response.StatusCode);
            }
            else if (response.StatusCode == HttpStatusCode.PaymentRequired ||
                     ContainsAny(responseBody, QuotaIndicators))
            {
                // Key is valid but has no credits
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
                   apiKey.StartsWith("pplx-");
        }
    }
}
