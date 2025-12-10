using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.AI_Providers
{
    /// <summary>
    /// Provider implementation for handling Together AI API tokens.
    /// </summary>
    [ApiProvider(scraperUse: true, verificationUse: false, Category = ProviderCategory.AI_LLM)]
    public class TogetherAIProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Together AI";
        public override ApiTypeEnum ApiType => ApiTypeEnum.TogetherAI;

        // Regex patterns specific to Together AI tokens
        public override IEnumerable<string> RegexPatterns =>
        [
            @"tok_[a-zA-Z0-9]{32,}"  // Together AI tokens start with "tok_"
        ];

        public TogetherAIProvider() : base()
        {
        }

        public TogetherAIProvider(ILogger<TogetherAIProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Use Together AI's models endpoint for lightweight validation
            using var modelRequest = new HttpRequestMessage(HttpMethod.Get, "https://api.together.xyz/models");
            modelRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
            
            var modelResponse = await httpClient.SendAsync(modelRequest);
            string responseBody = await modelResponse.Content.ReadAsStringAsync();

            _logger?.LogDebug("TogetherAI models API response: Status={StatusCode}, Body={Body}",
                modelResponse.StatusCode, TruncateResponse(responseBody));

            if (IsSuccessStatusCode(modelResponse.StatusCode))
            {
                // For efficiency, just validate model listing - skip completion test for bulk verification
                return ValidationResult.Success(modelResponse.StatusCode);
            }
            else if (modelResponse.StatusCode == HttpStatusCode.Unauthorized)
            {
                return ValidationResult.IsUnauthorized(modelResponse.StatusCode);
            }
            else if ((int)modelResponse.StatusCode == 429)
            {
                // Rate limited means the key is valid
                return ValidationResult.Success(modelResponse.StatusCode);
            }
            else
            {
                // Check for quota/billing/permission issues
                if (ContainsAny(responseBody, QuotaIndicators) || ContainsAny(responseBody, PermissionIndicators))
                {
                    return ValidationResult.Success(modelResponse.StatusCode);
                }
                
                return ValidationResult.HasHttpError(modelResponse.StatusCode, 
                    $"API request failed with status {modelResponse.StatusCode}. Response: {TruncateResponse(responseBody)}");
            }
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            return !string.IsNullOrWhiteSpace(apiKey) && 
                   apiKey.StartsWith("tok_") && 
                   apiKey.Length >= 36; // tok_ + at least 32 chars
        }
    }
}
