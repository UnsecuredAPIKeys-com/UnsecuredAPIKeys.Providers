using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.AI_Providers
{
    /// <summary>
    /// Provider implementation for handling Cohere API keys.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.AI_LLM)]
    public class CohereProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Cohere";
        public override ApiTypeEnum ApiType => ApiTypeEnum.Cohere;

        // Regex patterns specific to Cohere keys
        public override IEnumerable<string> RegexPatterns =>
        [
            @"co-[a-zA-Z0-9]{32}",   // Newer format Cohere keys (preferred)
            @"\bco[a-zA-Z0-9]{38}\b" // Legacy format with word boundaries to reduce false positives
        ];

        public CohereProvider() : base()
        {
        }

        public CohereProvider(ILogger<CohereProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Use Cohere's models endpoint for lightweight validation
            using var modelRequest = new HttpRequestMessage(HttpMethod.Get, "https://api.cohere.ai/v1/models");
            modelRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
            modelRequest.Headers.Add("Accept", "application/json");

            var modelResponse = await httpClient.SendAsync(modelRequest);
            string responseBody = await modelResponse.Content.ReadAsStringAsync();

            _logger?.LogDebug("Cohere models API response: Status={StatusCode}, Body={Body}",
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
                // Check for quota/billing/permission issues specific to Cohere
                if (ContainsAny(responseBody, QuotaIndicators) || ContainsAny(responseBody, PermissionIndicators) ||
                    responseBody.Contains("blocklist") || responseBody.Contains("finetuning_access_only"))
                {
                    return ValidationResult.Success(modelResponse.StatusCode);
                }
                
                return ValidationResult.HasHttpError(modelResponse.StatusCode, 
                    $"API request failed with status {modelResponse.StatusCode}. Response: {TruncateResponse(responseBody)}");
            }
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            // Prefer the newer co- format, but allow the older 40-char format
            return !string.IsNullOrWhiteSpace(apiKey) && 
                   (apiKey.StartsWith("co-") && apiKey.Length >= 35 || // co- + 32 chars
                    apiKey.Length == 40 && apiKey.All(char.IsLetterOrDigit)); // 40 alphanumeric chars
        }
    }
}
