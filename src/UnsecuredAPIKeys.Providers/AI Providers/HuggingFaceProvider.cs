using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.AI_Providers
{
    /// <summary>
    /// Provider implementation for handling Hugging Face API tokens.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.AI_LLM)]
    public class HuggingFaceProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Hugging Face";
        public override ApiTypeEnum ApiType => ApiTypeEnum.HuggingFace;

        // Regex patterns specific to Hugging Face tokens
        public override IEnumerable<string> RegexPatterns =>
        [
            @"hf_[a-zA-Z0-9]{34,}"  // Hugging Face API tokens start with "hf_"
        ];

        public HuggingFaceProvider() : base()
        {
        }

        public HuggingFaceProvider(ILogger<HuggingFaceProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // First, try a lightweight whoami-v2 endpoint (whoami is deprecated)
            using var whoamiRequest = new HttpRequestMessage(HttpMethod.Get, "https://huggingface.co/api/whoami-v2");
            whoamiRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
            
            var whoamiResponse = await httpClient.SendAsync(whoamiRequest);

            _logger?.LogDebug("HuggingFace whoami response: Status={StatusCode}", whoamiResponse.StatusCode);

            if (IsSuccessStatusCode(whoamiResponse.StatusCode))
            {
                // For efficiency, just validate authentication - skip inference test for bulk verification
                // Inference API validation would be too expensive and slow for large-scale validation
                return ValidationResult.Success(whoamiResponse.StatusCode);
            }
            else if (whoamiResponse.StatusCode == HttpStatusCode.Unauthorized)
            {
                return ValidationResult.IsUnauthorized(whoamiResponse.StatusCode);
            }
            else if ((int)whoamiResponse.StatusCode == 429)
            {
                // Rate limited means the key is valid
                return ValidationResult.Success(whoamiResponse.StatusCode);
            }
            else
            {
                string responseBody = await whoamiResponse.Content.ReadAsStringAsync();
                
                // Check for quota/permission issues that still indicate valid keys
                if (ContainsAny(responseBody, QuotaIndicators) || ContainsAny(responseBody, PermissionIndicators))
                {
                    return ValidationResult.Success(whoamiResponse.StatusCode);
                }
                
                return ValidationResult.HasHttpError(whoamiResponse.StatusCode, 
                    $"API request (whoami) failed with status {whoamiResponse.StatusCode}. Response: {TruncateResponse(responseBody)}");
            }
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            return !string.IsNullOrWhiteSpace(apiKey) && 
                   apiKey.StartsWith("hf_") && 
                   apiKey.Length >= 37; // hf_ + at least 34 chars
        }
    }
}
