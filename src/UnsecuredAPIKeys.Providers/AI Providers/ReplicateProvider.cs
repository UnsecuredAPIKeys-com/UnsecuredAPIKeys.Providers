using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.AI_Providers
{
    /// <summary>
    /// Provider implementation for handling Replicate API tokens.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.AI_LLM)]
    public class ReplicateProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Replicate";
        public override ApiTypeEnum ApiType => ApiTypeEnum.Replicate;

        // Regex patterns specific to Replicate tokens
        public override IEnumerable<string> RegexPatterns =>
        [
            @"r8_[a-zA-Z0-9]{24,}"  // Replicate API tokens start with "r8_"
        ];

        public ReplicateProvider() : base()
        {
        }

        public ReplicateProvider(ILogger<ReplicateProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Use Replicate's account endpoint for lightweight authentication check
            using var accountRequest = new HttpRequestMessage(HttpMethod.Get, "https://api.replicate.com/v1/account");
            accountRequest.Headers.Authorization = new AuthenticationHeaderValue("Token", apiKey); // Replicate uses "Token" prefix
            
            var accountResponse = await httpClient.SendAsync(accountRequest);
            string responseBody = await accountResponse.Content.ReadAsStringAsync();

            _logger?.LogDebug("Replicate account API response: Status={StatusCode}, Body={Body}",
                accountResponse.StatusCode, TruncateResponse(responseBody));

            if (IsSuccessStatusCode(accountResponse.StatusCode))
            {
                // For efficiency, just validate account access - skip prediction test for bulk verification
                // Creating predictions would be too expensive for large-scale validation
                return ValidationResult.Success(accountResponse.StatusCode);
            }
            else if (accountResponse.StatusCode == HttpStatusCode.Unauthorized)
            {
                return ValidationResult.IsUnauthorized(accountResponse.StatusCode);
            }
            else if ((int)accountResponse.StatusCode == 429)
            {
                // Rate limited means the key is valid
                return ValidationResult.Success(accountResponse.StatusCode);
            }
            else
            {
                // Check for quota/billing/permission issues
                if (ContainsAny(responseBody, QuotaIndicators) || ContainsAny(responseBody, PermissionIndicators))
                {
                    return ValidationResult.Success(accountResponse.StatusCode);
                }
                
                return ValidationResult.HasHttpError(accountResponse.StatusCode, 
                    $"API request failed with status {accountResponse.StatusCode}. Response: {TruncateResponse(responseBody)}");
            }
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            return !string.IsNullOrWhiteSpace(apiKey) && 
                   apiKey.StartsWith("r8_") && 
                   apiKey.Length >= 27; // r8_ + at least 24 chars
        }
    }
}
