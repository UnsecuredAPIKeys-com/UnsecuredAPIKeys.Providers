using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.AI_Providers
{
    /// <summary>
    /// Provider implementation for handling OpenRouter API keys.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.AI_LLM)]
    public class OpenRouterProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "OpenRouter";
        public override ApiTypeEnum ApiType => ApiTypeEnum.OpenRouter;

        public override IEnumerable<string> RegexPatterns =>
        [
            @"sk-or-[a-zA-Z0-9]{24,48}",
            @"sk-or-v1-[a-zA-Z0-9]{48,64}"
        ];

        private class OpenRouterCreditsResponse
        {
            public OpenRouterCreditsData Data { get; set; } = null!;
        }

        private class OpenRouterCreditsData
        {
            public decimal Total_Credits { get; set; }
            public decimal Total_Usage { get; set; }
        }

        public OpenRouterProvider() : base()
        {
        }

        public OpenRouterProvider(ILogger<OpenRouterProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Use ONLY the lightweight credits endpoint for validation
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://openrouter.ai/api/v1/credits");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
            request.Headers.Referrer = new Uri("https://unsecuredapikeys.com");
            
            var response = await httpClient.SendAsync(request);
            var responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("OpenRouter credits API response: Status={StatusCode}, Body={Body}",
                response.StatusCode, TruncateResponse(responseBody));

            if (IsSuccessStatusCode(response.StatusCode))
            {
                try
                {
                    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    var creditsData = JsonSerializer.Deserialize<OpenRouterCreditsResponse>(responseBody, options);

                    if (creditsData?.Data != null)
                    {
                        // Calculate remaining balance
                        var remainingCredits = creditsData.Data.Total_Credits - creditsData.Data.Total_Usage;
                        var hasCredits = remainingCredits > 0;

                        _logger?.LogInformation("OpenRouter key has {Balance:F4} credits remaining (total: {Total:F4}, used: {Used:F4})",
                            remainingCredits, creditsData.Data.Total_Credits, creditsData.Data.Total_Usage);

                        return ValidationResult.Success(response.StatusCode, hasCredits: hasCredits, creditBalance: remainingCredits);
                    }

                    // If we can parse but no data, still valid but unknown credits
                    return ValidationResult.Success(response.StatusCode);
                }
                catch (JsonException ex)
                {
                    _logger?.LogWarning(ex, "Failed to parse OpenRouter credits response, but HTTP status was success");
                    // If response is successful but unparseable, still consider key valid
                    return ValidationResult.Success(response.StatusCode);
                }
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
            else
            {
                // Check for quota/billing/permission issues
                if (ContainsAny(responseBody, QuotaIndicators) || 
                    ContainsAny(responseBody, PermissionIndicators) ||
                    responseBody.Contains("rate_limit_exceeded", StringComparison.OrdinalIgnoreCase) ||
                    responseBody.Contains("moderation", StringComparison.OrdinalIgnoreCase))
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
                   apiKey.StartsWith("sk-or-") && 
                   apiKey.Length >= 30; // sk-or- + at least 24 chars
        }
    }
}
