using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.AI_Providers
{
    /// <summary>
    /// Provider implementation for handling xAI (Grok) API keys.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.AI_LLM)]
    public class XAIProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "xAI";
        public override ApiTypeEnum ApiType => ApiTypeEnum.XAI;

        public override IEnumerable<string> RegexPatterns =>
        [
            @"xai-[a-zA-Z0-9]{20,80}",
            @"grok-[a-zA-Z0-9]{20,80}"
        ];

        public XAIProvider() : base()
        {
        }

        public XAIProvider(ILogger<XAIProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // xAI uses OpenAI-compatible API
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.x.ai/v1/models");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

            var response = await httpClient.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("xAI API response: Status={StatusCode}, Body={Body}",
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
                   (apiKey.StartsWith("xai-") || apiKey.StartsWith("grok-"));
        }
    }
}
