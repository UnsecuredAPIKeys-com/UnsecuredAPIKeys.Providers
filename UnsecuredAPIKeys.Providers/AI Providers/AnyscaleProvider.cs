using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.AI_Providers
{
    /// <summary>
    /// Provider implementation for handling Anyscale API keys.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.AI_LLM)]
    public class AnyscaleProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Anyscale";
        public override ApiTypeEnum ApiType => ApiTypeEnum.Anyscale;

        public override IEnumerable<string> RegexPatterns =>
        [
            @"esecret_[a-zA-Z0-9]{20,80}",
            @"anyscale[_-]?[a-zA-Z0-9]{20,80}"
        ];

        public AnyscaleProvider() : base()
        {
        }

        public AnyscaleProvider(ILogger<AnyscaleProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Anyscale uses OpenAI-compatible API
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.endpoints.anyscale.com/v1/models");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

            var response = await httpClient.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("Anyscale API response: Status={StatusCode}, Body={Body}",
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
                   apiKey.StartsWith("esecret_");
        }
    }
}
