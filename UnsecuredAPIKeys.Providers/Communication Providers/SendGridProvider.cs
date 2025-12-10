using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.Communication_Providers
{
    /// <summary>
    /// Provider implementation for handling SendGrid API keys.
    /// SendGrid keys provide access to email sending, templates, and analytics.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.Communication)]
    public class SendGridProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "SendGrid";
        public override ApiTypeEnum ApiType => ApiTypeEnum.SendGrid;

        public override IEnumerable<string> RegexPatterns =>
        [
            // SendGrid API keys start with SG. followed by base64-like characters
            @"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b",
            // Alternative shorter format
            @"\bSG\.[a-zA-Z0-9_-]{20,}\b"
        ];

        public SendGridProvider() : base()
        {
        }

        public SendGridProvider(ILogger<SendGridProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Use SendGrid's user profile endpoint for validation
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.sendgrid.com/v3/user/profile");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

            var response = await httpClient.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("SendGrid API response: Status={StatusCode}, Body={Body}",
                response.StatusCode, TruncateResponse(responseBody));

            if (IsSuccessStatusCode(response.StatusCode))
            {
                return ValidationResult.Success(response.StatusCode);
            }
            else if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                return ValidationResult.IsUnauthorized(response.StatusCode);
            }
            else if ((int)response.StatusCode == 429)
            {
                // Rate limited but key is valid
                return ValidationResult.Success(response.StatusCode);
            }
            else if (ContainsAny(responseBody, QuotaIndicators))
            {
                return ValidationResult.ValidNoCredits(response.StatusCode, "SendGrid account may have exceeded quota");
            }
            else
            {
                return ValidationResult.HasHttpError(response.StatusCode,
                    $"API request failed with status {response.StatusCode}. Response: {TruncateResponse(responseBody)}");
            }
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            if (string.IsNullOrWhiteSpace(apiKey))
                return false;

            // SendGrid keys start with "SG." and are typically 69 characters total
            return apiKey.StartsWith("SG.") && apiKey.Length >= 50;
        }
    }
}
