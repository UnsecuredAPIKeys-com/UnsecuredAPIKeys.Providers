using System.Net;
using System.Text;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.Communication_Providers
{
    /// <summary>
    /// Provider implementation for handling Mailgun API keys.
    /// Mailgun keys provide access to email sending, routing, and analytics.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.Communication)]
    public class MailgunProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Mailgun";
        public override ApiTypeEnum ApiType => ApiTypeEnum.Mailgun;

        public override IEnumerable<string> RegexPatterns =>
        [
            // Mailgun API keys (start with key-)
            @"\bkey-[a-f0-9]{32}\b",
            // Public validation keys (start with pubkey-)
            @"\bpubkey-[a-f0-9]{32}\b",
            // Newer format keys
            @"\b[a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8}\b"
        ];

        public MailgunProvider() : base()
        {
        }

        public MailgunProvider(ILogger<MailgunProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Use Mailgun's domains endpoint with Basic auth
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.mailgun.net/v3/domains");

            // Mailgun uses Basic auth with "api" as username and the API key as password
            var authBytes = Encoding.ASCII.GetBytes($"api:{apiKey}");
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
                "Basic", Convert.ToBase64String(authBytes));

            var response = await httpClient.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("Mailgun API response: Status={StatusCode}, Body={Body}",
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

            // API keys start with "key-" followed by 32 hex characters
            if (apiKey.StartsWith("key-") && apiKey.Length == 36)
                return true;

            // Public keys start with "pubkey-"
            if (apiKey.StartsWith("pubkey-") && apiKey.Length == 39)
                return true;

            return false;
        }
    }
}
