using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.Communication_Providers
{
    /// <summary>
    /// Provider implementation for handling Slack API tokens.
    /// Slack tokens provide access to workspaces, channels, messages, and integrations.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.Communication)]
    public class SlackProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Slack";
        public override ApiTypeEnum ApiType => ApiTypeEnum.Slack;

        public override IEnumerable<string> RegexPatterns =>
        [
            // Bot tokens
            @"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b",
            // User tokens
            @"\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b",
            // App-level tokens
            @"\bxoxa-[0-9]+-[a-zA-Z0-9]+\b",
            // Workspace tokens (legacy)
            @"\bxoxs-[0-9]+-[0-9]+-[a-zA-Z0-9]+\b",
            // Generic pattern for slack tokens
            @"\bxox[abps]-[0-9A-Za-z-]+\b"
        ];

        public SlackProvider() : base()
        {
        }

        public SlackProvider(ILogger<SlackProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Use Slack's auth.test endpoint for validation
            using var request = new HttpRequestMessage(HttpMethod.Post, "https://slack.com/api/auth.test");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

            var response = await httpClient.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("Slack API response: Status={StatusCode}, Body={Body}",
                response.StatusCode, TruncateResponse(responseBody));

            // Slack always returns 200, check the response body for success
            if (IsSuccessStatusCode(response.StatusCode))
            {
                if (responseBody.Contains("\"ok\":true") || responseBody.Contains("\"ok\": true"))
                {
                    return ValidationResult.Success(response.StatusCode);
                }
                else if (responseBody.Contains("invalid_auth") || responseBody.Contains("token_revoked"))
                {
                    return ValidationResult.IsUnauthorized(response.StatusCode, "Invalid or revoked Slack token");
                }
                else if (responseBody.Contains("\"ok\":false") || responseBody.Contains("\"ok\": false"))
                {
                    return ValidationResult.IsUnauthorized(response.StatusCode,
                        $"Slack API returned error: {TruncateResponse(responseBody)}");
                }
            }

            if ((int)response.StatusCode == 429)
            {
                // Rate limited but token format is valid
                return ValidationResult.Success(response.StatusCode);
            }

            return ValidationResult.HasHttpError(response.StatusCode,
                $"API request failed with status {response.StatusCode}. Response: {TruncateResponse(responseBody)}");
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            if (string.IsNullOrWhiteSpace(apiKey))
                return false;

            // All Slack tokens start with xox followed by a type character
            return apiKey.StartsWith("xoxb-") ||
                   apiKey.StartsWith("xoxp-") ||
                   apiKey.StartsWith("xoxa-") ||
                   apiKey.StartsWith("xoxs-");
        }
    }
}
