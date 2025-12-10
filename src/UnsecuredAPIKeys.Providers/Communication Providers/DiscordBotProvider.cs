using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.Communication_Providers
{
    /// <summary>
    /// Provider implementation for handling Discord Bot tokens.
    /// Discord bot tokens provide access to Discord servers, channels, and user data.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.Communication)]
    public class DiscordBotProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Discord Bot";
        public override ApiTypeEnum ApiType => ApiTypeEnum.DiscordBot;

        public override IEnumerable<string> RegexPatterns =>
        [
            // Discord bot tokens are base64 encoded and typically have this structure:
            // [Bot ID base64].[Timestamp base64].[HMAC base64]
            @"\b[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b",
            // Alternative pattern for newer tokens
            @"\b[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}\b"
        ];

        public DiscordBotProvider() : base()
        {
        }

        public DiscordBotProvider(ILogger<DiscordBotProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Use Discord's users/@me endpoint for validation
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://discord.com/api/v10/users/@me");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bot", apiKey);

            var response = await httpClient.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("Discord API response: Status={StatusCode}, Body={Body}",
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
                // Rate limited but token is valid
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

            // Discord tokens have a specific structure with dots separating parts
            var parts = apiKey.Split('.');
            if (parts.Length != 3)
                return false;

            // First part should be base64 of bot ID (starts with M or N for newer bots)
            // Total length is typically 59-72 characters
            return apiKey.Length is >= 50 and <= 80;
        }
    }
}
