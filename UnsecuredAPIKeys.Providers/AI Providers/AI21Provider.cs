using System.Net;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.AI_Providers
{
    /// <summary>
    /// Provider implementation for handling AI21 Labs API keys.
    /// DISABLED: AI21 uses Cloudflare protection that rate-limits by IP (not API key).
    /// All requests return 429 before the API validates the key, causing false positives.
    /// </summary>
    [ApiProvider(
        ScraperUse = false,
        ScraperDisabledReason = "Generic 40-80 char pattern matches too many non-AI21 strings",
        VerificationUse = false,
        VerificationDisabledReason = "Cloudflare IP-based rate limiting blocks validation",
        DisplayInUI = false,
        HiddenFromUIReason = "Cannot reliably scrape or validate AI21 keys",
        Category = ProviderCategory.AI_LLM)]
    public class AI21Provider : BaseApiKeyProvider
    {
        public override string ProviderName => "AI21";
        public override ApiTypeEnum ApiType => ApiTypeEnum.AI21;

        public override IEnumerable<string> RegexPatterns =>
        [
            // AI21 keys have no unique prefix - pattern disabled to prevent false positives
        ];

        public AI21Provider() : base()
        {
        }

        public AI21Provider(ILogger<AI21Provider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // AI21 uses Cloudflare which rate-limits by IP, not by API key
            _logger?.LogInformation("AI21 key validation disabled due to Cloudflare protection.");

            return await Task.FromResult(ValidationResult.Unknown("Cloudflare IP-based rate limiting prevents validation"));
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            // AI21 keys have no unique identifier - cannot reliably validate format
            return false;
        }
    }
}
