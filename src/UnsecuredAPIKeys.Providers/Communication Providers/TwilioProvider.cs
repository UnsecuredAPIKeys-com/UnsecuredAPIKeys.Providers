using System.Net;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.Communication_Providers
{
    /// <summary>
    /// Provider implementation for handling Twilio API keys.
    /// DEPRECATED: Twilio requires Account SID + Auth Token pair for authentication.
    /// Cannot validate individual credentials without the paired component.
    /// Account SIDs, Auth Tokens, and API Key SIDs are scraped but not verified.
    /// </summary>
    [ApiProvider(
        ScraperUse = true,
        VerificationUse = false,
        VerificationDisabledReason = "Requires Account SID + Auth Token pair for authentication",
        DisplayInUI = false,
        HiddenFromUIReason = "Cannot validate individual credentials without paired Account SID/Auth Token",
        Category = ProviderCategory.Communication)]
    public class TwilioProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Twilio";
        public override ApiTypeEnum ApiType => ApiTypeEnum.Twilio;

        public override IEnumerable<string> RegexPatterns =>
        [
            // Twilio Account SID (starts with AC)
            @"\bAC[a-f0-9]{32}\b",
            // API Key SID (starts with SK)
            @"\bSK[a-f0-9]{32}\b"
            // Removed generic 32-char hex pattern - too many false positives
        ];

        public TwilioProvider() : base()
        {
        }

        public TwilioProvider(ILogger<TwilioProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Twilio requires Account SID + Auth Token for Basic auth
            _logger?.LogInformation("Twilio credential detected. Cannot validate without paired credential.");

            return await Task.FromResult(ValidationResult.Unknown("Cannot validate without paired Account SID/Auth Token"));
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            if (string.IsNullOrWhiteSpace(apiKey))
                return false;

            // Account SID: AC + 32 hex chars
            if (apiKey.StartsWith("AC") && apiKey.Length == 34)
                return apiKey.Substring(2).All(c => char.IsAsciiHexDigit(c));

            // API Key SID: SK + 32 hex chars
            if (apiKey.StartsWith("SK") && apiKey.Length == 34)
                return apiKey.Substring(2).All(c => char.IsAsciiHexDigit(c));

            return false;
        }
    }
}
