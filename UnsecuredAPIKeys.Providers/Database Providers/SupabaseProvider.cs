using System.Net;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.Database_Providers
{
    /// <summary>
    /// Provider implementation for handling Supabase API keys.
    /// DEPRECATED: Supabase keys are JWTs that require the project URL for validation.
    /// Cannot validate keys without knowing which Supabase project they belong to.
    /// Keys are scraped but not verified.
    /// </summary>
    [ApiProvider(
        ScraperUse = true,
        VerificationUse = false,
        VerificationDisabledReason = "Requires project URL to validate (JWTs are project-specific)",
        DisplayInUI = false,
        HiddenFromUIReason = "Cannot validate keys without knowing the Supabase project URL",
        Category = ProviderCategory.DatabaseBackend)]
    public class SupabaseProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Supabase";
        public override ApiTypeEnum ApiType => ApiTypeEnum.Supabase;

        public override IEnumerable<string> RegexPatterns =>
        [
            // Service role keys with sbp_ prefix (more specific)
            @"\bsbp_[a-f0-9]{40}\b"
            // Removed generic JWT pattern - matches ALL JWTs, not just Supabase
        ];

        public SupabaseProvider() : base()
        {
        }

        public SupabaseProvider(ILogger<SupabaseProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Supabase keys are JWTs - full validation requires knowing the project URL
            _logger?.LogInformation("Supabase key detected. Cannot validate without project URL.");

            return await Task.FromResult(ValidationResult.Unknown("Cannot validate without Supabase project URL"));
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            if (string.IsNullOrWhiteSpace(apiKey))
                return false;

            // Service role key format with prefix
            if (apiKey.StartsWith("sbp_"))
                return apiKey.Length >= 44;

            return false;
        }
    }
}
