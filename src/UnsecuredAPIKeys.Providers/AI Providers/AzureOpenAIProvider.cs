using System.Net;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.AI_Providers
{
    /// <summary>
    /// Provider implementation for handling Azure OpenAI API keys.
    /// Note: Azure OpenAI requires both a key AND an endpoint URL, so validation is limited.
    /// We can only validate the key format, not actual API access without the endpoint.
    /// </summary>
    [ApiProvider(
        VerificationUse = false,
        VerificationDisabledReason = "Requires endpoint URL (e.g., https://{resource}.openai.azure.com/)",
        DisplayInUI = false,
        HiddenFromUIReason = "Keys cannot be validated without the Azure resource endpoint URL",
        Category = ProviderCategory.AI_LLM)]
    public class AzureOpenAIProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Azure OpenAI";
        public override ApiTypeEnum ApiType => ApiTypeEnum.AzureOpenAI;

        public override IEnumerable<string> RegexPatterns =>
        [
            // Azure OpenAI keys are typically 32-character hex strings
            @"[a-fA-F0-9]{32}"
        ];

        public AzureOpenAIProvider() : base()
        {
        }

        public AzureOpenAIProvider(ILogger<AzureOpenAIProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Azure OpenAI requires an endpoint URL which we don't have from scraping
            _logger?.LogInformation("Azure OpenAI key detected. Cannot validate without endpoint URL.");

            return await Task.FromResult(ValidationResult.Unknown("Cannot validate without Azure resource endpoint URL"));
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            if (string.IsNullOrWhiteSpace(apiKey))
                return false;

            // Azure OpenAI keys are 32-character hexadecimal strings
            if (apiKey.Length != 32)
                return false;

            return apiKey.All(c => c is >= '0' and <= '9' || c is >= 'a' and <= 'f' || c is >= 'A' and <= 'F');
        }
    }
}
