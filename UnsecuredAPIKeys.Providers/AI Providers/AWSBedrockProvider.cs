using System.Net;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.AI_Providers
{
    /// <summary>
    /// Provider implementation for handling AWS Bedrock credentials.
    /// Note: AWS Bedrock uses AWS access keys (AKIA...) which require both
    /// Access Key ID and Secret Access Key. We can detect the pattern but
    /// full validation requires the secret key pair.
    /// </summary>
    [ApiProvider(
        VerificationUse = false,
        VerificationDisabledReason = "Requires Access Key ID + Secret Key + Region + SigV4 signing",
        DisplayInUI = false,
        HiddenFromUIReason = "Keys cannot be validated without paired credentials and region info",
        Category = ProviderCategory.AI_LLM)]
    public class AWSBedrockProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "AWS Bedrock";
        public override ApiTypeEnum ApiType => ApiTypeEnum.AWSBedrock;

        public override IEnumerable<string> RegexPatterns =>
        [
            // AWS Access Key ID pattern (starts with AKIA, ASIA, or AIDA)
            @"AKIA[0-9A-Z]{16}",
            @"ASIA[0-9A-Z]{16}"
        ];

        public AWSBedrockProvider() : base()
        {
        }

        public AWSBedrockProvider(ILogger<AWSBedrockProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // AWS Bedrock requires AWS SDK with proper signing (SigV4)
            // Cannot validate with simple HTTP request - would need full AWS credentials
            _logger?.LogInformation("AWS Bedrock credential detected. Cannot validate without full AWS credentials.");

            return await Task.FromResult(ValidationResult.Unknown("Cannot validate without Secret Access Key and Region"));
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            if (string.IsNullOrWhiteSpace(apiKey))
                return false;

            // Check for AWS Access Key ID format (AKIA/ASIA prefix)
            if (apiKey.StartsWith("AKIA") || apiKey.StartsWith("ASIA") || apiKey.StartsWith("AIDA"))
            {
                return apiKey.Length == 20 && apiKey.All(c => char.IsLetterOrDigit(c));
            }

            return false;
        }
    }
}
