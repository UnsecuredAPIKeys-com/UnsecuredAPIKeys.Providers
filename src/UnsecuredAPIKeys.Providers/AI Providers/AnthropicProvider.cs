using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

using Microsoft.Extensions.Logging;

using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.AI_Providers
{
    /// <summary>
    /// Provider implementation for handling Anthropic (Claude) API keys with enhanced validation.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.AI_LLM)]
    public class AnthropicProvider : BaseApiKeyProvider
    {
        private const string API_ENDPOINT = "https://api.anthropic.com/v1/messages";
        private const string ANTHROPIC_VERSION = "2023-06-01";
        private const string DEFAULT_MODEL = "claude-sonnet-4-20250514";
        private const int MAX_RETRIES = 3;
        private const int TIMEOUT_SECONDS = 30;

        // Anthropic-specific response keywords (additional to base class)
        private static readonly HashSet<string> InvalidKeyIndicators = new(StringComparer.OrdinalIgnoreCase)
        {
            "invalid_api_key",
            "authentication_error",
            "invalid x-api-key",
            "unauthorized"
        };

        public override string ProviderName => "Anthropic";

        public override ApiTypeEnum ApiType => ApiTypeEnum.AnthropicClaude;

        // Enhanced regex patterns with compiled regex for better performance
        public override IEnumerable<string> RegexPatterns =>
        [
            @"sk-ant-api\d{0,2}-[a-zA-Z0-9\-_]{40,120}",
            @"sk-ant-[a-zA-Z0-9\-_]{40,95}",
            @"sk-ant-v\d+-[a-zA-Z0-9\-_]{40,95}",
            @"sk-ant-[a-zA-Z0-9]+-[a-zA-Z0-9\-_]{20,120}",
            @"sk-ant-[a-zA-Z0-9]{40,64}",
            @"\bsk-ant-[a-zA-Z0-9\-_]{20,120}\b"
        ];

        public AnthropicProvider() : base()
        {
        }

        public AnthropicProvider(ILogger<AnthropicProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            using var request = CreateValidationRequest(apiKey);

            var response = await httpClient.SendAsync(request);
            var responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("Anthropic API response: Status={StatusCode}, Body={Body}",
                response.StatusCode, responseBody.Length > 200 ? responseBody.Substring(0, 200) + "..." : responseBody);

            return InterpretResponse(response.StatusCode, responseBody);
        }

        private HttpRequestMessage CreateValidationRequest(string apiKey)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, API_ENDPOINT);

            // Set headers
            request.Headers.Add("x-api-key", apiKey);
            request.Headers.Add("anthropic-version", ANTHROPIC_VERSION);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            // Ultra-minimal payload for lowest cost
            var payload = new
            {
                model = DEFAULT_MODEL,
                max_tokens = 1,
                messages = new[]
                {
                    new { role = "user", content = "1" }
                },
                temperature = 0,
                stop_sequences = new[] { "1", "2", "3", "4", "5" }
            };

            var jsonContent = JsonSerializer.Serialize(payload);
            request.Content = new StringContent(jsonContent, Encoding.UTF8, "application/json");

            return request;
        }

        private ValidationResult InterpretResponse(HttpStatusCode statusCode, string responseBody)
        {
            // Success cases - request worked, key has credits
            if (IsSuccessStatusCode(statusCode))
            {
                _logger?.LogInformation("Anthropic key is valid with usable credits");
                return ValidationResult.Success(statusCode, hasCredits: true);
            }

            var bodyLower = responseBody.ToLowerInvariant();

            switch (statusCode)
            {
                case HttpStatusCode.Unauthorized: // 401
                    if (ContainsAny(bodyLower, InvalidKeyIndicators))
                    {
                        return ValidationResult.IsUnauthorized(statusCode);
                    }
                    return ValidationResult.IsUnauthorized(statusCode);

                case HttpStatusCode.Forbidden: // 403
                    if (ContainsAny(bodyLower, PermissionIndicators))
                    {
                        _logger?.LogInformation("Anthropic key has permission restrictions but is valid");
                        return ValidationResult.Success(statusCode, hasCredits: true);
                    }
                    return ValidationResult.HasHttpError(statusCode, $"Forbidden: {TruncateResponse(responseBody)}");

                case HttpStatusCode.BadRequest: // 400
                    if (ContainsAny(bodyLower, QuotaIndicators))
                    {
                        _logger?.LogInformation("Anthropic key is valid but has quota/billing issues (no credits)");
                        return ValidationResult.ValidNoCredits(statusCode, "Quota/billing issue detected");
                    }
                    return ValidationResult.HasHttpError(statusCode, $"Bad request: {TruncateResponse(responseBody)}");

                case HttpStatusCode.PaymentRequired: // 402
                    _logger?.LogInformation("Anthropic key is valid but requires payment (no credits)");
                    return ValidationResult.ValidNoCredits(statusCode, "Payment required");

                case HttpStatusCode.TooManyRequests: // 429
                    // Check if it's quota exhaustion vs temporary rate limit
                    if (ContainsAny(bodyLower, QuotaIndicators))
                    {
                        _logger?.LogInformation("Anthropic key is valid but quota exhausted (no credits)");
                        return ValidationResult.ValidNoCredits(statusCode, "Quota exhausted");
                    }
                    // Regular rate limit means key is valid and has credits
                    return ValidationResult.Success(statusCode, hasCredits: true);

                case HttpStatusCode.ServiceUnavailable: // 503
                case HttpStatusCode.GatewayTimeout: // 504
                    return ValidationResult.HasNetworkError($"Service unavailable: {statusCode}");

                default:
                    if (ContainsAny(bodyLower, QuotaIndicators))
                    {
                        _logger?.LogInformation("Anthropic key is valid but has quota issues (no credits)");
                        return ValidationResult.ValidNoCredits(statusCode, "Quota issue detected");
                    }

                    return ValidationResult.HasHttpError(statusCode,
                        $"API request failed with status {statusCode}. Response: {TruncateResponse(responseBody)}");
            }
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            if (string.IsNullOrWhiteSpace(apiKey) || apiKey.Length < 20)
                return false;

            if (!apiKey.StartsWith("sk-ant-", StringComparison.Ordinal))
                return false;

            return apiKey.All(c => char.IsLetterOrDigit(c) || c == '-' || c == '_');
        }
    }
}