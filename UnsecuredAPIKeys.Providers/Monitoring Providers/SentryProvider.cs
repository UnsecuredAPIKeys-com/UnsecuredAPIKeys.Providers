using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.Monitoring_Providers
{
    /// <summary>
    /// Provider implementation for handling Sentry DSN and API tokens.
    /// Sentry provides error tracking and performance monitoring.
    /// DSNs are validated by sending a minimal envelope to the store endpoint.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.Monitoring)]
    public class SentryProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Sentry";
        public override ApiTypeEnum ApiType => ApiTypeEnum.Sentry;

        // Regex to parse DSN: https://<public_key>@<host>/<project_id>
        // or https://<public_key>:<secret_key>@<host>/<project_id>
        private static readonly Regex DsnRegex = new(
            @"^https://([a-f0-9]{32})(?::([a-f0-9]{32}))?@([a-z0-9.-]+)/(\d+)$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public override IEnumerable<string> RegexPatterns =>
        [
            // Sentry DSN format: https://public@sentry.io/project-id
            @"https://[a-f0-9]{32}@[a-z0-9.-]+\.sentry\.io/[0-9]+",
            // Sentry DSN with private key
            @"https://[a-f0-9]{32}:[a-f0-9]{32}@[a-z0-9.-]+\.sentry\.io/[0-9]+",
            // Sentry API auth tokens
            @"\bsntrys_[a-zA-Z0-9]{60,}\b",
            // Legacy auth tokens - removed as too generic (matches SHA-256 hashes)
        ];

        public SentryProvider() : base()
        {
        }

        public SentryProvider(ILogger<SentryProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // If it's a DSN, validate by sending a minimal envelope to the store endpoint
            if (apiKey.StartsWith("https://") && apiKey.Contains("sentry.io"))
            {
                return await ValidateDsnAsync(apiKey, httpClient);
            }

            // For auth tokens, use the API
            if (apiKey.StartsWith("sntrys_"))
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, "https://sentry.io/api/0/");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

                var response = await httpClient.SendAsync(request);
                string responseBody = await response.Content.ReadAsStringAsync();

                _logger?.LogDebug("Sentry API response: Status={StatusCode}, Body={Body}",
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
                    return ValidationResult.Success(response.StatusCode);
                }
            }

            return ValidationResult.HasHttpError(HttpStatusCode.BadRequest, "Invalid Sentry credential format");
        }

        /// <summary>
        /// Validates a Sentry DSN by sending a minimal envelope to the store endpoint.
        /// Valid DSNs return 200 OK, invalid ones return 401/403.
        /// </summary>
        private async Task<ValidationResult> ValidateDsnAsync(string dsn, HttpClient httpClient)
        {
            var match = DsnRegex.Match(dsn);
            if (!match.Success)
            {
                return ValidationResult.HasHttpError(HttpStatusCode.BadRequest, "Invalid DSN format");
            }

            string publicKey = match.Groups[1].Value;
            string host = match.Groups[3].Value;
            string projectId = match.Groups[4].Value;

            // Sentry store endpoint: https://{host}/api/{project_id}/store/
            string storeUrl = $"https://{host}/api/{projectId}/store/";

            // Create a minimal event with just a valid event_id (32-char hex UUID)
            // This validates the DSN without creating real error data
            string eventId = Guid.NewGuid().ToString("N"); // 32 hex chars, no dashes
            string payload = $"{{\"event_id\":\"{eventId}\"}}";

            using var request = new HttpRequestMessage(HttpMethod.Post, storeUrl);
            request.Headers.Add("X-Sentry-Auth", $"Sentry sentry_version=7, sentry_key={publicKey}");
            request.Content = new StringContent(payload, Encoding.UTF8, "application/json");

            var response = await httpClient.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("Sentry DSN validation response: Status={StatusCode}, Body={Body}",
                response.StatusCode, TruncateResponse(responseBody));

            // Valid DSN returns 200 OK (even with minimal/empty envelope)
            // Invalid DSN returns 401 Unauthorized or 403 Forbidden
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
                // Rate limited but DSN is valid
                return ValidationResult.Success(response.StatusCode);
            }
            else
            {
                return ValidationResult.HasHttpError(response.StatusCode,
                    $"DSN validation failed with status {response.StatusCode}. Response: {TruncateResponse(responseBody)}");
            }
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            if (string.IsNullOrWhiteSpace(apiKey))
                return false;

            // Sentry DSN - must match our parsing regex
            if (apiKey.StartsWith("https://") && apiKey.Contains("sentry.io"))
                return DsnRegex.IsMatch(apiKey);

            // Auth tokens (sntrys_ prefix)
            if (apiKey.StartsWith("sntrys_") && apiKey.Length >= 65)
                return true;

            // Legacy 64 hex char tokens removed - too generic (matches SHA-256 hashes, etc.)
            // Only accept tokens with explicit Sentry prefixes or DSN format

            return false;
        }
    }
}
