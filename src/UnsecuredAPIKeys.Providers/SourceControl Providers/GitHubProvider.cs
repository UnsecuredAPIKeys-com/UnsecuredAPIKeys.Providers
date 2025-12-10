using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.SourceControl_Providers
{
    /// <summary>
    /// Provider implementation for validating GitHub Personal Access Tokens (PATs).
    /// Supports classic PATs (ghp_), fine-grained PATs (github_pat_), OAuth tokens (gho_),
    /// server-to-server tokens (ghs_), and refresh tokens (ghr_).
    /// </summary>
    [ApiProvider(
        ScraperUse = true,
        VerificationUse = true,
        DisplayInUI = false,
        HiddenFromUIReason = "Source control tokens not publicly displayed",
        Category = ProviderCategory.SourceControl)]
    public class GitHubProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "GitHub";
        public override ApiTypeEnum ApiType => ApiTypeEnum.GitHub;

        // Regex patterns for different GitHub token types
        public override IEnumerable<string> RegexPatterns =>
        [
            @"ghp_[A-Za-z0-9]{36}",              // Classic Personal Access Token
            @"github_pat_[A-Za-z0-9_]{22,82}",   // Fine-grained Personal Access Token
            @"gho_[A-Za-z0-9]{36}",              // OAuth token
            @"ghs_[A-Za-z0-9]{36}",              // Server-to-server token (GitHub Apps)
            @"ghr_[A-Za-z0-9]{36}"               // Refresh token
        ];

        public GitHubProvider() : base()
        {
        }

        public GitHubProvider(ILogger<GitHubProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // GitHub requires a User-Agent header
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/user");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
            request.Headers.UserAgent.ParseAdd("UnsecuredAPIKeys-Verifier/1.0");

            var response = await httpClient.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("GitHub API response: Status={StatusCode}, Body={Body}",
                response.StatusCode, TruncateResponse(responseBody));

            if (IsSuccessStatusCode(response.StatusCode))
            {
                // Extract metadata from response
                var metadata = ExtractMetadata(response, responseBody);
                return ValidationResult.Success(response.StatusCode, metadata, hasCredits: true);
            }
            else if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                // 401 - Invalid token
                return ValidationResult.IsUnauthorized(response.StatusCode);
            }
            else if (response.StatusCode == HttpStatusCode.Forbidden)
            {
                // 403 - Check if rate limited or insufficient permissions
                if (response.Headers.TryGetValues("X-RateLimit-Remaining", out var rateLimitValues))
                {
                    var remaining = rateLimitValues.FirstOrDefault();
                    if (remaining == "0")
                    {
                        // Token is valid but rate limited
                        _logger?.LogInformation("GitHub token is valid but rate limited");
                        return ValidationResult.ValidNoCredits(response.StatusCode, "Rate limit exceeded");
                    }
                }

                // 403 with rate limit remaining = permission issue or invalid
                if (responseBody.Contains("API rate limit exceeded", StringComparison.OrdinalIgnoreCase))
                {
                    return ValidationResult.ValidNoCredits(response.StatusCode, "API rate limit exceeded");
                }

                return ValidationResult.IsUnauthorized(response.StatusCode);
            }
            else if (response.StatusCode == HttpStatusCode.NotFound)
            {
                // 404 - Token might be valid but lacks 'user' scope
                // This is still technically a working token, just limited
                _logger?.LogInformation("GitHub token valid but lacks user scope");
                return ValidationResult.Success(response.StatusCode, hasCredits: true);
            }
            else if ((int)response.StatusCode == 429)
            {
                // Rate limited - token is valid
                return ValidationResult.ValidNoCredits(response.StatusCode, "Rate limited");
            }
            else
            {
                return ValidationResult.HasHttpError(response.StatusCode,
                    $"GitHub API request failed with status {response.StatusCode}. Response: {TruncateResponse(responseBody)}");
            }
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            if (string.IsNullOrWhiteSpace(apiKey) || apiKey.Length < 20)
                return false;

            // Check for valid prefixes
            return apiKey.StartsWith("ghp_", StringComparison.Ordinal) ||
                   apiKey.StartsWith("github_pat_", StringComparison.Ordinal) ||
                   apiKey.StartsWith("gho_", StringComparison.Ordinal) ||
                   apiKey.StartsWith("ghs_", StringComparison.Ordinal) ||
                   apiKey.StartsWith("ghr_", StringComparison.Ordinal);
        }

        /// <summary>
        /// Extracts metadata from the GitHub API response.
        /// For classic PATs, extracts scopes from X-OAuth-Scopes header.
        /// </summary>
        private List<ModelInfo>? ExtractMetadata(HttpResponseMessage response, string responseBody)
        {
            var metadata = new List<ModelInfo>();

            try
            {
                // Extract scopes from header (only works for classic PATs, not fine-grained)
                if (response.Headers.TryGetValues("X-OAuth-Scopes", out var scopeValues))
                {
                    var scopes = scopeValues.FirstOrDefault() ?? "";
                    if (!string.IsNullOrEmpty(scopes))
                    {
                        metadata.Add(new ModelInfo
                        {
                            ModelId = "scopes",
                            DisplayName = "OAuth Scopes",
                            Description = scopes
                        });
                    }
                }

                // Extract rate limit info
                if (response.Headers.TryGetValues("X-RateLimit-Remaining", out var rateLimitValues))
                {
                    metadata.Add(new ModelInfo
                    {
                        ModelId = "rate_limit",
                        DisplayName = "Rate Limit Remaining",
                        Description = rateLimitValues.FirstOrDefault() ?? "unknown"
                    });
                }

                // Parse user info from response body
                using var doc = JsonDocument.Parse(responseBody);
                var root = doc.RootElement;

                if (root.TryGetProperty("login", out var loginProp))
                {
                    metadata.Add(new ModelInfo
                    {
                        ModelId = "username",
                        DisplayName = "Username",
                        Description = loginProp.GetString() ?? ""
                    });
                }

                if (root.TryGetProperty("type", out var typeProp))
                {
                    metadata.Add(new ModelInfo
                    {
                        ModelId = "account_type",
                        DisplayName = "Account Type",
                        Description = typeProp.GetString() ?? ""
                    });
                }

                if (root.TryGetProperty("plan", out var planProp) &&
                    planProp.TryGetProperty("name", out var planNameProp))
                {
                    metadata.Add(new ModelInfo
                    {
                        ModelId = "plan",
                        DisplayName = "Plan",
                        Description = planNameProp.GetString() ?? ""
                    });
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to extract metadata from GitHub response");
            }

            return metadata.Count > 0 ? metadata : null;
        }
    }
}
