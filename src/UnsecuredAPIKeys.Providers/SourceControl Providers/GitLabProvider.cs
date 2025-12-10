using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.SourceControl_Providers
{
    /// <summary>
    /// Provider implementation for validating GitLab Personal Access Tokens (PATs).
    /// Supports tokens with the glpat- prefix.
    /// </summary>
    [ApiProvider(
        ScraperUse = true,
        VerificationUse = true,
        DisplayInUI = false,
        HiddenFromUIReason = "Source control tokens not publicly displayed",
        Category = ProviderCategory.SourceControl)]
    public class GitLabProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "GitLab";
        public override ApiTypeEnum ApiType => ApiTypeEnum.GitLab;

        // Regex patterns for GitLab tokens
        public override IEnumerable<string> RegexPatterns =>
        [
            @"glpat-[A-Za-z0-9\-_]{20,}"  // Personal Access Token
        ];

        public GitLabProvider() : base()
        {
        }

        public GitLabProvider(ILogger<GitLabProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // GitLab uses PRIVATE-TOKEN header for authentication
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://gitlab.com/api/v4/user");
            request.Headers.Add("PRIVATE-TOKEN", apiKey);

            var response = await httpClient.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("GitLab API response: Status={StatusCode}, Body={Body}",
                response.StatusCode, TruncateResponse(responseBody));

            if (IsSuccessStatusCode(response.StatusCode))
            {
                // Extract metadata from response
                var metadata = ExtractMetadata(responseBody);
                return ValidationResult.Success(response.StatusCode, metadata, hasCredits: true);
            }
            else if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                // 401 - Invalid token
                return ValidationResult.IsUnauthorized(response.StatusCode);
            }
            else if (response.StatusCode == HttpStatusCode.Forbidden)
            {
                // 403 - Token valid but insufficient scopes
                _logger?.LogInformation("GitLab token valid but insufficient scopes");
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
                    $"GitLab API request failed with status {response.StatusCode}. Response: {TruncateResponse(responseBody)}");
            }
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            if (string.IsNullOrWhiteSpace(apiKey) || apiKey.Length < 25)
                return false;

            // Check for valid prefix
            return apiKey.StartsWith("glpat-", StringComparison.Ordinal);
        }

        /// <summary>
        /// Extracts metadata from the GitLab API response.
        /// </summary>
        private List<ModelInfo>? ExtractMetadata(string responseBody)
        {
            var metadata = new List<ModelInfo>();

            try
            {
                using var doc = JsonDocument.Parse(responseBody);
                var root = doc.RootElement;

                if (root.TryGetProperty("username", out var usernameProp))
                {
                    metadata.Add(new ModelInfo
                    {
                        ModelId = "username",
                        DisplayName = "Username",
                        Description = usernameProp.GetString() ?? ""
                    });
                }

                if (root.TryGetProperty("name", out var nameProp))
                {
                    metadata.Add(new ModelInfo
                    {
                        ModelId = "name",
                        DisplayName = "Display Name",
                        Description = nameProp.GetString() ?? ""
                    });
                }

                if (root.TryGetProperty("is_admin", out var isAdminProp))
                {
                    metadata.Add(new ModelInfo
                    {
                        ModelId = "is_admin",
                        DisplayName = "Admin Status",
                        Description = isAdminProp.GetBoolean() ? "Yes" : "No"
                    });
                }

                if (root.TryGetProperty("can_create_group", out var canCreateGroupProp))
                {
                    metadata.Add(new ModelInfo
                    {
                        ModelId = "can_create_group",
                        DisplayName = "Can Create Groups",
                        Description = canCreateGroupProp.GetBoolean() ? "Yes" : "No"
                    });
                }

                if (root.TryGetProperty("can_create_project", out var canCreateProjectProp))
                {
                    metadata.Add(new ModelInfo
                    {
                        ModelId = "can_create_project",
                        DisplayName = "Can Create Projects",
                        Description = canCreateProjectProp.GetBoolean() ? "Yes" : "No"
                    });
                }

                if (root.TryGetProperty("two_factor_enabled", out var twoFactorProp))
                {
                    metadata.Add(new ModelInfo
                    {
                        ModelId = "two_factor",
                        DisplayName = "2FA Enabled",
                        Description = twoFactorProp.GetBoolean() ? "Yes" : "No"
                    });
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to extract metadata from GitLab response");
            }

            return metadata.Count > 0 ? metadata : null;
        }
    }
}
