using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.AI_Providers
{
    /// <summary>
    /// Provider implementation for handling Google AI API keys.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.AI_LLM)]
    public class GoogleProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Google";
        public override ApiTypeEnum ApiType => ApiTypeEnum.GoogleAI;

        // Regex patterns specific to Google AI keys (from Scraper_Program.cs)
        public override IEnumerable<string> RegexPatterns =>
        [
            @"AIza[0-9A-Za-z\-_]{35}",  // Standard length is exactly 39 characters total
            @"AIza[0-9A-Za-z\-_]{35,40}" // Allow for some variation in newer keys
        ];

        public GoogleProvider() : base()
        {
        }

        public GoogleProvider(ILogger<GoogleProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Use Google's models endpoint for lightweight validation
            using var modelRequest = new HttpRequestMessage(HttpMethod.Get, "https://generativelanguage.googleapis.com/v1beta/models");
            // Google uses x-goog-api-key header
            modelRequest.Headers.Add("x-goog-api-key", apiKey);
            
            var modelResponse = await httpClient.SendAsync(modelRequest);
            string responseBody = await modelResponse.Content.ReadAsStringAsync();

            _logger?.LogDebug("Google AI models API response: Status={StatusCode}, Body={Body}",
                modelResponse.StatusCode, TruncateResponse(responseBody));

            if (IsSuccessStatusCode(modelResponse.StatusCode))
            {
                // Parse the models from the response
                var models = ParseGoogleModels(responseBody);
                // Successful model listing means key is valid and active
                _logger?.LogInformation("Google AI key is valid with {ModelCount} models available", models?.Count ?? 0);
                return ValidationResult.Success(modelResponse.StatusCode, models, hasCredits: true);
            }
            else if (modelResponse.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                // Google often uses 403 for invalid keys
                if (ContainsAny(responseBody, UnauthorizedIndicators))
                {
                    return ValidationResult.IsUnauthorized(modelResponse.StatusCode);
                }
                return ValidationResult.IsUnauthorized(modelResponse.StatusCode);
            }
            else if (modelResponse.StatusCode == HttpStatusCode.BadRequest)
            {
                // Check specific error types
                if (ContainsAny(responseBody, UnauthorizedIndicators))
                {
                    return ValidationResult.IsUnauthorized(modelResponse.StatusCode);
                }
                return ValidationResult.HasHttpError(modelResponse.StatusCode, $"Bad request. Response: {TruncateResponse(responseBody)}");
            }
            else if ((int)modelResponse.StatusCode == 429)
            {
                // Check if it's RESOURCE_EXHAUSTED (quota) vs rate limit
                if (responseBody.Contains("RESOURCE_EXHAUSTED", StringComparison.OrdinalIgnoreCase) ||
                    ContainsAny(responseBody, QuotaIndicators))
                {
                    _logger?.LogInformation("Google AI key is valid but quota exhausted (no credits)");
                    return ValidationResult.ValidNoCredits(modelResponse.StatusCode, "Quota exhausted");
                }
                // Regular rate limit means key is valid and has credits
                return ValidationResult.Success(modelResponse.StatusCode, hasCredits: true);
            }
            else
            {
                // Check for quota/billing issues (RESOURCE_EXHAUSTED is Google's quota error)
                if (responseBody.Contains("RESOURCE_EXHAUSTED", StringComparison.OrdinalIgnoreCase) ||
                    ContainsAny(responseBody, QuotaIndicators))
                {
                    _logger?.LogInformation("Google AI key is valid but has quota/billing issues (no credits)");
                    return ValidationResult.ValidNoCredits(modelResponse.StatusCode, "Quota/billing issue detected");
                }

                return ValidationResult.HasHttpError(modelResponse.StatusCode,
                    $"API request failed with status {modelResponse.StatusCode}. Response: {TruncateResponse(responseBody)}");
            }
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            return !string.IsNullOrWhiteSpace(apiKey) && 
                   apiKey.StartsWith("AIza") && 
                   apiKey.Length >= 39; // AIza + 35 chars
        }

        private List<ModelInfo>? ParseGoogleModels(string jsonResponse)
        {
            try
            {
                using var doc = JsonDocument.Parse(jsonResponse);
                if (!doc.RootElement.TryGetProperty("models", out var modelsArray))
                {
                    return null;
                }

                var models = new List<ModelInfo>();
                foreach (var modelElement in modelsArray.EnumerateArray())
                {
                    var model = new ModelInfo
                    {
                        ModelId = modelElement.GetProperty("name").GetString() ?? "",
                        DisplayName = modelElement.TryGetProperty("displayName", out var displayName) ? displayName.GetString() : null,
                        Description = modelElement.TryGetProperty("description", out var description) ? description.GetString() : null,
                        Version = modelElement.TryGetProperty("version", out var version) ? version.GetString() : null,
                        InputTokenLimit = modelElement.TryGetProperty("inputTokenLimit", out var inputLimit) ? inputLimit.GetInt64() : null,
                        OutputTokenLimit = modelElement.TryGetProperty("outputTokenLimit", out var outputLimit) ? outputLimit.GetInt64() : null,
                        Temperature = modelElement.TryGetProperty("temperature", out var temp) ? (float?)temp.GetDouble() : null,
                        TopP = modelElement.TryGetProperty("topP", out var topP) ? (float?)topP.GetDouble() : null,
                        TopK = modelElement.TryGetProperty("topK", out var topK) ? topK.GetInt32() : null,
                        MaxTemperature = modelElement.TryGetProperty("maxTemperature", out var maxTemp) ? (float?)maxTemp.GetDouble() : null
                    };

                    // Parse supported methods
                    if (modelElement.TryGetProperty("supportedGenerationMethods", out var methods))
                    {
                        model.SupportedMethods = new List<string>();
                        foreach (var method in methods.EnumerateArray())
                        {
                            if (method.GetString() is string methodStr)
                            {
                                model.SupportedMethods.Add(methodStr);
                            }
                        }
                    }

                    // Extract model group from the display name
                    if (model.DisplayName != null)
                    {
                        // Extract model family (e.g., "Gemini 1.5", "Gemini 2.0", etc.)
                        if (model.DisplayName.Contains("Gemini"))
                        {
                            var parts = model.DisplayName.Split(' ');
                            if (parts.Length >= 2)
                            {
                                model.ModelGroup = $"{parts[0]} {parts[1]}";
                            }
                        }
                    }

                    models.Add(model);
                }

                return models;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error parsing Google models response");
                return null;
            }
        }
    }
}
