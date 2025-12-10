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
    /// Provider implementation for handling OpenAI API keys.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.AI_LLM)]
    public class OpenAIProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "OpenAI";
        public override ApiTypeEnum ApiType => ApiTypeEnum.OpenAI;

        // Enhanced regex patterns for OpenAI keys
        public override IEnumerable<string> RegexPatterns =>
        [
            @"sk-[A-Za-z0-9\-]{20,}",
            @"sk-proj-[A-Za-z0-9\-]{20,}",
            @"sk-svcacct-[A-Za-z0-9\-]{20,}",
            @"sk-[A-Za-z0-9]{48}",  // Standard format
            @"Bearer sk-[A-Za-z0-9\-]{20,}"  // Keys in auth headers
        ];

        public OpenAIProvider() : base()
        {
        }

        public OpenAIProvider(ILogger<OpenAIProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // First, try a lightweight model listing endpoint
            using var modelRequest = new HttpRequestMessage(HttpMethod.Get, "https://api.openai.com/v1/models");
            modelRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
            
            var modelResponse = await httpClient.SendAsync(modelRequest);
            string responseBody = await modelResponse.Content.ReadAsStringAsync();

            _logger?.LogDebug("OpenAI models API response: Status={StatusCode}, Body={Body}",
                modelResponse.StatusCode, TruncateResponse(responseBody));

            if (IsSuccessStatusCode(modelResponse.StatusCode))
            {
                // Parse the models from the response
                var models = ParseOpenAIModels(responseBody);
                // 200 OK on models endpoint means key is valid and has credits (can make requests)
                return ValidationResult.Success(modelResponse.StatusCode, models, hasCredits: true);
            }
            else if (modelResponse.StatusCode == HttpStatusCode.Unauthorized)
            {
                return ValidationResult.IsUnauthorized(modelResponse.StatusCode);
            }
            else if ((int)modelResponse.StatusCode == 429)
            {
                // Rate limited - check if it's quota exhausted vs temporary rate limit
                if (responseBody.Contains("insufficient_quota", StringComparison.OrdinalIgnoreCase) ||
                    responseBody.Contains("exceeded", StringComparison.OrdinalIgnoreCase))
                {
                    _logger?.LogInformation("OpenAI key is valid but has no credits (quota exceeded)");
                    return ValidationResult.ValidNoCredits(modelResponse.StatusCode, "Quota exceeded");
                }
                // Regular rate limit means key is valid and has credits
                return ValidationResult.Success(modelResponse.StatusCode, hasCredits: true);
            }
            else if (modelResponse.StatusCode == HttpStatusCode.PaymentRequired)
            {
                // Payment required means valid key but no credits
                _logger?.LogInformation("OpenAI key is valid but requires payment (no credits)");
                return ValidationResult.ValidNoCredits(modelResponse.StatusCode, "Payment required");
            }
            else
            {
                // Check response body for quota/billing issues
                if (ContainsAny(responseBody, QuotaIndicators))
                {
                    _logger?.LogInformation("OpenAI key is valid but has quota/billing issues");
                    return ValidationResult.ValidNoCredits(modelResponse.StatusCode, "Quota/billing issue detected");
                }

                return ValidationResult.HasHttpError(modelResponse.StatusCode,
                    $"API request failed with status {modelResponse.StatusCode}. Response: {TruncateResponse(responseBody)}");
            }
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            return !string.IsNullOrWhiteSpace(apiKey) && 
                   apiKey.StartsWith("sk-") && 
                   apiKey.Length >= 23; // sk- + at least 20 chars
        }

        private List<ModelInfo>? ParseOpenAIModels(string jsonResponse)
        {
            try
            {
                using var doc = JsonDocument.Parse(jsonResponse);
                if (!doc.RootElement.TryGetProperty("data", out var dataArray))
                {
                    return null;
                }

                var models = new List<ModelInfo>();
                foreach (var modelElement in dataArray.EnumerateArray())
                {
                    var model = new ModelInfo
                    {
                        ModelId = modelElement.GetProperty("id").GetString() ?? "",
                        DisplayName = modelElement.GetProperty("id").GetString() ?? "", // OpenAI uses id as display name
                        Description = modelElement.TryGetProperty("description", out var desc) ? desc.GetString() : null
                    };

                    // Extract model group from the ID
                    if (!string.IsNullOrEmpty(model.ModelId))
                    {
                        // Group models by family (e.g., "gpt-4", "gpt-3.5", "text-embedding")
                        if (model.ModelId.StartsWith("gpt-4"))
                        {
                            model.ModelGroup = "GPT-4";
                            
                            // Check for specific capabilities
                            if (model.ModelId.Contains("turbo"))
                            {
                                model.Description = "GPT-4 Turbo model with enhanced capabilities";
                            }
                            else if (model.ModelId.Contains("vision"))
                            {
                                model.Description = "GPT-4 model with vision capabilities";
                            }
                        }
                        else if (model.ModelId.StartsWith("gpt-3.5"))
                        {
                            model.ModelGroup = "GPT-3.5";
                        }
                        else if (model.ModelId.StartsWith("o1"))
                        {
                            model.ModelGroup = "O1";
                            model.Description = "OpenAI's reasoning model";
                        }
                        else if (model.ModelId.StartsWith("text-embedding"))
                        {
                            model.ModelGroup = "Embeddings";
                            model.Description = "Text embedding model";
                        }
                        else if (model.ModelId.StartsWith("dall-e"))
                        {
                            model.ModelGroup = "DALL-E";
                            model.Description = "Image generation model";
                        }
                        else if (model.ModelId.StartsWith("whisper"))
                        {
                            model.ModelGroup = "Whisper";
                            model.Description = "Speech recognition model";
                        }
                        else if (model.ModelId.StartsWith("tts"))
                        {
                            model.ModelGroup = "TTS";
                            model.Description = "Text-to-speech model";
                        }
                        else
                        {
                            model.ModelGroup = "Other";
                        }
                    }

                    models.Add(model);
                }

                return models;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error parsing OpenAI models response");
                return null;
            }
        }
    }
}
