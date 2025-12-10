using System.Net;
using Microsoft.Extensions.Logging;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.Map_Providers
{
    /// <summary>
    /// Provider implementation for handling Mapbox API tokens.
    /// Mapbox tokens provide access to maps, geocoding, navigation, and location services.
    /// </summary>
    [ApiProvider(Category = ProviderCategory.MapsLocation)]
    public class MapboxProvider : BaseApiKeyProvider
    {
        public override string ProviderName => "Mapbox";
        public override ApiTypeEnum ApiType => ApiTypeEnum.Mapbox;

        public override IEnumerable<string> RegexPatterns =>
        [
            // Public tokens (pk.)
            @"\bpk\.[a-zA-Z0-9_-]{60,}\b",
            // Secret tokens (sk.)
            @"\bsk\.[a-zA-Z0-9_-]{60,}\b",
            // Temporary tokens (tk.)
            @"\btk\.[a-zA-Z0-9_-]{60,}\b"
        ];

        public MapboxProvider() : base()
        {
        }

        public MapboxProvider(ILogger<MapboxProvider>? logger) : base(logger)
        {
        }

        protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(string apiKey, HttpClient httpClient)
        {
            // Use Mapbox's tokens endpoint for validation
            using var request = new HttpRequestMessage(HttpMethod.Get,
                $"https://api.mapbox.com/tokens/v2?access_token={apiKey}");

            var response = await httpClient.SendAsync(request);
            string responseBody = await response.Content.ReadAsStringAsync();

            _logger?.LogDebug("Mapbox API response: Status={StatusCode}, Body={Body}",
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
            else
            {
                return ValidationResult.HasHttpError(response.StatusCode,
                    $"API request failed with status {response.StatusCode}. Response: {TruncateResponse(responseBody)}");
            }
        }

        protected override bool IsValidKeyFormat(string apiKey)
        {
            if (string.IsNullOrWhiteSpace(apiKey))
                return false;

            // Mapbox tokens start with pk., sk., or tk. followed by base64-like characters
            return (apiKey.StartsWith("pk.") || apiKey.StartsWith("sk.") || apiKey.StartsWith("tk."))
                   && apiKey.Length >= 80;
        }
    }
}
