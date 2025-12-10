using System.Reflection;
using UnsecuredAPIKeys.Providers.Core;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers
{
    public static class ApiProviderRegistry
    {
        private static readonly Lazy<List<IApiKeyProvider>> _allProviders = new(() =>
        {
            return [.. Assembly.GetExecutingAssembly()
                .GetTypes()
                .Where(type => type.GetCustomAttribute<ApiProviderAttribute>() != null
                               && typeof(IApiKeyProvider).IsAssignableFrom(type)
                               && type is { IsInterface: false, IsAbstract: false })
                .Select(type => (IApiKeyProvider)Activator.CreateInstance(type)!)];
        });

        private static readonly Lazy<List<IApiKeyProvider>> _scraperProviders = new(() =>
        {
            return [.. Assembly.GetExecutingAssembly()
                .GetTypes()
                .Where(type => {
                    var attr = type.GetCustomAttribute<ApiProviderAttribute>();
                    return attr is { ScraperUse: true }
                           && typeof(IApiKeyProvider).IsAssignableFrom(type)
                           && type is { IsInterface: false, IsAbstract: false };
                })
                .Select(type => (IApiKeyProvider)Activator.CreateInstance(type)!)];
        });

        private static readonly Lazy<List<IApiKeyProvider>> _verifierProviders = new(() =>
        {
            return [.. Assembly.GetExecutingAssembly()
                .GetTypes()
                .Where(type => {
                    var attr = type.GetCustomAttribute<ApiProviderAttribute>();
                    return attr is { VerificationUse: true }
                           && typeof(IApiKeyProvider).IsAssignableFrom(type)
                           && type is { IsInterface: false, IsAbstract: false };
                })
                .Select(type => (IApiKeyProvider)Activator.CreateInstance(type)!)];
        });

        /// <summary>
        /// Gets all providers with ApiProvider attribute (backward compatibility)
        /// </summary>
        public static IReadOnlyList<IApiKeyProvider> Providers => _allProviders.Value;

        /// <summary>
        /// Gets providers that are enabled for scraper use
        /// </summary>
        public static IReadOnlyList<IApiKeyProvider> ScraperProviders => _scraperProviders.Value;

        /// <summary>
        /// Gets providers that are enabled for verifier use
        /// </summary>
        public static IReadOnlyList<IApiKeyProvider> VerifierProviders => _verifierProviders.Value;

        /// <summary>
        /// Gets providers for a specific bot type
        /// </summary>
        /// <param name="botType">The type of bot (Scraper or Verifier)</param>
        /// <returns>List of providers enabled for the specified bot type</returns>
        public static IReadOnlyList<IApiKeyProvider> GetProvidersForBot(BotType botType)
        {
            return botType switch
            {
                BotType.Scraper => ScraperProviders,
                BotType.Verifier => VerifierProviders,
                _ => Providers
            };
        }

        /// <summary>
        /// Gets the category for a given API type
        /// </summary>
        /// <param name="apiType">The API type enum value</param>
        /// <returns>The provider category, or Unknown if not found</returns>
        public static ProviderCategory GetCategoryForApiType(ApiTypeEnum apiType)
        {
            var provider = Providers.FirstOrDefault(p => p.ApiType == apiType);
            if (provider == null)
                return ProviderCategory.Unknown;

            var type = provider.GetType();
            var attr = type.GetCustomAttribute<ApiProviderAttribute>();
            return attr?.Category ?? ProviderCategory.Unknown;
        }

        /// <summary>
        /// Gets a dictionary mapping all API types to their categories
        /// </summary>
        public static Dictionary<ApiTypeEnum, ProviderCategory> GetApiTypeCategories()
        {
            var categories = new Dictionary<ApiTypeEnum, ProviderCategory>();

            foreach (var provider in Providers)
            {
                var type = provider.GetType();
                var attr = type.GetCustomAttribute<ApiProviderAttribute>();
                var category = attr?.Category ?? ProviderCategory.Unknown;
                categories[provider.ApiType] = category;
            }

            return categories;
        }

        /// <summary>
        /// Gets the ApiType enum values for providers that are enabled for display in UI.
        /// Use this to filter orphaned keys to only recover those from active providers.
        /// </summary>
        public static HashSet<ApiTypeEnum> GetDisplayEnabledApiTypes()
        {
            return [.. Assembly.GetExecutingAssembly()
                .GetTypes()
                .Where(type => {
                    var attr = type.GetCustomAttribute<ApiProviderAttribute>();
                    return attr is { DisplayInUI: true }
                           && typeof(IApiKeyProvider).IsAssignableFrom(type)
                           && type is { IsInterface: false, IsAbstract: false };
                })
                .Select(type => ((IApiKeyProvider)Activator.CreateInstance(type)!).ApiType)];
        }

        /// <summary>
        /// Gets the ApiType enum values for providers that are enabled for verification.
        /// </summary>
        public static HashSet<ApiTypeEnum> GetVerificationEnabledApiTypes()
        {
            return [.. VerifierProviders.Select(p => p.ApiType)];
        }
    }

    /// <summary>
    /// Enumeration of bot types for provider filtering
    /// </summary>
    public enum BotType
    {
        Scraper,
        Verifier
    }
}
