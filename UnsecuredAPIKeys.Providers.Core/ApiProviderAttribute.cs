namespace UnsecuredAPIKeys.Providers.Core;

[AttributeUsage(AttributeTargets.Class)]
public class ApiProviderAttribute : Attribute
{
    /// <summary>
    /// Whether this provider should be used by the Scraper bot
    /// </summary>
    public bool ScraperUse { get; set; } = true;

    /// <summary>
    /// Explanation for why scraping is disabled (shown in Provider Status page)
    /// </summary>
    public string? ScraperDisabledReason { get; set; }

    /// <summary>
    /// Whether this provider should be used by the Verifier bot
    /// </summary>
    public bool VerificationUse { get; set; } = true;

    /// <summary>
    /// Explanation for why verification is disabled (shown in Provider Status page)
    /// </summary>
    public string? VerificationDisabledReason { get; set; }

    /// <summary>
    /// Whether this provider's keys should be displayed in the UI and included in statistics.
    /// Set to false for providers that require additional context (e.g., endpoint URLs) to be useful,
    /// or for financial providers that should never be exposed publicly.
    /// </summary>
    public bool DisplayInUI { get; set; } = true;

    /// <summary>
    /// Explanation for why this provider is hidden from UI (shown in Provider Status page)
    /// </summary>
    public string? HiddenFromUIReason { get; set; }

    /// <summary>
    /// The category this provider belongs to for UI grouping and filtering
    /// </summary>
    public ProviderCategory Category { get; set; } = ProviderCategory.Unknown;

    /// <summary>
    /// Whether to directly notify the repository owner when a valid key is found.
    /// Used for sensitive providers (e.g., financial) where keys should not be exposed publicly.
    /// </summary>
    public bool NotifyOwnerDirectly { get; set; } = false;

    /// <summary>
    /// Creates an ApiProvider attribute with default usage (enabled for all features)
    /// </summary>
    public ApiProviderAttribute()
    {
    }

    /// <summary>
    /// Creates an ApiProvider attribute with specific usage flags
    /// </summary>
    /// <param name="scraperUse">Enable for scraper bot</param>
    /// <param name="verificationUse">Enable for verifier bot</param>
    public ApiProviderAttribute(bool scraperUse, bool verificationUse)
    {
        ScraperUse = scraperUse;
        VerificationUse = verificationUse;
    }
}
