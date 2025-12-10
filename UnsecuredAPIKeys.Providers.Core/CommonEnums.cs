namespace UnsecuredAPIKeys.Providers.Core;

/// <summary>
/// Categories for grouping providers in the UI and for filtering
/// </summary>
public enum ProviderCategory
{
    Unknown = 0,
    AI_LLM = 1,               // AI and Language Model providers
    CloudInfrastructure = 2,  // Cloud hosting and infrastructure
    SourceControl = 3,        // Git hosting and version control
    Communication = 4,        // Email, SMS, messaging services
    DatabaseBackend = 5,      // Database and backend services
    MapsLocation = 6,         // Maps and geolocation services
    Monitoring = 7,           // Monitoring and analytics
    Financial = 8             // Payment processing (never exposed publicly)
}

public enum IssueVerificationStatus
{
    NotFound = 0,
    Open = 1,
    Closed = 2,
    VerificationError = 3
}
