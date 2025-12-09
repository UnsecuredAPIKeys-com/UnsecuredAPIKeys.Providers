namespace UnsecuredAPIKeys.Providers.Core;

public enum SearchProviderEnum
{
    Unknown = -99,
    GitHub = 1,
    GitLab = 2,
    BitBucket = 3,
    SourceGraph = 4
}

public enum ApiStatusEnum
{
    // The key was found but not yet checked for validity
    Unverified = -99,

    // The key was checked and is valid/working
    Valid = 1,

    // The key was checked and is not working (invalid, expired, revoked, etc.)
    Invalid = 0,

    // The key was removed at the request of the repo owner or by admin action
    Removed = 3,

    // The key was flagged for removal at the request of the repo owner.
    FlaggedForRemoval = 4,

    // The key is no longer valid. (Fixed / Removed)
    NoLongerWorking = 5,

    // The key was checked and is erroring out for some reason.
    Error = 6,

    // The key is valid but has no credits/quota
    ValidNoCredits = 7
}

public enum ApiTypeEnum
{
    // Default
    Unknown = -99,

    // AI Services (100+)
    OpenAI = 100,
    AzureOpenAI = 110,        // Not used | Requires too much info (base org URL + api key)
    AnthropicClaude = 120,    // More specific than AnthropicAI
    GoogleAI = 130,
    Cohere = 140,
    HuggingFace = 150,
    StabilityAI = 160,        // Stability.ai
    MistralAI = 170,
    Replicate = 180,
    TogetherAI = 190,
    OpenRouter = 195,

    // New AI Services
    PerplexityAI = 196,
    Groq = 197,
    DeepSeek = 198,
    ElevenLabs = 199,
    XAI = 207,                // xAI/Grok
    FireworksAI = 208,
    Anyscale = 209,
    AI21 = 211,
    AWSBedrock = 212,
    RunwayML = 201,
    AssemblyAI = 202,
    Pinecone = 203,
    Weaviate = 204,
    ChromaDB = 205,
    LangChain = 206,

    // Cloud Infrastructure (200+)
    AWS = 200,                // AWS Access Keys
    Azure = 210,              // Azure Service Principal Keys
    GCP = 220,                // Google Cloud Platform Keys
    DigitalOcean = 230,       // DigitalOcean API tokens
    Cloudflare = 240,         // Cloudflare API tokens
    Vercel = 250,             // Vercel API tokens
    Netlify = 260,            // Netlify API tokens
    Heroku = 270,             // Heroku API tokens

    // Source Control (300+)
    GitHub = 300,             // GitHub Personal Access Tokens
    GitLab = 310,
    BitBucket = 320,

    // Communication & Email (400+)
    Stripe = 400,             // Payment processing (INTERNAL ONLY)
    SendGrid = 410,           // Email service
    Twilio = 420,             // SMS/Voice services
    Mailgun = 425,            // Email service
    Postmark = 426,           // Transactional email
    Slack = 430,              // Workspace messaging
    DiscordBot = 435,         // Discord bot tokens

    // Database & Backend (500+)
    MongoDB = 500,            // MongoDB Atlas access keys
    Firebase = 510,           // Google Firebase keys
    Supabase = 520,           // Supabase API keys
    PlanetScale = 530,        // PlanetScale API keys

    // Maps & Location (600+)
    Mapbox = 600,             // Mapbox API keys
    HereMaps = 610,           // HERE Maps API keys

    // Monitoring & Analytics (700+)
    Datadog = 700,            // Datadog API keys
    NewRelic = 710,           // New Relic API keys
    Sentry = 720,             // Sentry DSN keys

    // Payment Processing - INTERNAL ONLY (800+)
    PayPal = 800,             // PayPal API keys (never expose)
    Square = 810              // Square API keys (never expose)
}

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
