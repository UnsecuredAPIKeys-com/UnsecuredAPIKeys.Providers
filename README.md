# UnsecuredAPIKeys.Providers

**Community-driven API key provider implementations for detecting and validating exposed API keys.**

This repository contains provider plugins for [UnsecuredAPIKeys.com](https://unsecuredapikeys.com) - a service that scans public repositories for accidentally exposed API keys and helps developers secure them.

## 🎯 Purpose

This project provides:
- **Core Contracts**: Base interfaces and classes for building API key providers
- **Provider Implementations**: 37+ validators for popular APIs (OpenAI, Anthropic, AWS, Stripe, etc.)
- **Plugin Architecture**: Dynamically loadable providers that can be updated independently

## 📁 Repository Structure

```
UnsecuredAPIKeys.Providers/
├── UnsecuredAPIKeys.Providers.Core/    # Core contracts and base classes
│   ├── IApiKeyProvider.cs              # Provider interface
│   ├── BaseApiKeyProvider.cs           # Base class with retry logic
│   ├── ValidationResult.cs             # Validation result types
│   ├── ApiProviderAttribute.cs         # Provider metadata attribute
│   └── CommonEnums.cs                  # Shared enums (ApiTypeEnum, etc.)
│
└── UnsecuredAPIKeys.Providers/         # Provider implementations
    ├── AI Providers/                   # AI/LLM providers (OpenAI, Anthropic, etc.)
    ├── Cloud Providers/                # Cloud infrastructure (Cloudflare, Vercel, etc.)
    ├── Communication Providers/        # Messaging (Discord, Twilio, SendGrid, etc.)
    ├── Database Providers/             # Database services (Supabase, PlanetScale)
    ├── Map Providers/                  # Mapping APIs (Mapbox)
    ├── Monitoring Providers/           # Observability (Datadog, Sentry)
    └── SourceControl Providers/        # Git hosting (GitHub, GitLab)
```

## 🚀 Quick Start for Contributors

### 1. Fork and Clone

```bash
git clone https://github.com/YOUR_USERNAME/UnsecuredAPIKeys.Providers.git
cd UnsecuredAPIKeys.Providers
```

### 2. Create a New Provider

```bash
cd UnsecuredAPIKeys.Providers
# Create your provider in the appropriate category folder
# Example: "AI Providers/MyAIProvider.cs"
```

### 3. Build and Test

```bash
dotnet build UnsecuredAPIKeys.Providers.Core -c Release
dotnet build UnsecuredAPIKeys.Providers -c Release
```

### 4. Submit Pull Request

- Keep changes focused (one provider per PR)
- Follow the contribution rules below
- Add clear commit messages

## 📋 Contribution Rules

**All contributions MUST follow these rules:**

### 1. ✅ Key-Only Validation

**DO NOT** require anything beyond the API key itself.

❌ **Bad Examples:**
- AWS (requires Key + Region + Account ID)
- Azure OpenAI (requires Key + Deployment URL + Endpoint)
- Custom endpoints requiring additional configuration

✅ **Good Examples:**
- OpenAI (just the key: `sk-...`)
- Anthropic (just the key: `sk-ant-...`)
- Stripe (just the key: `sk_live_...` or `sk_test_...`)

**Why?** When scanning public repositories, we only find the API key in plaintext. Additional context (like regions, endpoints) is rarely exposed alongside the key.

### 2. 💰 Zero-Cost Validation

**DO NOT** use endpoints that incur charges when validating.

❌ **Bad Examples:**
- Sending a prompt to an LLM and reading the response (costs money per token)
- Making API calls that consume credits/quota
- Endpoints that charge per request

✅ **Good Examples:**
- `/v1/models` (lists available models, no cost)
- `/v1/me` or `/v1/account` (returns account info, no cost)
- `/v1/usage` (checks quota/billing, no cost)
- Simple authentication checks that return 200/401

**Why?** We validate thousands of keys per day. If each validation costs $0.001, that's unsustainable.

### 3. 📝 Small, Focused Pull Requests

- **One provider per PR** (exceptions for closely related providers like `OpenAI` + `AzureOpenAI`)
- Maximum ~200 lines of code per PR
- Clear, descriptive commit messages
- Reference any related issues

**Why?** Small PRs are easier to review, test, and merge quickly.

### 4. 🔒 Clean, Safe Code

- **No malicious code** (contributors found adding malware will be banned)
- Follow existing code patterns and style
- Proper error handling (use `ValidationResult` factory methods)
- No hardcoded credentials or secrets in code

### 5. 📦 Smart Library Usage

- Use **well-known NuGet packages only** (e.g., `System.Text.Json`)
- **Do NOT** add custom/unknown libraries without justification
- **Do NOT** use libraries created by the PR author (potential malware risk)
- Minimize dependencies - prefer built-in .NET libraries when possible

**Pre-approved libraries:**
- `System.Text.Json` (preferred for JSON)
- `Newtonsoft.Json` (legacy JSON, avoid if possible)
- `Microsoft.Extensions.*` (DI, Logging, Http)

**Require approval:**
- Any third-party NuGet package not listed above
- SDKs for specific services (e.g., AWS SDK, Azure SDK) - generally discouraged

## 🛠️ How to Add a New Provider

### Step 1: Create the Provider Class

Create a new file in the appropriate category folder:

```csharp
using System.Net;
using System.Text.Json;
using UnsecuredAPIKeys.Providers.Core;

namespace UnsecuredAPIKeys.Providers.AI_Providers;

[ApiProvider(
    ScraperUse = true,              // Enable for scraping (finding keys)
    VerificationUse = true,         // Enable for verification (validating keys)
    DisplayInUI = true,             // Show in UnsecuredAPIKeys.com UI
    Category = ProviderCategory.AI_LLM
)]
public class MyAIProvider : BaseApiKeyProvider
{
    public override string ProviderName => "MyAI";
    public override ApiTypeEnum ApiType => ApiTypeEnum.Unknown; // Add your type to CommonEnums.cs

    public override IEnumerable<string> RegexPatterns => new[]
    {
        @"myai[_-]?api[_-]?key[_=:\s]+['\""']?([a-zA-Z0-9]{32})['\""']?",
        @"myai-[a-zA-Z0-9]{32}"
    };

    protected override async Task<ValidationResult> ValidateKeyWithHttpClientAsync(
        string apiKey,
        HttpClient httpClient)
    {
        try
        {
            // Use a zero-cost endpoint (e.g., /v1/models, /v1/me, /v1/account)
            var request = new HttpRequestMessage(HttpMethod.Get, "https://api.myai.com/v1/models");
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiKey);

            var response = await httpClient.SendAsync(request);

            if (response.StatusCode == HttpStatusCode.OK)
            {
                // Key is valid and working
                return ValidationResult.Success(response.StatusCode);
            }
            else if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                // Key is invalid/expired
                return ValidationResult.IsUnauthorized(response.StatusCode, "Invalid API key");
            }
            else if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                // Rate limited (treat as network error to retry)
                return ValidationResult.HasNetworkError("Rate limited");
            }
            else
            {
                // Other HTTP errors
                return ValidationResult.HasHttpError(response.StatusCode);
            }
        }
        catch (HttpRequestException ex)
        {
            return ValidationResult.HasNetworkError($"HTTP error: {ex.Message}");
        }
        catch (Exception ex)
        {
            return ValidationResult.HasProviderSpecificError($"Unexpected error: {ex.Message}");
        }
    }

    protected override bool IsValidKeyFormat(string apiKey)
    {
        // Basic format validation (optional but recommended)
        return !string.IsNullOrWhiteSpace(apiKey)
            && apiKey.Length >= 32
            && apiKey.Length <= 64;
    }
}
```

### Step 2: Add to CommonEnums.cs (if new service)

If your provider is for a new service not in the enum:

```csharp
public enum ApiTypeEnum
{
    // ... existing entries ...
    MyAI = 999,  // Pick an unused number in the appropriate range
}
```

### Step 3: Test Your Provider

1. Build the project: `dotnet build -c Release`
2. Test with a real API key (create a test account if needed)
3. Verify it correctly identifies valid vs invalid keys
4. Verify it doesn't consume credits or cost money

### Step 4: Submit PR

- Title: `feat: add MyAI provider`
- Description: Explain the provider, link to API docs, confirm zero-cost validation

## 🧪 Testing Guidelines

### Manual Testing Checklist

- [ ] Provider builds without errors
- [ ] Regex patterns correctly match example keys
- [ ] Valid key returns `ValidationResult.Success`
- [ ] Invalid key returns `ValidationResult.IsUnauthorized`
- [ ] Expired key returns `ValidationResult.IsUnauthorized`
- [ ] No credits/quota consumed during validation
- [ ] Handles rate limits gracefully (returns `NetworkError` to retry)
- [ ] No exceptions thrown for common scenarios

### Example Test Keys

When testing, use:
- Your own test API key (create a free account)
- Revoked/expired keys (if available)
- Intentionally malformed keys

**Never commit real API keys to the repository.**

## 📚 API Documentation

### Core Interfaces

#### `IApiKeyProvider`

```csharp
public interface IApiKeyProvider
{
    string ProviderName { get; }
    ApiTypeEnum ApiType { get; }
    IEnumerable<string> RegexPatterns { get; }
    Task<ValidationResult> ValidateKeyAsync(string apiKey, IHttpClientFactory httpClientFactory, WebProxy? proxy);
}
```

#### `ValidationResult` Factory Methods

```csharp
// Key is valid and working
ValidationResult.Success(HttpStatusCode statusCode)

// Key is explicitly invalid/unauthorized
ValidationResult.IsUnauthorized(HttpStatusCode statusCode, string? detail = null)

// HTTP error occurred (4xx/5xx)
ValidationResult.HasHttpError(HttpStatusCode statusCode, string? detail = null)

// Network-level error (DNS, timeout, connection refused)
ValidationResult.HasNetworkError(string detail)

// Provider-specific error
ValidationResult.HasProviderSpecificError(string detail)

// Key is valid but has no credits/quota
ValidationResult.ValidNoCredits(HttpStatusCode statusCode, string? detail = null)
```

## 🤝 Code of Conduct

- Be respectful and professional in all interactions
- Provide constructive feedback on pull requests
- Help newcomers learn the contribution process
- Report security issues privately (do not open public issues)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- **Main Project**: [UnsecuredAPIKeys.com](https://unsecuredapikeys.com) (private repo)
- **Open Source Lite**: [UnsecuredAPIKeys.Lite](https://github.com/UnsecuredAPIKeys-com/UnsecuredAPIKeys.Lite) (coming soon)

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/UnsecuredAPIKeys-com/UnsecuredAPIKeys.Providers/issues)
- **Discussions**: [GitHub Discussions](https://github.com/UnsecuredAPIKeys-com/UnsecuredAPIKeys.Providers/discussions)

## 🙏 Contributors

Thank you to all the developers who have contributed to this project!

See [CONTRIBUTORS.md](CONTRIBUTORS.md) for the full list.

---

**Made with ❤️ by the UnsecuredAPIKeys community**
