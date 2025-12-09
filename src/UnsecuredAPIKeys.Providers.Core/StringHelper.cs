using System.Buffers;
using System.Runtime.CompilerServices;

namespace UnsecuredAPIKeys.Providers.Core;

/// <summary>
/// High-performance string utilities optimized for .NET 10.
/// Uses Span, string.Create, and SearchValues to minimize allocations.
/// </summary>
public static class StringHelper
{
    /// <summary>
    /// Masks an API key for logging, showing only first 4 and last 4 characters.
    /// Uses string.Create to avoid intermediate allocations.
    /// </summary>
    /// <param name="apiKey">The API key to mask</param>
    /// <returns>Masked key like "sk-a...xyz9" or the original if too short</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static string MaskApiKey(string apiKey)
    {
        if (string.IsNullOrEmpty(apiKey) || apiKey.Length <= 8)
            return apiKey ?? string.Empty;

        // "xxxx...yyyy" = 4 + 3 + 4 = 11 chars
        return string.Create(11, apiKey, static (span, key) =>
        {
            key.AsSpan(0, 4).CopyTo(span);
            span[4] = '.';
            span[5] = '.';
            span[6] = '.';
            key.AsSpan(key.Length - 4, 4).CopyTo(span[7..]);
        });
    }

    /// <summary>
    /// Masks an API key with configurable visible character counts.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static string MaskApiKey(string apiKey, int prefixLength, int suffixLength)
    {
        if (string.IsNullOrEmpty(apiKey))
            return apiKey ?? string.Empty;

        int minLength = prefixLength + suffixLength + 1;
        if (apiKey.Length <= minLength)
            return apiKey;

        int resultLength = prefixLength + 3 + suffixLength; // prefix + "..." + suffix
        return string.Create(resultLength, (apiKey, prefixLength, suffixLength), static (span, state) =>
        {
            var (key, prefix, suffix) = state;
            key.AsSpan(0, prefix).CopyTo(span);
            span[prefix] = '.';
            span[prefix + 1] = '.';
            span[prefix + 2] = '.';
            key.AsSpan(key.Length - suffix, suffix).CopyTo(span[(prefix + 3)..]);
        });
    }

    /// <summary>
    /// Checks if text contains any of the specified indicators (case-insensitive).
    /// Optimized to short-circuit on first match.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool ContainsAnyOrdinalIgnoreCase(ReadOnlySpan<char> text, ReadOnlySpan<string> indicators)
    {
        foreach (var indicator in indicators)
        {
            if (text.Contains(indicator.AsSpan(), StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Checks if text contains any of the specified indicators (case-insensitive).
    /// Overload for HashSet compatibility.
    /// </summary>
    public static bool ContainsAnyOrdinalIgnoreCase(string text, HashSet<string> indicators)
    {
        if (string.IsNullOrEmpty(text))
            return false;

        ReadOnlySpan<char> textSpan = text.AsSpan();
        foreach (var indicator in indicators)
        {
            if (textSpan.Contains(indicator.AsSpan(), StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Truncates a string for logging purposes without allocating if already short enough.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static string Truncate(string? text, int maxLength = 200)
    {
        if (string.IsNullOrEmpty(text))
            return string.Empty;

        if (text.Length <= maxLength)
            return text;

        // Allocate exactly what we need: maxLength + 3 for "..."
        return string.Create(maxLength + 3, text, static (span, source) =>
        {
            int maxLen = span.Length - 3;
            source.AsSpan(0, maxLen).CopyTo(span);
            span[maxLen] = '.';
            span[maxLen + 1] = '.';
            span[maxLen + 2] = '.';
        });
    }

    /// <summary>
    /// Removes a prefix from a string if present, using span to check without allocation.
    /// Returns the original string if prefix not found (no allocation).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static string RemovePrefixOrdinalIgnoreCase(string text, string prefix)
    {
        if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(prefix))
            return text ?? string.Empty;

        if (text.AsSpan().StartsWith(prefix.AsSpan(), StringComparison.OrdinalIgnoreCase))
        {
            // Only allocate if we actually need to remove the prefix
            return text[prefix.Length..].TrimStart();
        }

        return text;
    }

    /// <summary>
    /// Cleans an API key by removing common prefixes. Optimized to minimize allocations.
    /// </summary>
    public static string CleanApiKey(string apiKey)
    {
        if (string.IsNullOrEmpty(apiKey))
            return string.Empty;

        ReadOnlySpan<char> span = apiKey.AsSpan().Trim();

        // Check prefixes using span (no allocation for the check)
        if (span.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            span = span[7..].Trim();
        }
        else if (span.StartsWith("x-api-key:", StringComparison.OrdinalIgnoreCase))
        {
            span = span[10..].Trim();
        }

        // Only allocate a new string if we modified something
        if (span.Length == apiKey.Length && span.SequenceEqual(apiKey.AsSpan()))
            return apiKey;

        return span.ToString();
    }
}
