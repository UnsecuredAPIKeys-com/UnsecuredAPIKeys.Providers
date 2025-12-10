namespace UnsecuredAPIKeys.Providers.Core;

/// <summary>
/// Assembly-level attribute to indicate the Provider API version this assembly was built against.
/// Used by the plugin system to verify version compatibility.
/// </summary>
[AttributeUsage(AttributeTargets.Assembly)]
public class ProviderApiVersionAttribute : Attribute
{
    public int Major { get; }
    public int Minor { get; }
    public int Patch { get; }

    public ProviderApiVersionAttribute(int major, int minor, int patch)
    {
        Major = major;
        Minor = minor;
        Patch = patch;
    }

    public Version Version => new Version(Major, Minor, Patch);
}
