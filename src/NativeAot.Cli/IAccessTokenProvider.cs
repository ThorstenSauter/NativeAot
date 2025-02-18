namespace NativeAot.Cli;

public interface IAccessTokenProvider
{
    Task<string?> GetAccessTokenAsync();
}
