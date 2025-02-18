using System.Text.Json.Serialization;

namespace NativeAot.Cli;

public sealed class TokenResponse
{
    [JsonPropertyName("access_token")] public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("refresh_token")] public string RefreshToken { get; set; } = string.Empty;
}
