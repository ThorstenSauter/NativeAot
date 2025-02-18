using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;

namespace NativeAot.Cli;

public sealed class AuthenticationBroker(IHttpClientFactory httpClientFactory) : IAccessTokenProvider
{
    private const string TenantId = "ffab38df-cddf-433f-859a-6cfa161a5ceb";
    private const string ClientId = "27018d62-d928-4af9-a419-809f154ab9f9";
    private const string RedirectUri = "http://localhost:5000/callback";
    private const string GraphScope = "offline_access https://graph.microsoft.com/.default";

    private static readonly byte[] AuthenticationResponse =
        "<html><body><h1>Authentication successful. You can close this window.</h1></body></html>"u8.ToArray();

    private readonly HttpClient _httpClient = httpClientFactory.CreateClient();

    private readonly string _tokenCachePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NativeAot.Cli",
        "accessToken.dat"
    );

    public async Task<string?> GetAccessTokenAsync()
    {
        var cachedToken = await GetCachedAccessTokenAsync();
        if (cachedToken is not null)
        {
            return cachedToken;
        }

        var (codeVerifier, codeChallenge) = GeneratePkceValues();
        var authCode = await GetAuthorizationCodeAsync(codeChallenge);
        return await ExchangeCodeForTokenAsync(authCode, codeVerifier);
    }

    private static (string, string) GeneratePkceValues()
    {
        using var rng = RandomNumberGenerator.Create();
        Span<byte> bytes = stackalloc byte[32];
        rng.GetBytes(bytes);

        var codeVerifier = ToBase64Dialect(bytes);

        var hashBytes = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
        var codeChallenge = ToBase64Dialect(hashBytes);

        return (codeVerifier, codeChallenge);
    }

    private static string ToBase64Dialect(Span<byte> bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static async Task<string?> GetAuthorizationCodeAsync(string codeChallenge)
    {
        var authUrl = $"https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/authorize" +
                      $"?client_id={ClientId}" +
                      $"&response_type=code" +
                      $"&redirect_uri={Uri.EscapeDataString(RedirectUri)}" +
                      $"&scope={Uri.EscapeDataString(GraphScope)}" +
                      $"&code_challenge={codeChallenge}" +
                      $"&code_challenge_method=S256";

        Process.Start(new ProcessStartInfo { FileName = authUrl, UseShellExecute = true });

        return await ListenForAuthCodeAsync();
    }

    private static async Task<string?> ListenForAuthCodeAsync()
    {
        using HttpListener listener = new();
        listener.Prefixes.Add($"{RedirectUri}/");
        listener.Start();

        var context = await listener.GetContextAsync();
        var request = context.Request;
        var code = request.QueryString["code"];

        var response = context.Response;
        response.ContentLength64 = AuthenticationResponse.Length;
        await using var output = response.OutputStream;
        await output.WriteAsync(AuthenticationResponse);

        listener.Stop();
        return code;
    }

    private async Task<string?> ExchangeCodeForTokenAsync(string? authCode, string codeVerifier)
    {
        using var requestBody = new FormUrlEncodedContent([
            new KeyValuePair<string, string?>("client_id", ClientId),
            new KeyValuePair<string, string?>("grant_type", "authorization_code"),
            new KeyValuePair<string, string?>("code", authCode),
            new KeyValuePair<string, string?>("redirect_uri", RedirectUri),
            new KeyValuePair<string, string?>("code_verifier", codeVerifier),
            new KeyValuePair<string, string?>("scope", GraphScope)
        ]);

        var response = await _httpClient.PostAsync(
            new Uri($"https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/token"),
            requestBody);

        var responseBody = await response.Content.ReadAsStringAsync();
        var tokenResponse = JsonSerializer.Deserialize(responseBody, JsonContext.Default.TokenResponse);

        var accessToken = tokenResponse?.AccessToken;
        if (accessToken is not null)
        {
            CacheTokens(tokenResponse);
        }

        return accessToken;
    }

    private async Task<string?> GetCachedAccessTokenAsync()
    {
        if (!OperatingSystem.IsWindows() || !File.Exists(_tokenCachePath))
        {
            return null;
        }

        try
        {
            var encryptedData = await File.ReadAllBytesAsync(_tokenCachePath);
            var decryptedData = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);
            var json = Encoding.UTF8.GetString(decryptedData);
            var tokenResponse = JsonSerializer.Deserialize(json, JsonContext.Default.TokenResponse);
            var decodedToken = new JsonWebToken(tokenResponse?.AccessToken);

            if (DateTime.UtcNow.AddMinutes(5) < decodedToken.ValidTo)
            {
                return tokenResponse!.AccessToken;
            }

            return await RefreshAccessToken(tokenResponse!.RefreshToken);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Failed to read cached token: {ex.Message}");
        }

        return null;
    }

    private void CacheTokens(TokenResponse? tokenResponse)
    {
        if (tokenResponse is null || !OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_tokenCachePath)!);

            var json = JsonSerializer.Serialize(tokenResponse, JsonContext.Default.TokenResponse);
            var jsonBytes = Encoding.UTF8.GetBytes(json);
            var encryptedData = ProtectedData.Protect(jsonBytes, null, DataProtectionScope.CurrentUser);

            File.WriteAllBytes(_tokenCachePath, encryptedData);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Failed to cache tokens: {ex.Message}");
        }
    }

    private async Task<string?> RefreshAccessToken(string refreshToken)
    {
        using var requestBody = new FormUrlEncodedContent([
            new KeyValuePair<string, string?>("client_id", ClientId),
            new KeyValuePair<string, string?>("grant_type", "refresh_token"),
            new KeyValuePair<string, string?>("refresh_token", refreshToken),
            new KeyValuePair<string, string?>("scope", GraphScope)
        ]);

        var response = await _httpClient.PostAsync(
            new Uri($"https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/token"),
            requestBody);

        var responseBody = await response.Content.ReadAsStringAsync();
        var tokenResponse = JsonSerializer.Deserialize(responseBody, JsonContext.Default.TokenResponse);

        if (tokenResponse?.AccessToken is not null)
        {
            CacheTokens(tokenResponse);
            return tokenResponse.AccessToken;
        }

        Debug.WriteLine("Failed to refresh token, falling back to full authentication.");
        return null;
    }
}
