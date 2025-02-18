namespace NativeAot.Cli;

public class GraphClient(HttpClient httpClient)
{
    internal const string GraphBaseUri = "https://graph.microsoft.com/v1.0";

    private readonly HttpClient _httpClient = httpClient;

    public async Task<string> GetUserProfileAsync()
    {
        var response = await _httpClient.GetAsync(new Uri($"{GraphBaseUri}/me"));
        return await response.Content.ReadAsStringAsync();
    }
}
