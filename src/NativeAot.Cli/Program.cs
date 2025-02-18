using Microsoft.Extensions.DependencyInjection;
using NativeAot.Cli;

var serviceCollection = new ServiceCollection();

serviceCollection
    .AddSingleton<IAccessTokenProvider, AuthenticationBroker>()
    .AddSingleton<AuthenticationHandler>()
    .AddHttpClient<GraphClient>(client => { client.BaseAddress = new Uri(GraphClient.GraphBaseUri); })
    .AddHttpMessageHandler<AuthenticationHandler>();

var services = serviceCollection.BuildServiceProvider();

var graphClient = services.GetRequiredService<GraphClient>();
var userProfile = await graphClient.GetUserProfileAsync();

Console.WriteLine(userProfile);
