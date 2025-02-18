using System.Text.Json.Serialization;

namespace NativeAot.Cli;

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(TokenResponse))]
internal sealed partial class JsonContext : JsonSerializerContext;
