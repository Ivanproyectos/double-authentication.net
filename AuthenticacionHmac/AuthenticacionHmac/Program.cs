// See https://aka.ms/new-console-template for more information
using System.Security.Cryptography;
using System.Text;

var apiKey = "test-key";
var secret = "test-secret";
var timestamp = DateTime.UtcNow.ToString("o");
var endpoint = "/authtest/hmac-only";
var method = "GET";

try
{
    // Calcular firma
    var message = $"{method}:{endpoint}:{timestamp}";
    var signature = ComputeHmac(secret, message);
    // Crear cliente HTTP
    using var client = new HttpClient();
    client.DefaultRequestHeaders.Add("Authorization", $"HMAC {signature}");
    client.DefaultRequestHeaders.Add("X-Api-Key", apiKey);
    client.DefaultRequestHeaders.Add("X-Timestamp", timestamp);

    var response = await client.GetAsync($"https://localhost:7099{endpoint}");
    Console.WriteLine(await response.Content.ReadAsStringAsync());

    Console.ReadKey();

    string ComputeHmac(string key, string data)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
        return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(data)));
    }
}
catch (Exception ex)
{
    Console.WriteLine(ex);
}
