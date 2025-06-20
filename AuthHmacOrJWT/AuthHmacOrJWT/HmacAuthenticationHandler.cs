using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace AuthHmacOrJWT
{
    public class HmacAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public HmacAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock
        )
            : base(options, logger, encoder, clock) { }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            // 1. Verificar si el header Authorization existe
            if (!Request.Headers.TryGetValue("Authorization", out var authHeader))
            {
                return AuthenticateResult.Fail("Authorization header missing");
            }

            // 2. Verificar formato HMAC
            var authHeaderVal = authHeader.ToString();
            if (string.IsNullOrEmpty(authHeaderVal) || !authHeaderVal.StartsWith("HMAC "))
            {
                return AuthenticateResult.Fail("Invalid Authorization format");
            }

            // 3. Extraer firma
            var receivedSignature = authHeaderVal.Substring("HMAC ".Length).Trim();

            // 4. Obtener otros headers necesarios
            if (!Request.Headers.TryGetValue("X-Api-Key", out var apiKey))
            {
                return AuthenticateResult.Fail("API Key missing");
            }

            if (!Request.Headers.TryGetValue("X-Timestamp", out var timestamp))
            {
                return AuthenticateResult.Fail("Timestamp missing");
            }

            // 5. Validar timestamp (5 minutos de margen)
            if (
                !DateTimeOffset.TryParse(timestamp, out var requestTime)
                || Math.Abs((DateTimeOffset.UtcNow - requestTime).TotalMinutes) > 5
            )
            {
                return AuthenticateResult.Fail("Invalid timestamp");
            }

            // 6. Obtener secreto (en producción, de base de datos)
            var secret = await GetSecretForKey(apiKey.ToString());
            if (string.IsNullOrEmpty(secret))
            {
                return AuthenticateResult.Fail("Invalid API Key");
            }

            // 7. Construir mensaje para firma
            var message = $"{Request.Method}:{Request.Path}:{timestamp}";
            var computedSignature = ComputeSignature(secret, message);

            // 8. Comparar firmas (seguro contra timing attacks)
            if (
                !CryptographicOperations.FixedTimeEquals(
                    Encoding.UTF8.GetBytes(computedSignature),
                    Encoding.UTF8.GetBytes(receivedSignature)
                )
            )
            {
                return AuthenticateResult.Fail("Invalid signature");
            }

            // 9. Crear identidad autenticada
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, apiKey),
                new Claim(ClaimTypes.Name, "ServiceClient"),
                new Claim("ServiceAuth", "true"),
            };

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }

        private async Task<string> GetSecretForKey(string apiKey)
        {
            // En producción, buscar en base de datos
            // Ejemplo simplificado:
            if (apiKey == "test-key")
                return "test-secret";

            return null;
        }

        private string ComputeSignature(string secret, string message)
        {
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
            return Convert.ToBase64String(hash);
        }
    }
}
