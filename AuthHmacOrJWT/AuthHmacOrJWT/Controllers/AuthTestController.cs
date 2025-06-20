using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthHmacOrJWT.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthTestController : ControllerBase
    {
        [HttpGet("public")]
        public IActionResult PublicEndpoint() => Ok(new { message = "Acceso público" });

        [HttpGet("jwt-only")]
        [Authorize(Policy = "JWT")]
        public IActionResult JwtEndpoint() =>
            Ok(new { message = "Acceso JWT", user = User.Identity.Name });

        [HttpGet("hmac-only")]
        [Authorize(Policy = "HMAC")]
        public IActionResult HmacEndpoint() =>
            Ok(
                new
                {
                    message = "Acceso HMAC",
                    service = User.FindFirstValue(ClaimTypes.NameIdentifier),
                }
            );

        [HttpGet("any-auth")]
        [Authorize(AuthenticationSchemes = "Bearer,HMAC")]
        public IActionResult AnyAuthEndpoint()
        {
            var authType = User.Identity.AuthenticationType;
            return Ok(new { message = $"Acceso con {authType}", identity = User.Identity.Name });
        }
    }
}
