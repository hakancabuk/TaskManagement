using IdentityService.Application.DTOs;
using IdentityService.Application.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace IdentityService.Api.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class AuthController : ControllerBase
{
	private readonly IAuthService _auth;
	public AuthController(IAuthService auth) => _auth = auth;

	[HttpPost("register")]
	public async Task<IActionResult> Register([FromBody] RegisterRequest req)
	{
		await _auth.RegisterAsync(req);
		return Ok(new { message = "Registration successful" });
	}

	[HttpPost("login")]
	public async Task<IActionResult> Login([FromBody] LoginRequest req)
	{
		var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
		var res = await _auth.LoginAsync(req, ip);
		return Ok(res);
	}

	[HttpPost("refresh")]
	public async Task<IActionResult> Refresh([FromBody] string refreshToken)
	{
		var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
		var res = await _auth.RefreshTokenAsync(refreshToken, ip);
		return Ok(res);
	}

	[HttpPost("revoke")]
	public async Task<IActionResult> Revoke([FromBody] string refreshToken)
	{
		var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
		var res = await _auth.RevokeRefreshTokenAsync(refreshToken, ip);
		return Ok(new { revoked = res });
	}
}
