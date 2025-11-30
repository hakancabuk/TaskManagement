namespace IdentityService.Application.DTOs;

public class AuthResponse
{
    public string AccessToken { get; set; } = default!;
    public string RefreshToken { get; set; } = default!;
    public DateTime AccessTokenExpires { get; set; }
}
