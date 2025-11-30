using IdentityService.Application.DTOs;

namespace IdentityService.Application.Interfaces;

public interface IAuthService
{
    Task RegisterAsync(RegisterRequest request);
    Task<AuthResponse> LoginAsync(LoginRequest request, string ipAddress);
    Task<AuthResponse> RefreshTokenAsync(string token, string ipAddress);
    Task<bool> RevokeRefreshTokenAsync(string token, string ipAddress);
}
