using BCrypt.Net;
using IdentityService.Application.DTOs;
using IdentityService.Application.Interfaces;
using IdentityService.Domain.Entities;
using IdentityService.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace IdentityService.Infrastructure.Services;

public class AuthService : IAuthService
{
    private readonly IUserRepository _userRepository;
    private readonly IdentityDbContext _db;
    private readonly IConfiguration _config;

    public AuthService(IUserRepository userRepository, IdentityDbContext db, IConfiguration config)
    {
        _userRepository = userRepository;
        _db = db;
        _config = config;
    }

    public async Task RegisterAsync(RegisterRequest request)
    {
        var exists = await _userRepository.GetByEmailAsync(request.Email);
        if (exists != null) throw new InvalidOperationException("Email already registered.");

        var user = new User
        {
            FirstName = request.FirstName,
            LastName = request.LastName,
            Email = request.Email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
            IsActive = true
        };

        await _userRepository.AddAsync(user);

        // Optionally assign default role
        var role = await _db.Roles.FirstOrDefaultAsync(r => r.Name == "Member");
        if (role == null)
        {
            role = new Role { Name = "Member" };
            await _db.Roles.AddAsync(role);
            await _db.SaveChangesAsync();
        }

        _db.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = role.Id });
        await _db.SaveChangesAsync();
    }

    public async Task<AuthResponse> LoginAsync(LoginRequest request, string ipAddress)
    {
        var user = await _userRepository.GetByEmailAsync(request.Email);
        if (user == null) throw new UnauthorizedAccessException("Invalid credentials");

        if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            throw new UnauthorizedAccessException("Invalid credentials");

        var roles = (await _userRepository.GetUserRolesAsync(user.Id)).ToArray();

        var accessToken = GenerateJwtToken(user, roles);
        var refreshToken = GenerateRefreshToken(ipAddress);

        refreshToken.UserId = user.Id;
        await _db.RefreshTokens.AddAsync(refreshToken);
        await _db.SaveChangesAsync();

        return new AuthResponse
        {
            AccessToken = accessToken.Token,
            AccessTokenExpires = accessToken.Expires,
            RefreshToken = refreshToken.Token
        };
    }

    public async Task<AuthResponse> RefreshTokenAsync(string token, string ipAddress)
    {
        var rt = await _db.RefreshTokens.Include(r => r.User).FirstOrDefaultAsync(r => r.Token == token);
        if (rt == null || !rt.IsActive) throw new SecurityTokenException("Invalid token");

        // revoke current and issue new
        rt.Revoked = DateTime.UtcNow;
        _db.RefreshTokens.Update(rt);

        var roles = (await _userRepository.GetUserRolesAsync(rt.UserId)).ToArray();
        var newAccess = GenerateJwtToken(rt.User, roles);
        var newRefresh = GenerateRefreshToken(ipAddress);
        newRefresh.UserId = rt.UserId;

        await _db.RefreshTokens.AddAsync(newRefresh);
        await _db.SaveChangesAsync();

        return new AuthResponse
        {
            AccessToken = newAccess.Token,
            AccessTokenExpires = newAccess.Expires,
            RefreshToken = newRefresh.Token
        };
    }

    public async Task<bool> RevokeRefreshTokenAsync(string token, string ipAddress)
    {
        var rt = await _db.RefreshTokens.FirstOrDefaultAsync(r => r.Token == token);
        if (rt == null || !rt.IsActive) return false;
        rt.Revoked = DateTime.UtcNow;
        _db.RefreshTokens.Update(rt);
        await _db.SaveChangesAsync();
        return true;
    }

    // helper methods
    private (string Token, DateTime Expires) GenerateJwtToken(User user, string[] roles)
    {
        var jwt = _config.GetSection("Jwt");
        var secret = jwt.GetValue<string>("Secret");
        var issuer = jwt.GetValue<string>("Issuer");
        var audience = jwt.GetValue<string>("Audience");
        var minutes = jwt.GetValue<int>("AccessTokenExpirationMinutes");

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}")
        };

        foreach (var role in roles)
            claims.Add(new Claim(ClaimTypes.Role, role));

        var expires = DateTime.UtcNow.AddMinutes(minutes);

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: expires,
            signingCredentials: creds);

        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
        return (tokenString, expires);
    }

    private RefreshToken GenerateRefreshToken(string ipAddress)
    {
        return new RefreshToken
        {
            Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
            Expires = DateTime.UtcNow.AddDays(_config.GetValue<int>("Jwt:RefreshTokenExpirationDays")),
            Created = DateTime.UtcNow
        };
    }
}
