namespace IdentityService.Domain.Entities;

public class RefreshToken
{
	public Guid Id { get; set; } = Guid.NewGuid();
	public Guid UserId { get; set; }
	public User User { get; set; } = default!;

	public string Token { get; set; } = default!;
	public DateTime Expires { get; set; }
	public DateTime Created { get; set; } = DateTime.UtcNow;
	public DateTime? Revoked { get; set; }

	public bool IsActive => Revoked == null && DateTime.UtcNow < Expires;
}
