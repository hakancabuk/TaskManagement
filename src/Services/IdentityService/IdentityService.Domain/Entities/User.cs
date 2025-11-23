namespace IdentityService.Domain.Entities;

public class User
{
	public Guid Id { get; set; } = Guid.NewGuid();

	public string FirstName { get; set; } = default!;
	public string LastName { get; set; } = default!;
	public string Email { get; set; } = default!;
	public string PasswordHash { get; set; } = default!;

	public bool IsActive { get; set; } = true;

	// Navigation
	public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
}
