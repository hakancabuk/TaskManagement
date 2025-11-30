using IdentityService.Infrastructure.Data;
using IdentityService.Infrastructure.Repositories;
using IdentityService.Infrastructure.Services;
using IdentityService.Application.Interfaces;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration; // IConfiguration'ý builder üzerinden alýyoruz

// DbContext - Veritabaný baðlantýsýný doðru þekilde yapýlandýrýyoruz
builder.Services.AddDbContext<IdentityDbContext>(options =>
    options.UseSqlServer(config.GetConnectionString("IdentityConnection")));

// Repositories & services - Gerekli servisler ve repository'ler DI konteynerine ekleniyor
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IAuthService, AuthService>();

// JWT Authentication yapýlandýrmasý
var jwtSection = config.GetSection("Jwt"); // appsettings.json'dan Jwt ayarlarýný alýyoruz
var secret = jwtSection.GetValue<string>("Secret"); // Secret anahtarýný alýyoruz
var key = Encoding.UTF8.GetBytes(secret); // Secret anahtarýný byte array'e dönüþtürüyoruz

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false; // Geliþtirme aþamasýnda HTTPS gereksiz olabilir
    options.SaveToken = true; // Token'ý saklamasýný saðlýyoruz
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSection.GetValue<string>("Issuer"), // Ýssuer'ý ayarlýyoruz
        ValidAudience = jwtSection.GetValue<string>("Audience"), // Audience'ý ayarlýyoruz
        IssuerSigningKey = new SymmetricSecurityKey(key), // Ýmza doðrulama anahtarýný ayarlýyoruz
        ClockSkew = TimeSpan.Zero // Token'ýn geçerliliði ile ilgili herhangi bir tolerans olmamasý için
    };
});

// MVC ve Swagger için gerekli servislerin eklenmesi
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Swagger'ý etkinleþtiriyoruz
app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection(); // HTTPS'ye yönlendirme

// Authentication ve Authorization iþlemlerini sýrasýyla ekliyoruz
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers(); // API endpointlerini haritalýyoruz

app.Run(); // Uygulamayý çalýþtýrýyoruz
