using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Password_Manager.Data;
using Password_Manager.Helpers;
using Password_Manager.Repositories;
using System.Text;

var builder = WebApplication.CreateBuilder(args);


// Add authentication services
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = false,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
        };

        options.RequireHttpsMetadata = false;
    });

builder.Services.AddAuthorization();

// ✅ Configure CORS to Allow Frontend Access
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAllOrigins",
        policy => policy
            .AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader()
    );
});

// ✅ Configure Database Connection (if using a database)
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// ✅ Configure Identity (if storing user data)
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// ✅ Register JWT Authentication Helper
builder.Services.AddSingleton<JwtHelper>();

// ✅ Add Controllers
builder.Services.AddControllers();

// ✅ Register Swagger for API Documentation
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Password Manager API", Version = "v1" });
});
// Program.cs or Startup.cs
builder.Services.AddSingleton<PasswordRepository>();

// ✅ Build the App
var app = builder.Build();



// ✅ Enable CORS Globally
app.UseCors("AllowAllOrigins");

// ✅ Enable Swagger in Development
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Password Manager API v1");
        c.RoutePrefix = "swagger"; // Load Swagger at `localhost:7277/`
    });
}

app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();


// ✅ Run the App
app.Run();

