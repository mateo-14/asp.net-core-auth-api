using API_with_Identity;
using API_with_Identity.Policies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
    options.SwaggerDoc("v1",
        new OpenApiInfo {
            Version = "v1",
            Title = " ASP.NET Core Auth API",
            Description = "Add JWT authentication and role based authorization with ASP.NET Core Identity.",
            Contact = new OpenApiContact { Name = "My web", Url = new Uri("https://mateoledesma.vercel.app") },
        }
    )
);

builder.Services.AddDbContext<AppDbContext>(options => options.UseNpgsql("Host=localhost:5432;Username=postgres;Password=admin;Database=asp_auth"));
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>();


builder.Services.AddAuthentication(options => {
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options => {
    options.TokenValidationParameters = new TokenValidationParameters {
        ValidateIssuerSigningKey = true,
        ValidAudience = builder.Configuration["AUDIENCE"],
        ValidateAudience = true,
        ValidIssuer = builder.Configuration["ISSUER"],
        ValidateIssuer = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["TOKEN_SECRET"]))
    };
});

builder.Services.AddAuthorization(options => {
    options.AddPolicy("IdentityRoleAdmin", policy =>
       policy.RequireAuthenticatedUser().AddRequirements(new IdentityRoleRequirement("Admin"))
   );
    options.AddPolicy("IdentityRoleModerator", policy =>
        policy.RequireAuthenticatedUser().AddRequirements(new IdentityRoleRequirement("Admin,Moderator"))
    );
});

builder.Services.AddTransient<IAuthorizationHandler, IdentityRoleHandler>();

var app = builder.Build();

using (var scope = app.Services.CreateScope()) {
    var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    context.Database.Migrate();
}

app.UseSwagger();
app.UseSwaggerUI(options => {
    options.SwaggerEndpoint("/swagger/v1/swagger.json", "V1");
    options.RoutePrefix = "";
});

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
