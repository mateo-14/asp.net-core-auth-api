using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace API_with_Identity {
    public class AppDbContext : IdentityDbContext<IdentityUser> {
        public AppDbContext(DbContextOptions options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder builder) {
            base.OnModelCreating(builder);

            var ADMIN_ROLE_ID = "868756bc-d484-45bd-9c8f-e0d594677bef";
            var ADMIN_ID = "c3660a50-3ceb-47e6-ac3c-976ab5400b2c";

            // Seed admin role
            builder.Entity<IdentityRole>().HasData(new IdentityRole {
                Id = ADMIN_ROLE_ID,
                Name = "Admin",
                NormalizedName = "ADMIN",
                ConcurrencyStamp = ADMIN_ROLE_ID
            });


            // Seed admin user
            var admin = new IdentityUser {
                Id = ADMIN_ID,
                UserName = "admin",
                NormalizedUserName = "ADMIN"
            };

            var passwordHasher = new PasswordHasher<IdentityUser>();
            admin.PasswordHash = passwordHasher.HashPassword(admin, "admin");

            builder.Entity<IdentityUser>().HasData(admin);

            // Add admin role to admin user
            builder.Entity<IdentityUserRole<string>>().HasData(new IdentityUserRole<string> {
                RoleId = ADMIN_ROLE_ID,
                UserId = ADMIN_ID
            });

        }
    }
}
