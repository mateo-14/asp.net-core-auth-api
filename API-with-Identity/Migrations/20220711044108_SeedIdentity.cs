using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace API_with_Identity.Migrations
{
    public partial class SeedIdentity : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "868756bc-d484-45bd-9c8f-e0d594677bef", "868756bc-d484-45bd-9c8f-e0d594677bef", "Admin", "ADMIN" });

            migrationBuilder.InsertData(
                table: "AspNetUsers",
                columns: new[] { "Id", "AccessFailedCount", "ConcurrencyStamp", "Email", "EmailConfirmed", "LockoutEnabled", "LockoutEnd", "NormalizedEmail", "NormalizedUserName", "PasswordHash", "PhoneNumber", "PhoneNumberConfirmed", "SecurityStamp", "TwoFactorEnabled", "UserName" },
                values: new object[] { "c3660a50-3ceb-47e6-ac3c-976ab5400b2c", 0, "7f9cec77-c603-4c9a-a567-7dbb42da2076", null, false, false, null, null, "ADMIN", "AQAAAAEAACcQAAAAELpDmBW40Ar6xRlWvBVKUJ4b1W8rh6pPEe1xeoDdPwPTpC3LIGasxPifFx5kpcyT1g==", null, false, "8b685a79-1be2-4ead-bee7-2b8978fb1bbc", false, "admin" });

            migrationBuilder.InsertData(
                table: "AspNetUserRoles",
                columns: new[] { "RoleId", "UserId" },
                values: new object[] { "868756bc-d484-45bd-9c8f-e0d594677bef", "c3660a50-3ceb-47e6-ac3c-976ab5400b2c" });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetUserRoles",
                keyColumns: new[] { "RoleId", "UserId" },
                keyValues: new object[] { "868756bc-d484-45bd-9c8f-e0d594677bef", "c3660a50-3ceb-47e6-ac3c-976ab5400b2c" });

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "868756bc-d484-45bd-9c8f-e0d594677bef");

            migrationBuilder.DeleteData(
                table: "AspNetUsers",
                keyColumn: "Id",
                keyValue: "c3660a50-3ceb-47e6-ac3c-976ab5400b2c");
        }
    }
}
