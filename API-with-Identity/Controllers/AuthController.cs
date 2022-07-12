using API_with_Identity.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace API_with_Identity.Controllers {
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase {
        private readonly IConfiguration _configuration;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AuthController(IConfiguration configuration, UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager) {
            _configuration = configuration;
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(AuthDto dto) {
            var user = new IdentityUser {
                UserName = dto.UserName,
            };
            var result = await _userManager.CreateAsync(user, dto.Password);
            if (!result.Succeeded) return BadRequest(result.Errors);

            return Ok(new { UserName = user.UserName });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(AuthDto dto) {
            var result = await _signInManager.PasswordSignInAsync(dto.UserName, dto.Password, false, false);
            if (!result.Succeeded) return Unauthorized();

            var user = await _userManager.FindByNameAsync(dto.UserName);
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["TOKEN_SECRET"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var claims = new[] {
                      new Claim(ClaimTypes.NameIdentifier, user.Id),
                      new Claim(ClaimTypes.Name, user.UserName),
            };

            var token = new JwtSecurityToken(
                issuer: _configuration["ISSUER"],
                audience: _configuration["AUDIENCE"],
                expires: DateTime.Now.AddDays(1),
                claims: claims,
                signingCredentials: creds
            );

            return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
        }

        [HttpGet("roles")]
        [Authorize(Policy = "IdentityRoleModerator")]
        public async Task<IActionResult> GetRoles() {
            return Ok(await _roleManager.Roles.ToListAsync());
        }

        [HttpPost("roles")]
        [Authorize(Policy = "IdentityRoleAdmin")]
        public async Task<IActionResult> AddRole(RoleDto dto) {
            var result = await _roleManager.CreateAsync(new IdentityRole(dto.Name));
            if (!result.Succeeded) return Conflict(result.Errors.First());
            
            return NoContent();
        }


        [HttpGet("users")]
        [Authorize(Policy = "IdentityRoleModerator")]
        public async Task<IActionResult> GetUsers() {
            return Ok(await _userManager.Users.Select(u => new { UserName = u.UserName, Id = u.Id }).ToListAsync());
        }


        [HttpPut("users/{userId}/roles")]
        [Authorize(Policy = "IdentityRoleAdmin")]
        public async Task<IActionResult> AddRoleToUser(RoleDto dto, string userId) {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound(new { status = 404, error = "User not found" });

            var roleExists = await _roleManager.RoleExistsAsync(dto.Name);
            if (!roleExists) return NotFound(new { status = 404, error = "Role not found" });

            await _userManager.AddToRoleAsync(user, dto.Name);
            return NoContent();
        }

        [HttpDelete("users/{userId}/roles")]
        [Authorize(Policy = "IdentityRoleAdmin")]
        public async Task<IActionResult> RemoveUserRole(RoleDto dto, string userId) {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound(new { status = 404, error = "User not found" });

            var roleExists = await _roleManager.RoleExistsAsync(dto.Name);
            if (!roleExists) return NotFound(new { status = 404, error = "Role not found" });

            await _userManager.RemoveFromRoleAsync(user, dto.Name);
            return NoContent();
        }
    }
}
