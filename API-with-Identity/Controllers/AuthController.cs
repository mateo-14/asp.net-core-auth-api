using API_with_Identity.Models;
using API_with_Identity.Models.Responses;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Mime;
using System.Security.Claims;
using System.Text;

namespace API_with_Identity.Controllers {
    [Route("api/[controller]")]
    [ApiController]
    [Produces("application/json")]
    [Consumes("application/json")]
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

        /// <summary>
        /// Create a new account
        /// </summary>
        /// <response code="200">Returns the username</response>
        /// <response code="409">If the username is already taken</response>
        [HttpPost("register")]
        [ProducesResponseType(StatusCodes.Status409Conflict, Type = typeof(IEnumerable<IdentityError>))]
        public async Task<ActionResult<RegisterResponse>> Register(AuthDto dto) {
            var user = new IdentityUser {
                UserName = dto.UserName,
            };
            var result = await _userManager.CreateAsync(user, dto.Password);
            if (!result.Succeeded) return Conflict(result.Errors);

            return Ok(new RegisterResponse { UserName = user.UserName });
        }

        /// <summary>
        /// Login with username and password
        /// </summary>
        /// <response code="200">Returns the token</response>
        /// <response code="401">If username or password are invalid</response>
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [HttpPost("login")]
        public async Task<ActionResult<LoginResponse>> Login(AuthDto dto) {
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

            return Ok(new LoginResponse { Token = new JwtSecurityTokenHandler().WriteToken(token) });
        }

        /// <summary>
        /// Get role list
        /// </summary>
        /// <response code="200">Returns the role list</response>
        /// <response code="401">If the token is invalid</response>
        /// <response code="403">If the user doesn't have a valid role</response>
        [HttpGet("roles")]
        [Authorize(Policy = "IdentityRoleModerator")]
        public async Task<ActionResult<IEnumerable<IdentityRole>>> GetRoles() {
            return Ok(await _roleManager.Roles.ToListAsync());
        }

        /// <summary>
        /// Add a new role
        /// </summary>
        /// <response code="204">Role created</response>
        /// <response code="401">If the token is invalid</response>
        /// <response code="403">If the user doesn't have a valid role</response>
        [HttpPost("roles")]
        [Authorize(Policy = "IdentityRoleAdmin")]
        public async Task<IActionResult> AddRole(RoleDto dto) {
            var result = await _roleManager.CreateAsync(new IdentityRole(dto.Name));
            if (!result.Succeeded) return Conflict(result.Errors.First());

            return NoContent();
        }


        /// <summary>
        /// Get user list
        /// </summary>
        /// <response code="200">Returns the user list</response>
        /// <response code="401">If the token is invalid</response>
        /// <response code="403">If the user doesn't have a valid role</response>
        [HttpGet("users")]
        [Authorize(Policy = "IdentityRoleModerator")]
        public async Task<ActionResult<IEnumerable<PublicUserResponse>>> GetUsers() {
            return Ok(await _userManager.Users.Select(u => new { UserName = u.UserName, Id = u.Id }).ToListAsync());
        }

        /// <summary>
        /// Add user to a role
        /// </summary>
        /// <param name="userId">User Id</param>
        /// <response code="204">User added to the role</response>
        /// <response code="401">If the token is invalid</response>
        /// <response code="403">If the user doesn't have a valid role</response>
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

        /// <summary>
        /// Remove user from role
        /// </summary>
        /// <param name="userId">User Id</param>
        /// <response code="204">User removed from the role</response>
        /// <response code="401">If the token is invalid</response>
        /// <response code="403">If the user doesn't have a valid role</response>
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
