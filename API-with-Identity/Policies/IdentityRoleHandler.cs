using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace API_with_Identity.Policies {
    public class IdentityRoleHandler : AuthorizationHandler<IdentityRoleRequirement> {
        private UserManager<IdentityUser> _userManager;
        public IdentityRoleHandler(UserManager<IdentityUser> userManager) {
            _userManager = userManager;
        }

        protected override async Task<Task> HandleRequirementAsync(AuthorizationHandlerContext context, IdentityRoleRequirement requirement) {
            var user = await _userManager.GetUserAsync(context.User);
            if (user == null) return Task.CompletedTask;

            var roles = requirement.Roles.Split(",").ToList();
            var userRoles = await _userManager.GetRolesAsync(user);
            if (!userRoles.Any(r => roles.Contains(r.ToUpper()))) return Task.CompletedTask;

            context.Succeed(requirement);
            return Task.CompletedTask;
        }
    }
}
