using Microsoft.AspNetCore.Authorization;

namespace API_with_Identity.Policies {
    public class IdentityRoleRequirement  : IAuthorizationRequirement{
        public string Roles { get; set; }
        public IdentityRoleRequirement(string roles) {
            Roles = roles.ToUpper();
        }
    }
}
