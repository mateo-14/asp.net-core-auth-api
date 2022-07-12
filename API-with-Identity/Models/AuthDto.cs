using System.ComponentModel.DataAnnotations;

namespace API_with_Identity.Models {
    public class AuthDto {
        [Required]
        public string UserName { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
