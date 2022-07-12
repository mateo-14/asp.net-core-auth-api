using System.ComponentModel.DataAnnotations;

namespace API_with_Identity.Models {
    public class RoleDto {

        [Required]
        public string Name { get; set; }
    }
}
