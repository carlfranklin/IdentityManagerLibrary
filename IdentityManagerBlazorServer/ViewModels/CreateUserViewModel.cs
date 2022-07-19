using System.ComponentModel.DataAnnotations;

namespace IdentityManagerBlazorServer.ViewModels
{
    public class CreateUserViewModel
    {
        [Required]
        public string? UserName { get; set; }
        [Required]
        public string? Name { get; set; }
        [Required]
        [EmailAddress]
        public string? Email { get; set; }
        [Required]
        public string? Password { get; set; }
    }
}