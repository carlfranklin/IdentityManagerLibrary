using System.ComponentModel.DataAnnotations;

namespace IdentityManagerBlazorServer.ViewModels
{
    public class EditUserViewModel
    {
        [Required]
        [EmailAddress]
        public string? Email { get; set; }
    }
}