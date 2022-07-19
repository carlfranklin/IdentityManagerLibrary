using System.ComponentModel.DataAnnotations;

namespace IdentityManagerBlazorServer.ViewModels
{
    public class CreateRoleViewModel
    {
        [Required]
        public string? Name { get; set; }
    }
}