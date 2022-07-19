using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;

namespace IdentityManagerLibrary
{
    /// <summary>
    /// Custom implementation of IdentityUser.
    /// </summary>
    public class ApplicationUser : IdentityUser
    {
        public virtual ICollection<IdentityUserRole<string>>? Roles { get; set; }
        public virtual ICollection<IdentityUserClaim<string>>? Claims { get; set; }
    }
}