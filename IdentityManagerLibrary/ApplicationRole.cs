using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;

namespace IdentityManagerLibrary
{
    /// <summary>
    /// Custom implementation of IdentityRole.
    /// </summary>
    public class ApplicationRole : IdentityRole
    {
        public ApplicationRole() { }

        public ApplicationRole(string roleName) : base(roleName) { }

        public virtual ICollection<IdentityRoleClaim<string>>? Claims { get; set; }
    }
}