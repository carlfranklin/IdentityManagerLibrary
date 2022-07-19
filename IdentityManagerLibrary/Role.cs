using System.Collections.Generic;

namespace IdentityManagerLibrary
{
    /// <summary>
    /// Role model.
    /// </summary>    
    public class Role
    {
        public string? Id { get; set; }
        public string? Name { get; set; }
        public IEnumerable<KeyValuePair<string, string>>? Claims { get; set; }
    }
}