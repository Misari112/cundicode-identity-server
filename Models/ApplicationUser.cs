using Microsoft.AspNetCore.Identity;

namespace dis_identityserver.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string Name { get; set; }
    }
}
