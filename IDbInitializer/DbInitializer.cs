using dis_identityserver.Data;
using dis_identityserver.Models;
using IdentityModel;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace dis_identityserver.IDbInitializer
{
    public class DbInitializer : IDbInitializer
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public DbInitializer(ApplicationDbContext db, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _roleManager = roleManager;
            _userManager = userManager;
        }
        public void Initialize()
        {
            if (_roleManager.FindByNameAsync(SD.Admin).Result == null)
            {
                _roleManager.CreateAsync(new IdentityRole(SD.Admin)).GetAwaiter().GetResult();
                _roleManager.CreateAsync(new IdentityRole(SD.User)).GetAwaiter().GetResult();
            }
            else { return; }

            ApplicationUser adminUser = new ApplicationUser()
            {
                UserName = "admin_dis_identityserver@gmail.com",
                Email = "admin_dis_identityserver@gmail.com",
                EmailConfirmed = true,
                PhoneNumber = "3103395050",
                Name = "Admin",
            };

            _userManager.CreateAsync(adminUser, "Admin123*").GetAwaiter().GetResult();
            _userManager.AddToRoleAsync(adminUser, SD.Admin).GetAwaiter().GetResult();

            var temp1 = _userManager.AddClaimsAsync(adminUser, new Claim[] {
                new Claim(JwtClaimTypes.Name,adminUser.Name),
                new Claim(JwtClaimTypes.Role,SD.Admin),
            }).Result;

            ApplicationUser user = new()
            {
                UserName = "user@gmail.com",
                Email = "user@gmail.com",
                EmailConfirmed = true,
                PhoneNumber = "1111111111",
                Name = "Ben User",
            };

            _userManager.CreateAsync(user, "Admin123*").GetAwaiter().GetResult();
            _userManager.AddToRoleAsync(user, SD.User).GetAwaiter().GetResult();

            var temp2 = _userManager.AddClaimsAsync(user, new Claim[] {
                new Claim(JwtClaimTypes.Name,user.Name),
                new Claim(JwtClaimTypes.Role,SD.User),
            }).Result;
        }
    }
}
