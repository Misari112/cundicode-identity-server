using dis_identityserver.Models;
using IdentityModel;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace dis_identityserver.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class RegisterController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RegisterController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        [HttpPost]
        public async Task<IActionResult> PostAsync([FromBody] RegisterRequest registerRequest)
        {
            // Verificar si los datos son válidos
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Verificar si el rol existe, si no, crearlo
            if (await _roleManager.FindByNameAsync(SD.User) == null)
            {
                await _roleManager.CreateAsync(new IdentityRole(SD.User));
            }

            // Crear un nuevo usuario
            var newUser = new ApplicationUser
            {
                UserName = registerRequest.UserName,
                Email = registerRequest.Email,
                PhoneNumber = registerRequest.PhoneNumber,
                Name = registerRequest.Name,
                EmailConfirmed = true // Suponiendo que la confirmación de correo no es necesaria
            };

            // Agregar el usuario a la tabla de usuarios de ASP.NET Identity
            var result = await _userManager.CreateAsync(newUser, registerRequest.Password);

            // Verificar si la operación fue exitosa
            if (result.Succeeded)
            {
                // Agregar el usuario al rol de usuarios
                await _userManager.AddToRoleAsync(newUser, SD.User);

                // Agregar reclamaciones al usuario
                var temp = await _userManager.AddClaimsAsync(newUser, new Claim[] {
                    new Claim(JwtClaimTypes.Name, newUser.Name),
                    new Claim(JwtClaimTypes.Role, SD.User)
                });

                return Ok();
            }
            else
            {
                return BadRequest(result.Errors);
            }
        }
    }
}
