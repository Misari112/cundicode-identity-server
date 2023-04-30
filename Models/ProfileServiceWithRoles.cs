using dis_identityserver.Models;
using Duende.IdentityServer.AspNetIdentity;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using IdentityModel;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

public class ProfileServiceWithRoles : IProfileService
{
    private readonly UserManager<ApplicationUser> _userManager;

    public ProfileServiceWithRoles(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task GetProfileDataAsync(ProfileDataRequestContext context)
    {
        var subjectId = context.Subject?.GetSubjectId();
        if (subjectId == null)
        {
            throw new ArgumentException("Invalid subject identifier");
        }

        var user = await _userManager.FindByIdAsync(subjectId);
        if (user == null)
        {
            throw new ArgumentException("Invalid subject identifier");
        }

        var claims = new List<Claim>
        {
            new Claim(JwtClaimTypes.Name, user.Name),
            new Claim(JwtClaimTypes.Subject, user.Id),
            new Claim(JwtClaimTypes.PreferredUserName, user.UserName),
            new Claim(JwtClaimTypes.Email, user.Email),
        };

        var roles = await _userManager.GetRolesAsync(user);
        foreach (var role in roles)
        {
            claims.Add(new Claim(JwtClaimTypes.Role, role));
        }

        context.IssuedClaims = claims;
    }

    public async Task IsActiveAsync(IsActiveContext context)
    {
        var subjectId = context.Subject?.GetSubjectId();
        if (subjectId == null)
        {
            throw new ArgumentException("Invalid subject identifier");
        }

        var user = await _userManager.FindByIdAsync(subjectId);
        context.IsActive = user != null;
    }
}
