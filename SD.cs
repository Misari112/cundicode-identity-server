using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using Microsoft.AspNetCore.Identity;
using System.Security.Principal;

namespace dis_identityserver
{
    public static class SD
    {
        public const string Admin = "admin";
        public const string User = "user";

        public static IEnumerable<ApiResource> ApiResources => new[]
        {
            new ApiResource("ms_general")
            {
                Scopes = new List<string> { "ms_general.read", "ms_general.write", "ms_general.delete" },
                ApiSecrets = new List<Secret> { new Secret("secret".Sha256())}
            },
            new ApiResource("ms_practice")
            {
                Scopes = new List<string> { "ms_practice.read", "ms_practice.write", "ms_practice.delete" },
                ApiSecrets = new List<Secret> { new Secret("secret".Sha256())}
            },
            new ApiResource("ms_learn")
            {
                Scopes = new List<string> { "ms_learn.read", "ms_learn.write", "ms_learn.delete" },
                ApiSecrets = new List<Secret> { new Secret("secret".Sha256())}
            }
        };
        public static IEnumerable<IdentityResource> IdentityResources =>
            new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Email(),
                new IdentityResources.Profile()
            };
        public static IEnumerable<ApiScope> ApiScopes =>
            new List<ApiScope>
            {
                new ApiScope(name: "ms_general.read",   displayName: "(general) Read your data."),
                new ApiScope(name: "ms_general.write",  displayName: "(general) Write your data."),
                new ApiScope(name: "ms_general.delete", displayName: "(general) Delete your data."),
                new ApiScope(name: "ms_practice.read",   displayName: "(practice) Read your data."),
                new ApiScope(name: "ms_practice.write",  displayName: "(practice) Write your data."),
                new ApiScope(name: "ms_practice.delete", displayName: "(practice) Delete your data."),
               new ApiScope(name: "ms_learn.read",   displayName: "(learn) Read your data."),
                new ApiScope(name: "ms_learn.write",  displayName: "(learn) Write your data."),
                new ApiScope(name: "ms_learn.delete", displayName: "(learn) Delete your data."),
            };

        public static IEnumerable<Client> Clients =>
            new List<Client>
            {
                new Client
                {
                    ClientId = "interactive",
                    ClientSecrets = { new Secret("secret".Sha256()) },

                    AllowedGrantTypes = GrantTypes.Code,
                    AllowedScopes = { 
                        "ms_general.read", 
                        "ms_practice.read", 
                        "ms_practice.write", 
                        "ms_learn.read",
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email},
                    RedirectUris={ "https://cundicode-81412.web.app/callback" },
                    PostLogoutRedirectUris={ "https://cundicode-81412.web.app/" }

                }
            };  
    }
}
