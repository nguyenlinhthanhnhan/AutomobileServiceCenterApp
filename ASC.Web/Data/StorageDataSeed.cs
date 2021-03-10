using ASC.Web.Configuration;
using ASC.Web.Models;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace ASC.Web.Data
{
    public interface IIdentitySeed
    {
        Task Seed(UserManager<ApplicationUser> userManager,
                  RoleManager<ElCamino.AspNetCore.Identity.AzureTable.Model.IdentityRole> roleManager,
                  IOptions<ApplicationSettings> options);
    }
    public class IdentitySeed : IIdentitySeed
    {
        public async Task Seed(UserManager<ApplicationUser> userManager,
                         RoleManager<ElCamino.AspNetCore.Identity.AzureTable.Model.IdentityRole> roleManager,
                         IOptions<ApplicationSettings> options)
        {
            // Get All comma-separated roles
            var roles = options.Value.Roles.Split(new char[] { ',' });

            // Create roles if they don't exist
            foreach(var role in roles)
            {
                if(!await roleManager.RoleExistsAsync(role))
                {
                    ElCamino.AspNetCore.Identity.AzureTable.Model.IdentityRole storageRole = new()
                    {
                        Name = role
                    };
                    IdentityResult roleResult = await roleManager.CreateAsync(storageRole);
                }
            }

            // Create admin if he doesn't exist
            var admin = await userManager.FindByEmailAsync(Environment.GetEnvironmentVariable("MYOUTLOOKEMAIL"));
            // Uncomment if you use config on application.json
            //var admin = await userManager.FindByEmailAsync(Environment.GetEnvironmentVariable("MYOUTLOOKEMAIL"));
            if(admin is null)
            {
                ApplicationUser user = new()
                {
                    UserName = options.Value.AdminName,
                    Email = Environment.GetEnvironmentVariable("MYOUTLOOKEMAIL"),
                    EmailConfirmed = true
                };

                IdentityResult result = await userManager.CreateAsync(user, options.Value.AdminPassword);
                await userManager.AddClaimAsync(user,
                                                new System.Security.Claims.Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                                                                                 Environment.GetEnvironmentVariable("MYOUTLOOKEMAIL")));
                await userManager.AddClaimAsync(user, new System.Security.Claims.Claim("IsActive", "True"));

                // Add admin to Admin roles
                if (result.Succeeded) await userManager.AddToRoleAsync(user, "Admin");
            }
        }
    }
}
