using ASC.Web.Configuration;
using ASC.Web.Models;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using ASC.Models.BaseTypes;

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
            var roles = options.Value.Roles.Split(new char[] { ',', ' '}, StringSplitOptions.RemoveEmptyEntries);

            // Create roles if they don't exist
            foreach(var role in roles)
            {
                if(!await roleManager.RoleExistsAsync(role))
                {
                    ElCamino.AspNetCore.Identity.AzureTable.Model.IdentityRole storageRole = new()
                    {
                        Name = role
                    };
                    await roleManager.CreateAsync(storageRole);
                }
            }

            // Create admin if he doesn't exist
            var admin = await userManager.FindByEmailAsync(Environment.GetEnvironmentVariable(ProjectConstants.MYOUTLOOKEMAIL));
            // Uncomment if you use config on application.json
            //var admin = await userManager.FindByEmailAsync(Environment.GetEnvironmentVariable(ProjectConstants.MYOUTLOOKEMAIL));
            if(admin is null)
            {
                ApplicationUser user = new()
                {
                    UserName = options.Value.AdminName,
                    Email = Environment.GetEnvironmentVariable(ProjectConstants.MYOUTLOOKEMAIL),
                    EmailConfirmed = true,
                    LockoutEnabled = false
                };

                IdentityResult result = await userManager.CreateAsync(user, options.Value.AdminPassword);
                await userManager.AddClaimAsync(user,
                                                new System.Security.Claims.Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                                                                                 Environment.GetEnvironmentVariable(ProjectConstants.MYOUTLOOKEMAIL)));
                await userManager.AddClaimAsync(user, new System.Security.Claims.Claim("IsActive", "True"));

                // Add admin to Admin roles
                if (result.Succeeded) await userManager.AddToRoleAsync(user, Roles.Admin.ToString());
            }

            // Create a service engineer if he doesn't exist
            var engineer = await userManager.FindByEmailAsync(options.Value.EngineerEmail);
            if(engineer is null)
            {
                ApplicationUser user = new()
                {
                    UserName = options.Value.EngineerName,
                    Email = options.Value.EngineerEmail,
                    EmailConfirmed = true,
                    LockoutEnabled = false
                };

                IdentityResult result = await userManager.CreateAsync(user, options.Value.EngineerPassword);
                await userManager.AddClaimAsync(user,
                                                new System.Security.Claims.Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                                                                                 options.Value.EngineerEmail));
                await userManager.AddClaimAsync(user, new System.Security.Claims.Claim("IsActive", "True"));

                // Add service engineer to Engineer role
                if (result.Succeeded) await userManager.AddToRoleAsync(user, Roles.Engineer.ToString());
            }
        }
    }
}
