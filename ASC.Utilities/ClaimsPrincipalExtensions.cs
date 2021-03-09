using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace ASC.Utilities
{
    public class CurrentUser
    {
        public string Name { get; set; }
        public string Email { get; set; }
        public bool IsActive { get; set; }
        public string[] Roles { get; set; }
    }

    public static class ClaimsPrincipalExtensions
    {
        public static CurrentUser GetCurrenUserDetails(this ClaimsPrincipal claimsPrincipal)
        {
            //if (!claimsPrincipal.Claims.Any()) return null;

            return new CurrentUser
            {
                Name = claimsPrincipal.Claims.Where(x => x.Type == ClaimTypes.Name)
                                             .Select(x => x.Value)
                                             .Take(1)
                                             .SingleOrDefault(),
                Email = claimsPrincipal.Claims.Where(x => x.Type == ClaimTypes.Email)
                                              .Select(x => x.Value)
                                              .Take(1)
                                              .SingleOrDefault(),
                Roles = claimsPrincipal.Claims.Where(x => x.Type == ClaimTypes.Role)
                                              .Select(x => x.Value)
                                              .ToArray(),
                IsActive = bool.Parse(claimsPrincipal.Claims.Where(x => x.Type == "IsActive")
                                                            .Select(x => x.Value)
                                                            .Take(1)
                                                            .SingleOrDefault())
            };
        }
    }
}
