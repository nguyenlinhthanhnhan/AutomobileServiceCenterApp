using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ASC.Web.Models.AccountViewModels
{
    public class CustomersViewModel
    {
        public List<ApplicationUser> Customers { get; set; }
        public CustomerRegistrationViewModel Registration { get; set; }
    }
}
