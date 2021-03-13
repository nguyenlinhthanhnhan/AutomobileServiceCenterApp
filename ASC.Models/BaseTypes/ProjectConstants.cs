using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASC.Models.BaseTypes
{
    public static class ProjectConstants
    {
        // Define SECRET key
        public static readonly string SMTPMailAccount = "SMTPMailAccount";
        public static readonly string SMTPMailPassword = "SMTPMailPassword";
        public static readonly string MYOUTLOOKEMAIL = "MYOUTLOOKEMAIL";
    }

    public enum Roles
    {
        Admin, Engineer, User
    }
}
