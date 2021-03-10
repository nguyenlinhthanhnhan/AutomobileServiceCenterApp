using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ASC.Web.Services
{
    public interface ISMSSender
    {
        Task SendSMSAsync(string number, string message);
    }
}
