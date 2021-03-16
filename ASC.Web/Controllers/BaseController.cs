using ASC.Web.Filters;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ASC.Web.Controllers
{
    [Authorize]
    [UserActivityFilter]
    public class BaseController : Controller
    {
    }
}
