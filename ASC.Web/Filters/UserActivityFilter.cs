using ASC.Business.Interfaces;
using ASC.Utilities;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ASC.Web.Filters
{
    public class UserActivityFilter:ActionFilterAttribute
    {
        public override async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            await next();
            var logger = context.HttpContext.RequestServices.GetService(typeof(ILogDataOperations)) as ILogDataOperations;
            await logger.CreateUserActivityAsync(context.HttpContext.User.GetCurrenUserDetails().Email,
                                                 context.HttpContext.Request.Path);
        }
    }
}
