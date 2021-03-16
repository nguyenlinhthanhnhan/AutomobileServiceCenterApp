using ASC.Utilities;
using ASC.Web.Configuration;
using ASC.Web.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace ASC.Web.Controllers
{
    public class HomeController : AnonymousController
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IOptions<ApplicationSettings> _settings;

        public HomeController(ILogger<HomeController> logger, IOptions<ApplicationSettings> settings)
        {
            _logger = logger;
            _settings = settings;
        }

        public IActionResult Index()
        {
            // Set Session
            HttpContext.Session.SetSession("Test", _settings.Value);
            // Get Session
            var settings = HttpContext.Session.GetSession<ApplicationSettings>("Test");
            // Usage of IOptions
            ViewBag.Title = _settings.Value.ApplicationTitle;
            return View();
        }

        public IActionResult Contact() => View();

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error(string id)
        {
            if (id is "404") return View("NotFound");
            if (id is "401" && User.Identity.IsAuthenticated) return View("AccessDenied");
            else return RedirectToAction("Login", "Account");
        }
    }
}
