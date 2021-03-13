using ASC.Models.BaseTypes;
using ASC.Utilities;
using ASC.Web.Models;
using ASC.Web.Models.AccountViewModels;
using ASC.Web.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ASC.Web.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<AccountController> _logger;
        private readonly IEmailSender _emailSender;
        private readonly ISMSSender _sMSSender;

        public AccountController(UserManager<ApplicationUser> userManager,
                                 SignInManager<ApplicationUser> signInManager,
                                 ILogger<AccountController> logger,
                                 IEmailSender emailSender,
                                 ISMSSender sMSSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _emailSender = emailSender;
            _sMSSender = sMSSender;
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string returnUrl = null)
        {
            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ViewData["ReturnUrl"] = returnUrl;

            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> SendCode(string returnUrl = null, bool rememberMe = false)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user is null) return View("Error");
            var userFactors = await _userManager.GetValidTwoFactorProvidersAsync(user);
            var factorOptions = userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return View(new SendCodeViewModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "ActiveOnly")]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (ModelState.IsValid)
            {
                // This does not count login failures toward account lockout
                // To enable password failures to trigger account lockout, set lockoutOnFailure:true
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user is null)
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt");
                    return View(model);
                }

                var roles = await _userManager.GetRolesAsync(user);

                var result = await _signInManager.PasswordSignInAsync(user.UserName,
                                                                      model.Password,
                                                                      model.RememberMe,
                                                                      lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    _logger.LogInformation(1, $"User {user.UserName}: {user.Email} logged in.");
                    if (roles.Select(x => x.ToLower()).Contains("admin")) return RedirectToAction("Dashboard", "Dashboard");
                    else return LocalRedirect(returnUrl ?? Url.Content("~/"));
                }
                if (result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(SendCode),
                                            new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
                }
                if (result.IsLockedOut)
                {
                    _logger.LogWarning(2, "User account locked out");
                    return View("Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt");
                    return View(model);
                }
            }
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var currentUserEmail = User.FindFirst(ClaimTypes.Email).Value;
            var currentUserName = User.FindFirst(ClaimTypes.Name).Value;

            await _signInManager.SignOutAsync();
            _logger.LogInformation(4, $"User {currentUserName}: {currentUserEmail} logged out");
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

        public IActionResult AccessDenied() => View();

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null) => code == null ? View("Error") : View();

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> InitiateResetPassword()
        {
            // Find user
            var userEmail = HttpContext.User.GetCurrenUserDetails().Email;
            var user = await _userManager.FindByEmailAsync(userEmail);

            // Generate User code
            var code = await _userManager.GeneratePasswordResetTokenAsync(user);
            var callbackUrl = Url.Action(nameof(ResetPassword),
                                         "Account",
                                         new { email = user.Email, code = code },
                                         protocol: HttpContext.Request.Scheme);

            // Send email
            await _emailSender.SendEmailAsync(userEmail,
                                              "Reset Password",
                                              $"Please reset your password by clicking here: {callbackUrl}");
            return View("ResetPasswordEmailConfirmation");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation() => View();

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model, [FromForm] string emailInput)
        {
            if (!ModelState.IsValid) return View(model);
            var user = await _userManager.FindByEmailAsync(emailInput);
            if (user is null)
            {
                // Dont reveal that user does not exist
                return RedirectToAction(nameof(AccountController.ResetPasswordConfirmation), "Account");
            }
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                if (HttpContext.User.Identity.IsAuthenticated) await _signInManager.SignOutAsync();
                return RedirectToAction(nameof(AccountController.ResetPasswordConfirmation), "Account");
            }

            AddErrors(result);
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword() => View();

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user is null || !(await _userManager.IsEmailConfirmedAsync(user)))
                {
                    // Dont reveal that user does not exist or is not confirmed
                    return View("ResetPasswordEmailConfirmation");
                }

                // Send an email with this link
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackUrl = Url.Action(nameof(ResetPassword), "Account", new { email = user.Email, code = code }, protocol: HttpContext.Request.Scheme);
                await _emailSender.SendEmailAsync(model.Email, "Reset Password", $"Please reset your password by clicking here: {callbackUrl}");
                return View("ResetPasswordEmailConfirmation");
            }

            return View(model);
        }

        [HttpGet]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> ServiceEngineers()
        {
            var serviceEngineers = await _userManager.GetUsersInRoleAsync(Roles.Engineer.ToString());

            // Hold all service engineers in session
            HttpContext.Session.SetSession("ServiceEngineers", serviceEngineers);

            return View(new ServiceEngineerViewModel
            {
                ServiceEngineers = serviceEngineers.Count > 0 ? serviceEngineers.ToList() : null,
                Registration = new ServiceEngineerRegistrationViewModel() { IsEdit = false }
            });
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ServiceEngineers(ServiceEngineerViewModel serviceEngineer)
        {
            serviceEngineer.ServiceEngineers = HttpContext.Session.GetSession<List<ApplicationUser>>("ServiceEngineers");
            if (!ModelState.IsValid) return View(serviceEngineer);

            if (serviceEngineer.Registration.IsEdit)
            {
                // Update User
                var user = await _userManager.FindByEmailAsync(serviceEngineer.Registration.Email);
                user.UserName = serviceEngineer.Registration.UserName;
                IdentityResult result = await _userManager.UpdateAsync(user);

                if (!result.Succeeded)
                {
                    result.Errors.ToList().ForEach(x => ModelState.AddModelError("", x.Description));
                    return View(serviceEngineer);
                }

                // Update Password
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                IdentityResult passwordResult = await _userManager.ResetPasswordAsync(user, token, serviceEngineer.Registration.Password);

                if (!passwordResult.Succeeded)
                {
                    passwordResult.Errors.ToList().ForEach(x => ModelState.AddModelError("", x.Description));
                    return View(serviceEngineer);
                }

                // Update Claims
                user = await _userManager.FindByEmailAsync(serviceEngineer.Registration.Email);
                var isActiveClaim = _userManager.GetClaimsAsync(user).Result.SingleOrDefault(x => x.Type == "IsActive");
                var removeClaimResult = await _userManager.RemoveClaimAsync(user,
                                                                            new Claim(isActiveClaim.Type,
                                                                                      isActiveClaim.Value));
                var addClaimResult = await _userManager.AddClaimAsync(user,
                                                                      new Claim(isActiveClaim.Type,
                                                                                serviceEngineer.Registration.IsActive.ToString()));
            }
            else
            {
                // Create User
                ApplicationUser user = new ApplicationUser
                {
                    UserName = serviceEngineer.Registration.UserName,
                    Email = serviceEngineer.Registration.Email,
                    EmailConfirmed = true
                };

                IdentityResult result = await _userManager.CreateAsync(user, serviceEngineer.Registration.Password);
                await _userManager.AddClaimAsync(user,
                                                 new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                                                           serviceEngineer.Registration.Email));
                await _userManager.AddClaimAsync(user, new Claim("IsActive", serviceEngineer.Registration.IsActive.ToString()));

                await _userManager.AddToRoleAsync(user, Roles.Engineer.ToString());

                if (!result.Succeeded)
                {
                    result.Errors.ToList().ForEach(x => ModelState.AddModelError("", x.Description));
                    return View(serviceEngineer);
                }
            }

            if (serviceEngineer.Registration.IsActive)
            {
                await _emailSender.SendEmailAsync(serviceEngineer.Registration.Email,
                                                  "Account Created/Modified",
                                                  $"Email: {serviceEngineer.Registration.Email} \n Password: {serviceEngineer.Registration.Password}");
            }
            else
            {
                await _emailSender.SendEmailAsync(serviceEngineer.Registration.Email, "Account Deactivated", $"Your account has been deactivated");
            }

            return RedirectToAction();
        }
    }
}
