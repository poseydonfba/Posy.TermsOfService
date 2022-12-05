using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System;
using Posy.TermsOfService.Middlewares;

namespace Posy.TermsOfService.Areas.Identity.Pages.Account
{
    public class TermsOfServiceModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public string ReturnUrl { get; set; }
        public bool ShowAgreeButton { get; set; }

        public TermsOfServiceModel(
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }


        public IActionResult OnGet(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");
            ReturnUrl = returnUrl;

            if (_signInManager.IsSignedIn(User) && !User.HasClaim(c => c.Type == ApplicationClaimType.TermsOfService))
                ShowAgreeButton = true;

            return Page();
        }
        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            if (!ModelState.IsValid) return Page();

            var user = await _userManager.GetUserAsync(User).ConfigureAwait(false);
            if (user == null) return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            var claims = User.Claims.ToList();
            if (claims.Count == 0 || claims.Where(c => c.Type == ApplicationClaimType.TermsOfService).FirstOrDefault() == null)
            {
                var result = await _userManager.AddClaimAsync(user,
                    new Claim(ApplicationClaimType.TermsOfService,
                    string.Format("{0:MM/dd/yyyy}", DateTimeOffset.UtcNow))).ConfigureAwait(false);

                if (!result.Succeeded)
                    throw new InvalidOperationException($"Error occurred setting TermsOfService claim " +
                        $"({result}) for user with ID '{_userManager.GetUserId(User)}'.");

                await _signInManager.RefreshSignInAsync(user).ConfigureAwait(false);
            }

            returnUrl ??= Url.Content("~/");
            return LocalRedirect(returnUrl);
        }
    }
}
