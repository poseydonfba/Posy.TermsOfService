using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace Posy.TermsOfService.Middlewares
{
    public class TermsOfServiceMiddleware
    {
        private readonly RequestDelegate _next;
        public TermsOfServiceMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (context.User.Identity.IsAuthenticated &&
                context.Request.Path != new PathString("/identity/account/termsofservice") &&
                context.Request.Path != new PathString("/identity/account/logout") &&
                !((ClaimsIdentity)context.User.Identity).HasClaim(c => c.Type == ApplicationClaimType.TermsOfService))
            {
                var returnUrl = context.Request.Path.Value == "/" ? "" : "?returnUrl=" +
                    HttpUtility.UrlEncode(context.Request.Path.Value);
                context.Response.Redirect("/identity/account/termsofservice" + returnUrl);
            }
            await _next(context).ConfigureAwait(true);
        }
    }

    public static class TermsOfServiceMiddlewareExtensions
    {
        public static IApplicationBuilder UseTermsOfService(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<TermsOfServiceMiddleware>();
        }
    }
}
