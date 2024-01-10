
using User.Management.Data.Models;

namespace User.Management.Service.Models.Authentication.User
{
    public class OTPResponse
    {

        public string Token { get; set; } = null!;
        public bool IsTwoFactorEnable { get; set; }
        public ApplicationUser User { get; set; } = null!;
    }
}
