using Microsoft.AspNetCore.Identity;
using User.Management.Data.Models;
using User.Management.Service.Models;
using User.Management.Service.Models.Authentication.User;
using USER.MANAGMENT.Service.Models.Authentication.Login;
using USER.MANAGMENT.Service.Models.Authentication.SignUp;

namespace User.Management.Service.Services
{
    public interface IUserManagement
    {

        Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser);

        Task<ApiResponse<List<string>>> AssignRoleToUserAsync(IEnumerable<string> roles, ApplicationUser user);

        Task<ApiResponse<OTPResponse>> GetOtpByLoginAsync(LoginModel loginModel);

        Task<ApiResponse<LoginResponse>> GetJwtTokenAsync(ApplicationUser user);

        Task<ApiResponse<LoginResponse>> LoginUserWithJWTokenAsync(string otp, string userName);

        Task<ApiResponse<LoginResponse>> RenewAccessTokenAsync(LoginResponse tokens);

    }
}
