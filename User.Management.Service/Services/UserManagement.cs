using Microsoft.AspNetCore.Identity;
using User.Management.Service.Models;
using USER.MANAGMENT.Service.Models.Authentication.SignUp;
using Microsoft.Extensions.Configuration;
using User.Management.Service.Models.Authentication.User;
using USER.MANAGMENT.Service.Models.Authentication.Login;
using Microsoft.AspNetCore.Http;

namespace User.Management.Service.Services
{
    public class UserManagement : IUserManagement
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        
        public UserManagement(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager, 
            SignInManager<IdentityUser> signInManager, 
            IEmailService emailService, 
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;            
        }

        public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(IEnumerable<string> roles, IdentityUser user)
        {
            var assignedRole = new List<string>();
            foreach (var role in roles) 
            {
                if (await _roleManager.RoleExistsAsync(role))
                {
                    if (!await _userManager.IsInRoleAsync(user, role))
                    {
                        await _userManager.AddToRoleAsync(user, role);
                        assignedRole.Add(role);
                    }                    
                }
            }
            return new ApiResponse<List<string>> { IsSuccess = true, StatusCode = 200,
                 Message = "El rol ha sido asignado correctamente.", Response=assignedRole };
        }

        public async Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser)
        {
            //Verificar si el Usuario existe}
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
            {
                return new ApiResponse<CreateUserResponse> { IsSuccess = false, StatusCode = 403, Message = "User already exists!" };
            }

            //Agregar Usuario a la base de datos.
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.Username,
                TwoFactorEnabled = true
            };
            var result = await _userManager.CreateAsync(user, registerUser.Password);
            if (result.Succeeded)
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                return new ApiResponse<CreateUserResponse> {Response= new CreateUserResponse() {User=user, Token=token}, IsSuccess = true, StatusCode = 201, Message = "El usuario se ha creado correctamente." };
            }
            else
            {
                return new ApiResponse<CreateUserResponse> { IsSuccess = false, StatusCode = 500, Message = "El usuario no ha sido creado." };
            }
        }

        public async Task<ApiResponse<OTPResponse>> GetOtpByLoginAsync(LoginModel loginModel)
        {
            var user = await _userManager.FindByNameAsync(loginModel.Username);
            if(user != null)
            {
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);
                if (user.TwoFactorEnabled)
                {
                    var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                    return new ApiResponse<OTPResponse>
                    {
                        Response = new OTPResponse()
                        {
                            User = user,
                            Token = token,
                            IsTwoFactorEnable = user.TwoFactorEnabled
                        },
                        IsSuccess = true,
                        StatusCode = 200,
                        Message = $"El OTP se ha enviado al email {user.Email}."
                    };

                }
                else
                {
                    return new ApiResponse<OTPResponse>
                    {
                        Response = new OTPResponse()
                        {
                            User = user,
                            Token = string.Empty,
                            IsTwoFactorEnable = user.TwoFactorEnabled
                        },
                        IsSuccess = true,
                        StatusCode = 200,
                        Message = $"La autenticacion de 2 pasos no esta habilitada."
                    };
                }
            }
            else
            {
                return new ApiResponse<OTPResponse>
                {                    
                    IsSuccess = false,
                    StatusCode = 404,
                    Message = $"El usuario no existe."
                };
            }
           
            

        }
    }
}