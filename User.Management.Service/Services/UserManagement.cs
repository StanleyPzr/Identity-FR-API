using Microsoft.AspNetCore.Identity;
using User.Management.Service.Models;
using USER.MANAGMENT.Service.Models.Authentication.SignUp;
using Microsoft.Extensions.Configuration;
using User.Management.Service.Models.Authentication.User;

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
    }
}