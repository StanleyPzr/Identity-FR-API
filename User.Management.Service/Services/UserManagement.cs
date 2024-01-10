using Microsoft.AspNetCore.Identity;
using User.Management.Service.Models;
using USER.MANAGMENT.Service.Models.Authentication.SignUp;
using Microsoft.Extensions.Configuration;
using User.Management.Service.Models.Authentication.User;
using USER.MANAGMENT.Service.Models.Authentication.Login;
using User.Management.Data.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace User.Management.Service.Services
{
    public class UserManagement : IUserManagement
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        
        public UserManagement(UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager, 
            SignInManager<ApplicationUser> signInManager, 
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(IEnumerable<string> roles, ApplicationUser user)
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
            ApplicationUser user = new()
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

        public async Task<ApiResponse<LoginResponse>> GetJwtTokenAsync(ApplicationUser user)
        {
            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };
            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            var jwtToken = GetToken(authClaims); //Token de acceso. 
            var refreshToken = GenerateRefreshToken();
            _ = int.TryParse(_configuration["JWT:RefreshTokenValidity"], out int refreshTokenValidity);

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(refreshTokenValidity);

            await _userManager.UpdateAsync(user);

            return new ApiResponse<LoginResponse>
            {
                Response = new LoginResponse()
            { 
                    AccessToken = new TokenType()
                    {
                          Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    ExpiryTokenDate = jwtToken.ValidTo
                    },

                    RefreshToken=new TokenType()
                    {
                        Token = user.RefreshToken,
                        ExpiryTokenDate = (DateTime)user.RefreshTokenExpiry
                    }
            },                
                IsSuccess = true,
                StatusCode = 200,
                Message = $"Token Creado"                
            };
        }
        
        public async Task<ApiResponse<LoginResponse>> LoginUserWithJWTokenAsync(string otp, string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            var signIn = await _signInManager.TwoFactorSignInAsync("Email", otp, false, false);
            if (signIn.Succeeded)
            {
                if (user != null)
                {                    
                    return await GetJwtTokenAsync(user);
                }
            }
            return new ApiResponse<LoginResponse>
            {
                Response = new LoginResponse()
                {

                },
                IsSuccess = true,
                StatusCode = 400,
                Message = $"OTP Invalido"
            };
        }

        public async Task<ApiResponse<LoginResponse>> RenewAccessTokenAsync(LoginResponse tokens)
        {
            var accessToken = tokens.AccessToken;
            var refreshToken = tokens.RefreshToken;
            var principal = GetClaimsPrincipal(accessToken.Token);
            var user = await _userManager.FindByNameAsync(principal.Identity.Name);
            var response = await GetJwtTokenAsync(user);

            if (refreshToken.Token != user.RefreshToken && refreshToken.ExpiryTokenDate <= DateTime.Now)
            {
                return new ApiResponse<LoginResponse>
                {                    
                    IsSuccess = false,
                    StatusCode = 400,
                    Message = $"Token Expirado o Invalido"
                };

            }
            return response;
        }
        #region PrivateMethods
        private JwtSecurityToken GetToken(List<Claim> authclaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            _ = int.TryParse(_configuration["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);
            var expirationTimeUtc = DateTime.UtcNow.AddMinutes(tokenValidityInMinutes);
            var localTimeZone = TimeZoneInfo.Local;
            var expirationTimeInLozalZone = TimeZoneInfo.ConvertTimeFromUtc(expirationTimeUtc, localTimeZone);

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddMinutes(tokenValidityInMinutes),
                claims: authclaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );
            return token;
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new Byte[64];
            var range = RandomNumberGenerator.Create();
            range.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }       

        private ClaimsPrincipal GetClaimsPrincipal(string accessToken)
        {
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
                ValidateLifetime = false,
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out SecurityToken securityToken);

            return principal;

        }
        #endregion
    }
}
