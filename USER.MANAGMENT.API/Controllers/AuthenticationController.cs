using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using User.Management.Data.Models;
using User.Management.Service.Models;
using User.Management.Service.Services;
using USER.MANAGMENT.API.Models;
using USER.MANAGMENT.API.Models.Authentication.SignUp;
using USER.MANAGMENT.Service.Models.Authentication.Login;
using USER.MANAGMENT.Service.Models.Authentication.SignUp;
using User.Management.Service.Models.Authentication.User;

namespace USER.MANAGMENT.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;       
        private readonly IEmailService _emailService;
        private readonly IUserManagement _user;
        
        public AuthenticationController(UserManager<ApplicationUser> userManager,            
            IEmailService emailService,
            IUserManagement user, IConfiguration configuration)
        {
            _userManager = userManager;
            _emailService = emailService;
            _user = user;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser)
        {
            var tokenResponse= await _user.CreateUserWithTokenAsync(registerUser);
            if (tokenResponse.IsSuccess)
            {
                await _user.AssignRoleToUserAsync(registerUser.Roles, tokenResponse.Response.User);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { tokenResponse.Response.Token , email = registerUser.Email }, Request.Scheme);
                var message = new Message(new string[] { registerUser.Email! }, "Por Favor, Confirme su email", confirmationLink!);
                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK, 
                    new Response { Status = "Success", Message = "Email verificado con éxito." });
            }
            return StatusCode(StatusCodes.Status500InternalServerError, 
                new Response { Status = "Error", Message = tokenResponse.Message, IsSuccess=false });
        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                        new Response { Status = "Éxito", Message = "Email verificado correctamente." });
                }
            }
            return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Internally." });
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var loginOtpResponse = await _user.GetOtpByLoginAsync(loginModel);

            //Verificando Usuario
            
            if(loginOtpResponse.Response != null)
            {
                var user = loginOtpResponse.Response.User;
                if (user.TwoFactorEnabled)
                {
                    var token = loginOtpResponse.Response.Token;
                    var message = new Message(new string[] { user.Email! }, "Confirmación de OTP",token);
                    _emailService.SendEmail(message);
                    return StatusCode(StatusCodes.Status200OK,
                        new Response { IsSuccess=loginOtpResponse.IsSuccess ,Status = "Éxito", Message = $"Hemos enviado un OTP a tu Email {user.Email}." });
                }
                if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
                {
                    var serviceResponse = await _user.GetJwtTokenAsync(user);
                    return Ok(serviceResponse);                   
                }
            }            
            return Unauthorized();
        }

        [HttpPost]
        [Route("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(string code, string username)
        {
            var jwt = await _user.LoginUserWithJWTokenAsync(code, username);            
            if (jwt.IsSuccess)
            {
               
                return Ok(jwt);                    
            
            }
            return StatusCode(StatusCodes.Status404NotFound,
                    new Response { Status = "Error", Message = $"El código es inválido." });
        }

        [HttpPost]
        [Route("Refresh-Token")]
        public async Task<IActionResult> RefreshToken(LoginResponse tokens)
        {
            var jwt = await _user.RenewAccessTokenAsync(tokens);
            if (jwt.IsSuccess)
            {
                return Ok(jwt);
            }
            return StatusCode(StatusCodes.Status404NotFound,
                    new Response { Status = "Error", Message = $"El código es inválido." });
        }

        [HttpPost("Forgot-Password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([Required] string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var forgotPasswordlink = Url.Action(nameof(ResetPassword), "Authentication", new {token, email = user.Email}, Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "Reestablezca su contraseña: ", forgotPasswordlink!);
                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,new Response { Status = "Éxito", Message = $"La peticion de restablecimiento de contraseña ha sido enviada correctamente al correo {user.Email}, por favor ve a tu correo y haz click en el enlace de restablecimiento." });

            }
            return StatusCode(StatusCodes.Status400BadRequest,new Response { Status = "Error", Message = "No se pudo enviar el link al email, please intente nuevamente." });
        }

        [HttpGet("reset-password")]
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            var model = new ResetPassword { Token = token, Email = email };

            return Ok(new
            {
                model
            });
        }

        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if (user != null)
            {
                var resetPassResult = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);
                if(!resetPassResult.Succeeded)
                {
                    foreach (var error in resetPassResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }
                    return Ok(ModelState);
                }
                
                return StatusCode(StatusCodes.Status200OK, 
                    new Response { Status = "Éxito", Message = $"La contraseña ha sido cambiada." });

            }
            return StatusCode(StatusCodes.Status400BadRequest, 
                new Response { Status = "Error", Message = "No se pudo enviar el link al email, please intente nuevamente." });
        }        
    }
}
