using System.ComponentModel.DataAnnotations;

namespace USER.MANAGMENT.API.Models.Authentication.Login
{
    public class LoginModel
    {

        [Required(ErrorMessage = "Se requiere el nombre de usuario.")]
        public string? Username { get; set; }
        
        [Required(ErrorMessage = "Se requiere la contraseña.")]
        public string? Password { get; set; }
    }
}
