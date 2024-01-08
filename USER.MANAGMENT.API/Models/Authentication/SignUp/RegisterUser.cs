using System.ComponentModel.DataAnnotations;

namespace USER.MANAGMENT.API.Models.Authentication.SignUp
{
    public class RegisterUser
    {
        [Required(ErrorMessage = "Se requiere el nombre de usuario.")]
        public string? Username { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "Se requiere el e-mail.")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Se requiere la contraseña.")]
        public string? Password { get; set; }
    }
}
