using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace USER.MANAGMENT.API.Controllers
{
    [Authorize(Roles ="Admin")]
    [Route("api/[controller]")] 
    [ApiController]
    public class AdminController : ControllerBase
    {

        [HttpGet("employees")]
        public IEnumerable<string> Get()
        {
            return new List<string> { "Rolando", "pIZARRO" };
        }
    }
}
