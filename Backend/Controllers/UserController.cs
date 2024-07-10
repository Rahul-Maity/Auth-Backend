using Backend.Context;
using Backend.Helpers;
using Backend.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;

namespace Backend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {

        private readonly AppDbContext _authContext;
        private readonly IConfiguration _configuration;
        public UserController(AppDbContext appDbContext,IConfiguration configuration)
        {
            _authContext = appDbContext;    
            _configuration = configuration;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody]User userObj)
        {
            if(userObj == null)
            {
                return BadRequest();
            }
            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.Username == userObj.Username );
            if(user == null) { return NotFound(new { message = "User Not Found" }); }

            if(!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
            {
                return BadRequest(new { message = "Password is incorrect" });
            }
            user.Token = CreateJwtToken(user);

            return Ok(

                new {
                    Token = user.Token,
                    message = "Login success" }
                );
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody]User userObj)
        {
            if(userObj ==null)
            {
                return BadRequest();
            }


            //check username 
            if(await CheckUsernameExistAsync(userObj.Username))
            {
                return BadRequest(new { message = "Username already exist" });
            }



            //check email
            if (await CheckEmailExistAsync(userObj.Email))
            {
                return BadRequest(new { message = "Email already exist" });
            }


            //check password strength
            var pass = CheckPasswordStrength(userObj.Password);
            if(!string.IsNullOrEmpty(pass))
            {
                return BadRequest(new { message = pass.ToString() });
            }


            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "";
            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new
            {
                message = "User registered"
            });
        }

        private string CheckPasswordStrength(string password)
        {
            //throw new NotImplementedException();

            StringBuilder sb = new StringBuilder();
            if(password.Length <8)
            {
                sb.Append("Minimum password length should be 8"+Environment.NewLine);
               
            }
            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[0-9]")))
            {
                sb.Append("Password should be alphanumeric" + Environment.NewLine);
            }

            if(Regex.IsMatch(password, "[@, ., !, #, $, %, ^, &, *, (, ), +, =, {, }, [, ], :, ;, \", <, >, ,, ?, /, \\\\, |, `, ~ ]"))
            {
                sb.Append("Password should contain special char" +  Environment.NewLine);
            }
            return sb.ToString();
        }

        private async Task<bool>CheckUsernameExistAsync(string username)
        {
            return await _authContext.Users.AnyAsync(x => x.Username == username);

        }

        private async Task<bool> CheckEmailExistAsync(string email)
        {
            return await _authContext.Users.AnyAsync(x => x.Email == email);

        }

        private string CreateJwtToken(User user)
        {
            var JwtTokenHandler = new JwtSecurityTokenHandler();
            var secret_key = _configuration["JWT:secret_key"];
            var key = Encoding.ASCII.GetBytes(secret_key);

            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name, $"{user.Firstname} {user.Lastname}")

            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = credentials

            };

            var token = JwtTokenHandler.CreateToken(tokenDescriptor);

            return JwtTokenHandler.WriteToken(token);
        }


        [HttpGet]
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok(await _authContext.Users.ToListAsync());
        }
    }
}
