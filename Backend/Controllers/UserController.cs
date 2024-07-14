using Backend.Context;
using Backend.Helpers;
using Backend.Models;
using Backend.Models.Dto;
using Backend.UtilityService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
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
        private readonly IEmailService _emailService;
        public UserController(AppDbContext appDbContext, IConfiguration configuration,IEmailService emailService)
        {
            _authContext = appDbContext;
            _configuration = configuration;
            _emailService = emailService;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
            {
                return BadRequest();
            }
            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.Username == userObj.Username);
            if (user == null) { return NotFound(new { message = "User Not Found" }); }

            if (!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
            {
                return BadRequest(new { message = "Password is incorrect" });
            }
            user.Token = CreateJwtToken(user);
            var newAccessToken = user.Token;
            var newRefreshToken = createRefreshToken();
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(5);
            await _authContext.SaveChangesAsync();

            return Ok(
                new TokenApiDto()
                {
                    accessToken = newAccessToken,
                    refreshToken = newRefreshToken
                }


                );
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null)
            {
                return BadRequest();
            }


            //check username 
            if (await CheckUsernameExistAsync(userObj.Username))
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
            if (!string.IsNullOrEmpty(pass))
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
            if (password.Length < 8)
            {
                sb.Append("Minimum password length should be 8" + Environment.NewLine);

            }
            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[0-9]")))
            {
                sb.Append("Password should be alphanumeric" + Environment.NewLine);
            }

            if (Regex.IsMatch(password, "[@, ., !, #, $, %, ^, &, *, (, ), +, =, {, }, [, ], :, ;, \", <, >, ,, ?, /, \\\\, |, `, ~ ]"))
            {
                sb.Append("Password should contain special char" + Environment.NewLine);
            }
            return sb.ToString();
        }

        private async Task<bool> CheckUsernameExistAsync(string username)
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
                new Claim(ClaimTypes.Name, $"{user.Username}")

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
        [Authorize]
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok(await _authContext.Users.ToListAsync());
        }


        private string createRefreshToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert.ToBase64String(tokenBytes);
            var tokenInUser = _authContext.Users
                .Any(a => a.RefreshToken == refreshToken);
            if (tokenInUser)
            {
                return createRefreshToken();
            }
            return refreshToken;
        }

        private ClaimsPrincipal GetPrincipleFromExpiredToken(string token)
        {

            var secret_key = _configuration["JWT:secret_key"];
            var key = Encoding.ASCII.GetBytes(secret_key);
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principle = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);

            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid Token");
            }
            return principle;


        }


        [HttpPost("refreshToken")]
        public async Task<IActionResult> RefreshToken(TokenApiDto tokenApiDto)
        {
            if(tokenApiDto is null)
            {
                return BadRequest("Invalid client request");
            }
            string accessToken = tokenApiDto.accessToken;
            string refreshToken = tokenApiDto.refreshToken;
            var principle = GetPrincipleFromExpiredToken(accessToken);
            var username = principle.Identity.Name;
            var user = await _authContext.Users.FirstOrDefaultAsync(u => u.Username == username);
            if(user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return BadRequest("Invalid request");
            }

            var newAccessToken = CreateJwtToken(user);
            var newRefreshToken = createRefreshToken();
            user.RefreshToken = newRefreshToken;
            await _authContext.SaveChangesAsync();
            return Ok(
                new TokenApiDto()
                {
                    accessToken = newAccessToken,
                    refreshToken = newRefreshToken,
                }
              );

        }
        [HttpPost("send-reset-email/{email}")]
        public async Task<IActionResult>SendEmail(string email)
        {
            var user =await  _authContext.Users.FirstOrDefaultAsync(a => a.Email == email);
            if(user is null)
            {
                return NotFound(new
                {
                    StatusCode = 404,
                    Message = "email does'nt exist"
                });
            }

            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var emailToken = Convert.ToBase64String(tokenBytes);
            user.ResetPasswordToken = emailToken;
            user.ResetPasswordExpiry = DateTime.UtcNow.AddMinutes(15);
            string from = _configuration["EmailSettings:From"];
            var emailModel = new EmailModel(email, "Reset Password", EmailBody.EmailStringBody(email, emailToken));

            _emailService.SendEmail(emailModel);
             _authContext.Entry(user).State = EntityState.Modified;
            await _authContext.SaveChangesAsync();

            return Ok(new
            {
                StatusCode = 200,
                Message = "Email sent"
            });
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto resetPasswordDto)
        {
            var newToken = resetPasswordDto.EmailToken.Replace(" ", "+");
            var user = await _authContext.Users.AsNoTracking().FirstOrDefaultAsync(a => a.Email == resetPasswordDto.Email);
            if (user is null)
            {
                return NotFound(new
                {
                    StatusCode = 404,
                    Message = "email does'nt exist"
                });
            }

            var tokenCode = user.ResetPasswordToken;
            var tokenExpiry = user.ResetPasswordExpiry;
            if(tokenCode != resetPasswordDto.EmailToken || tokenExpiry <  DateTime.UtcNow)
            {
                return BadRequest(
                    new
                    {
                        StatusCode = 400,
                        Message = "Invalid reset link"
                    });
                    
            }
            user.Password = PasswordHasher.HashPassword(resetPasswordDto.NewPassword);
            _authContext.Entry(user).State = EntityState.Modified;
            await _authContext.SaveChangesAsync();
            return Ok(new
            {
                StatusCode = 200,
                Message = "Password reset successfully"
            });

        }



    }
}
