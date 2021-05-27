using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using AuthenticationService.Data;
using AuthenticationService.Interfaces;
using AuthenticationService.Dtos;

namespace RecordStore.AuthenticationService.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly IUsersService _usersService;
        private readonly IMapper _mapper;
        private readonly ILogger<UserController> _logger;
        private readonly RoleManager<IdentityRole> _roleManager;
        public UserController(
         UserManager<ApplicationUser> userManager,
         SignInManager<ApplicationUser> signInManager,
         IConfiguration configuration, IUsersService usersService,
         IMapper mapper,
         ILogger<UserController> logger,
        RoleManager<IdentityRole> roleManager
     )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _usersService = usersService;
            _mapper = mapper;
            _logger = logger;
            _roleManager = roleManager;

        }
        [AllowAnonymous]
        [HttpPost("Login")]
        public async Task<object> Login([FromBody] LoginUserDto model)
        {
            if (ModelState.IsValid)
            {
                _logger.LogWarning("info");
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe,
                    false);
                if (result.Succeeded)
                {
                    var appUser = _userManager.Users.SingleOrDefault(r => r.Email == model.Email);
                    LoginResponse loginResponse = new LoginResponse { token = await GenerateJwtTokenAsync(model.Email, appUser) };
                    return Ok(loginResponse);
                }

                if (result.IsLockedOut)
                {
                    return BadRequest("Lockout");
                }
            }

            // If we got this far, something failed, redisplay form
            return BadRequest(model);
        }

        [AllowAnonymous]
        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterUserDto model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    CreatedOn = DateTime.Now,
                    CreatedBy = model.Email,
                    Adress = model.Address,
                };
                var result = await _userManager.CreateAsync(user, model.Password);
                var role = await _roleManager.FindByNameAsync(model.Role);
                if (role != null)
                {
                    await _userManager.AddToRoleAsync(user, role.Name);
                }

                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(user, false);
                    return Ok(new { massage = "User created a new account with password." });
                }
                else if (result.Errors.Any(x => x.Code == "DuplicateUserName"))
                {
                    return BadRequest("DuplicateUserName");
                }

                AddErrors(result);
            }

            return BadRequest(model);
        }

        [Authorize]
        [HttpGet("GetAll")]
        public async Task<IActionResult> GetUsers()
        {
            try
            {
                var userList = await _usersService.GetUsers();
                var model = _mapper.Map<IEnumerable<ApplicationUser>>(userList);

                return Ok(model);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "");
                return BadRequest(new { message = "" });
            }
        }


        [Authorize]
        [HttpGet("GetUser")]
        public async Task<ActionResult<UserDto>> GetUserProfileAsync()
        {
            var model = new UserDto();
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return BadRequest();

            //model.Id = user.Id;
            model.Email = user.Email;
            model.FirstName = user.FirstName;
            model.LastName = user.LastName;

            return Ok(model);
        }

        [Authorize(Roles = "Admin,Client")]
        [HttpGet("GetById/{id}")]
        public async Task<ActionResult<UserDto>> GetUserById(string id)
        {
            try
            {
                var user = await _usersService.GetUserById(id);
                if (user == null)
                {
                    _logger.LogError(string.Format("User not found"));
                    return BadRequest(new { message = "User not found" });
                }

                var model = _mapper.Map<UserDto>(user);
                return Ok(model);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "UNEXPECTED_ERROR");
                return BadRequest(new { message = "UNEXPECTED_ERROR" });
            }
        }

        [Authorize(Roles = "Admin")]
        [HttpPut("ChangeUserProfile")]
        public async Task<IActionResult> ChangeUserProfile([FromBody] ChangeProfileDto model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                if (user == null)
                    return NotFound(new { message = "User not found" });

                if (model.CurrentPassword != null)
                {
                    var isValid = _userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, model.CurrentPassword);
                    if (isValid == PasswordVerificationResult.Success)
                    {
                        if (model.NewPassword != null)
                        {
                            var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
                            if (result.Succeeded)
                                await _signInManager.RefreshSignInAsync(user);
                            else return BadRequest(new { message = result.Errors });
                        }
                        if (model.FirstName != user.FirstName || model.LastName != user.LastName || model.Address!=user.Adress)
                        {
                            user.FirstName = model.FirstName != user.FirstName ? model.FirstName : user.FirstName;
                            user.LastName = model.LastName != user.LastName ? model.LastName : user.LastName;
                            user.Adress = model.Address != user.Adress ? model.Address : user.Adress;
                            user.ModifiedBy = user.Email;
                            user.ModifiedOn = DateTime.Now;
                            var result = await _userManager.UpdateAsync(user);
                            if (result.Succeeded)
                                return Ok(user);
                            else
                                return BadRequest();
                        }

                    }
                    else return BadRequest("CurrentPasswordNotValid");
                }
                return Ok("User updated succesfully");
            }
            else
                return BadRequest(new { message = "Model State not valid" });
        }

        [Authorize(Roles = "Client")]
        [HttpDelete("Delete/{id}")]
        public async Task<IActionResult> DeleteUser(string id)
        {
            try
            {
                var user = await _usersService.GetUserByStringId(id);

                if (user == null)
                {
                    _logger.LogError(string.Format("User not found"));
                    return BadRequest(new { message = "User not found" });
                }

                _usersService.UpdateUser(user);
                await _usersService.SaveChanges();

                return Ok(new { message = "DELETED_SUCCESSFULLY" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "UNEXPECTED_ERROR");
                return BadRequest(new { message = "UNEXPECTED_ERROR" });
            }
        }

        [Authorize]
        [HttpPost("Logoff")]
        public async Task<IActionResult> LogOff()
        {
            await _signInManager.SignOutAsync();
            return Ok(new { message = "User logged out!" });
        }


        //private methods
        private async Task<object> GenerateJwtTokenAsync(string email, ApplicationUser user)
        {
            var userRoles = await _userManager.GetRolesAsync(user);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.UserData, user.Id),

                new Claim(JwtRegisteredClaimNames.Sub, email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Email, email)
            };
            foreach (var userRole in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, userRole));
            }
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetValue<string>("AppSettings:Secret")));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expires = DateTime.Now.AddDays(Convert.ToDouble(1));

            var token = new JwtSecurityToken(
                "issuer",
                "issuer",
                claims,
                expires: expires,
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors) ModelState.AddModelError(string.Empty, error.Description);
        }
    }
}
