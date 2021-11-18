using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MeetupAPI.Entities;
using MeetupAPI.Identity;
using MeetupAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace MeetupAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly MeetupContext _meetupContext;
        private readonly IJwtProvider _jwtProvider;
        private readonly IPasswordHasher<User> _passwordHasher;

        public AccountController(MeetupContext meetupContext, IPasswordHasher<User> passwordHasher, IJwtProvider jwtProvider)
        {
            _meetupContext = meetupContext;
            _passwordHasher = passwordHasher;
            _jwtProvider = jwtProvider;
        }

        [HttpPost("login")]
        public ActionResult Login([FromBody]UserLoginDto userLoginDto)
        {
            var user = _meetupContext.Users
                .Include(user => user.Role)
                .FirstOrDefault(user => user.Email == userLoginDto.Email);
            
            if(user == null)
            {
                return BadRequest("Invalid Username  or password");
            }
           
            var passwordVerificationResult =  _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, userLoginDto.Password);

            if (passwordVerificationResult == PasswordVerificationResult.Failed)
            {
                return BadRequest("Invalid Username  or password");
            }

            var token = _jwtProvider.GenerateJwtToken(user);

            return Ok(token);

        }

        [HttpPost("register")]
        public ActionResult Register([FromBody]RegisterUserDto registerUserDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var newUser = new User() {
                Email = registerUserDto.Email,
                Nationality = registerUserDto.Nationality,
                DateOfBirth = registerUserDto.DateofBirth,
                RoleId = registerUserDto.RoleId
            };

            var passwordHash = _passwordHasher.HashPassword(newUser, registerUserDto.Password);
            newUser.PasswordHash = passwordHash;

            _meetupContext.Users.Add(newUser);
            _meetupContext.SaveChanges();

            return Ok();
        }
    }
}
