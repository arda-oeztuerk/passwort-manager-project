// Controllers/PasswordController.cs
using Azure.Core;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Password_Manager.Models;
using Password_Manager.Repositories;
using System.Collections.Generic;

namespace Password_Manager.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    
    public class PasswordController : ControllerBase
    {
        private readonly PasswordRepository _passwordRepository;
        private const string MasterPasswordFile = "user_data.json";

        public PasswordController()
        {
            _passwordRepository = new PasswordRepository();
        }

        // GET: api/password
        
        [HttpGet]
        
        public IActionResult GetAllPasswords(string salty)
        {
            try
            {
                var json = System.IO.File.ReadAllText(MasterPasswordFile);
                var userData = JsonConvert.DeserializeObject<UserData>(json);

                var user = userData.Users.FirstOrDefault(u => u.Salt == salty);
                if (user == null)
                    return Unauthorized(new { Message = "User not found." });

                var passwords = _passwordRepository.GetAllPasswords();
                return Ok(passwords);
            }
            catch
            {
                return BadRequest(new { Message = "Invalid Token." });
            }

        }

        // POST: api/password/save
        [HttpPost("save")]
        
        public IActionResult SavePassword([FromBody] PasswordRequest request, [FromQuery] string salty)
        {
            if (request == null || string.IsNullOrEmpty(request.SiteName) ||
                string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password) ||
                string.IsNullOrEmpty(request.Iv)) // Ensure IV is provided
            {
                return BadRequest(new { Message = "Invalid request. Provide all fields." });
            }

            var json = System.IO.File.ReadAllText(MasterPasswordFile);
            var userData = JsonConvert.DeserializeObject<UserData>(json);

            var user = userData.Users.FirstOrDefault(u => u.Salt == salty);
            if (user == null)
                return Unauthorized(new { Message = "User not found." });


            var password = new Password
            {
                SiteName = request.SiteName,
                Username = request.Username,
                EncryptedPassword = request.Password, // Store encrypted password
                Iv = request.Iv, // Store IV
                //EncryptionKey = request.EncryptionKey,
                DisplayName = request.DisplayName,
                Notes = request.Notes
            };

            _passwordRepository.AddPassword(password);
            return Ok(new { Message = "Password saved successfully." });
        }


        // DELETE: api/password/{id}
        [HttpDelete("{id}")]
        
        public IActionResult DeletePassword(string id, [FromQuery] string salty)

        {
            var json = System.IO.File.ReadAllText(MasterPasswordFile);
            var userData = JsonConvert.DeserializeObject<UserData>(json);

            var user = userData.Users.FirstOrDefault(u => u.Salt == salty);
            if (user == null)
                return Unauthorized(new { Message = "User not found." });

            var password = _passwordRepository.GetPasswordById(id);
            if (password == null)
            {
                return NotFound(new { Message = "Password not found." });
            }

            _passwordRepository.DeletePassword(id);
            return Ok(new { Message = "Password deleted successfully." });
        }

        [HttpGet("check")]
        
        public IActionResult CheckPasswordExists([FromQuery] string siteName, [FromQuery] string salty)
        {
            var json = System.IO.File.ReadAllText(MasterPasswordFile);
            var userData = JsonConvert.DeserializeObject<UserData>(json);

            var user = userData.Users.FirstOrDefault(u => u.Salt == salty);
            if (user == null)
                return Unauthorized(new { Message = "User not found." });

            // Query your database or storage to check if a password exists for the site
            bool exists = _passwordRepository.PasswordExistsForSite(siteName);
            return Ok(new { exists });
        }

        [HttpGet("get")]
        public IActionResult GetPasswordBySiteName([FromQuery] string siteName, [FromQuery] string salty)
        {
            var json = System.IO.File.ReadAllText(MasterPasswordFile);
            var userData = JsonConvert.DeserializeObject<UserData>(json);

            var user = userData.Users.FirstOrDefault(u => u.Salt == salty);
            if (user == null)
                return Unauthorized(new { message = "User not found." });

            var passwords = _passwordRepository.GetPasswordsBySiteName(siteName);

            if (passwords == null || !passwords.Any())
            {
                return Ok(new
                {
                    exists = false,
                    siteName,
                    passwords = new List<object>()  // return empty array
                });
            }

            var passwordList = passwords.Select(p => new
            {
                siteName = p.SiteName,
                username = p.Username,
                encryptedPassword = p.EncryptedPassword,
                iv = p.Iv
            });

            return Ok(new
            {
                exists = true,
                passwords = passwordList
            });
        }

    }

    // Request model for saving a password
    public class PasswordRequest
    {
        public string? SiteName { get; set; }
        public string? Username { get; set; }
        public string? Password { get; set; }

        public string? DisplayName { get; set; }

        public string? Notes { get; set; }

        public string? Iv { get; set; }

        //public string? EncryptionKey {  get; set; }
    }
}