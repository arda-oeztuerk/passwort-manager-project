using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Password_Manager.Models;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace Password_Manager.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private const string MasterPasswordFile = "user_data.json"; // Store both salt and derived key in this JSON file
        private static readonly object fileLock = new object(); // Ensure thread safety

        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        // Save Master Password
        [HttpPost("save")]
        public IActionResult SaveMasterPassword([FromBody] MasterPasswordRequest request)
        {
            if (request == null || string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.DerivedKey) || string.IsNullOrEmpty(request.Salt))
                return BadRequest(new { Message = "Invalid request. Provide a master password's salt and derived key." });

            lock (fileLock) // Prevent simultaneous file access
            {
                UserData userData;

                if (System.IO.File.Exists(MasterPasswordFile))
                {
                    string json = System.IO.File.ReadAllText(MasterPasswordFile);
                    userData = JsonConvert.DeserializeObject<UserData>(json) ?? new UserData();
                }
                else
                {
                    userData = new UserData(); // Initialize new if file does not exist
                }

                // Ensure Users list is initialized
                if (userData.Users == null)
                {
                    userData.Users = new List<MasterPasswordRequest>();
                }

                // Check if the user already exists
                if (userData.Users.Any(u => u.Username == request.Username))
                {
                    return Conflict(new { Message = "User already exists." }); // 409 Conflict is more appropriate
                }

                // Create the new user and add to list
                var newUser = new MasterPasswordRequest
                {
                    Username = request.Username,
                    Salt = request.Salt,
                    DerivedKey = request.DerivedKey
                };

                userData.Users.Add(newUser);

                try
                {
                    using (FileStream fs = new FileStream(MasterPasswordFile, FileMode.Create, FileAccess.Write, FileShare.None))
                    using (StreamWriter writer = new StreamWriter(fs))
                    {
                        string updatedJson = JsonConvert.SerializeObject(userData, Formatting.Indented);
                        writer.Write(updatedJson);
                    }
                }
                catch (IOException ex)
                {
                    return StatusCode(500, new { Message = "Error saving data: " + ex.Message });
                }
            }

            return Ok(new { Message = "Master password saved successfully." });
        }

        // Verify Master Password
        [HttpPost("verify")]
        public IActionResult VerifyMasterPassword([FromBody] UsernameRequest request)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.Username))
                return BadRequest(new { Message = "Invalid request. Provide a username." });

            if (!System.IO.File.Exists(MasterPasswordFile))
                return Unauthorized(new { Message = "Master password data not set. Please create one." });

            var json = System.IO.File.ReadAllText(MasterPasswordFile);
            var userData = JsonConvert.DeserializeObject<UserData>(json);

            var user = userData.Users.FirstOrDefault(u => u.Username == request.Username);
            if (user == null)
                return Unauthorized(new { Message = "User not found." });

            string storedSalt = user.Salt;
            string storedDerivedKey = user.DerivedKey;

            

            return Ok(new
            {
                Salt = storedSalt,
                DerivedKey = storedDerivedKey,
                

            });
        }
        
    }

    

} 

