using System.ComponentModel.DataAnnotations;

namespace Password_Manager.Models
{
    public class MasterPasswordRequest
    {
        public string DerivedKey { get; set; }

        public string Username { get; set; }

        public string Salt { get; set; }
    }


}



