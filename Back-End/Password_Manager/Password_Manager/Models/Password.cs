namespace Password_Manager.Models
{
    public class Password
    {
        public string? Id { get; set; }
        public string? SiteName { get; set; }
        public string? Username { get; set; }
        public string? EncryptedPassword { get; set; }

        public string? DisplayName { get; set; }

        public string? Notes { get; set; }

        public string? Iv { get; set; }

        
    }
}
