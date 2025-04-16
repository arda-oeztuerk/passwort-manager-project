// Repositories/PasswordRepository.cs
using Password_Manager.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace Password_Manager.Repositories
{
    public class PasswordRepository
    {
        private readonly string _filePath = "passwords.json";

        // Read all passwords from the JSON file
        private List<Password> ReadPasswordsFromFile()
        {
            if (!System.IO.File.Exists(_filePath))
            {
                return new List<Password>();
            }

            var json = System.IO.File.ReadAllText(_filePath);
            return JsonSerializer.Deserialize<List<Password>>(json);
        }

        // Write passwords to the JSON file
        private void WritePasswordsToFile(List<Password> passwords)
        {
            var json = JsonSerializer.Serialize(passwords);
            System.IO.File.WriteAllText(_filePath, json);
        }

        public List<Password> GetAllPasswords()
        {
            return ReadPasswordsFromFile();
        }

        public Password GetPasswordById(string id)
        {
            var passwords = ReadPasswordsFromFile();
            return passwords.FirstOrDefault(p => p.Id == id);
        }

        public bool PasswordExistsForSite(string siteName)
        {
            // Read all passwords from the file
            var passwords = ReadPasswordsFromFile();

            // Check if any password matches the given site name
            return passwords.Any(p => p.SiteName.Equals(siteName, StringComparison.OrdinalIgnoreCase));
        }

        public List<Password> GetPasswordsBySiteName(string siteName)
        {
            var passwords = ReadPasswordsFromFile();
            return passwords
                .Where(p => p.SiteName.Equals(siteName, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }


        public void AddPassword(Password password)
        {
            var passwords = ReadPasswordsFromFile();
            password.Id = Guid.NewGuid().ToString();
            passwords.Add(password);
            WritePasswordsToFile(passwords);
        }

        public void DeletePassword(string id)
        {
            var passwords = ReadPasswordsFromFile();
            var password = passwords.FirstOrDefault(p => p.Id == id);
            if (password != null)
            {
                passwords.Remove(password);
                WritePasswordsToFile(passwords);
            }
        }
    }
}