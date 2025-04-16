# 🔐 Password Manager Web Application

A secure, browser-based password manager that allows users to save, encrypt, decrypt, and manage passwords locally — with full client-side encryption and zero-knowledge architecture.

## 🌟 Features

- AES-256-GCM encryption of passwords
- Master password protection with PBKDF2 (hashed + salted)
- Auto-fill and auto-save functionality in the browser
- Password generator for strong credentials
- Client-side encryption and decryption (Zero-Knowledge)
- Data stored in a local **JSON file**
- RESTful API for backend communication

## 🛠️ Technologies

- **Frontend**: HTML, CSS, JavaScript (Web Crypto API)
- **Backend**: C# / ASP.NET Core Web API
- **Storage**: JSON file for encrypted password records

## 🔒 Security Highlights

- Master password is never stored — only its salt and derived key
- Each password is encrypted with AES-GCM using a key derived from the master password
- A unique IV is generated for every encryption and stored alongside the ciphertext
- Decryption is only possible with the correct master password
