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

  
![image](https://github.com/user-attachments/assets/d412ddf4-5ea7-4a98-a7a9-82b82232901b)                            ![image](https://github.com/user-attachments/assets/be9d0d70-803e-4a9e-8778-0132b70e178b) 

![image](https://github.com/user-attachments/assets/b90f2ca6-3bee-4e0f-90ba-570f2447a017)                              ![image](https://github.com/user-attachments/assets/d348bdec-acf6-4ea0-96ba-e4d91c813103)


                      
