
let salty = "";
function showScreen(screenId) {
    // List of all screen IDs
    const screens = ["login-container", "dashboard", "password-form", "Sign-Up"];

    // Hide all screens
    screens.forEach(screen => {
        const screenElement = document.getElementById(screen);
        if (screenElement) {
            screenElement.style.display = "none";
        }
    });

    // Show the requested screen
    const screenToShow = document.getElementById(screenId);
    if (screenToShow) {
        screenToShow.style.display = "block";
    } else {
        console.error("Screen not found:", screenId);
    }
}


async function fetchPasswords() {
    try {
        
        
        
        const response = await fetch(`https://localhost:7277/api/Password?salty=${encodeURIComponent(salty)}`, {
            method: "GET",
        });

        

        const passwords = await response.json();
        const passwordList = document.getElementById("password-list");
        passwordList.innerHTML = ""; // Clear the list

        

        
        const E_Key = hexStringToUint8Array(hashedPassword);
        // 2️⃣ Initialize a counter for successfully decrypted passwords
        

        // 2️⃣ Iterate through stored passwords and attempt decryption
        for (const password of passwords) {
                
                // Convert IV from hex to Uint8Array
                const IV = new Uint8Array(password.iv.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

                // Try to decrypt the password
                const decryptedPassword = await decryptPassword(password.encryptedPassword, IV, E_Key);
                // 3️⃣ Check if decryption was successful (decryptedPassword should not be null or empty)
                if (decryptedPassword && decryptedPassword !== null && decryptedPassword.length > 0) {
                    // ✅ Only add the password if it's successfully decrypted
                    
                    const li = document.createElement("li");
                    li.innerHTML = `
                        <strong>${password.siteName}</strong> - ${password.displayName ? await decryptPassword(password.displayName,IV,E_Key) : ""}
                        <button onclick="viewPassword('${password.encryptedPassword}', '${password.iv}', '${await decryptPassword(password.username, IV, E_Key)}', '${password.notes ? await decryptPassword(password.notes, IV, E_Key) : ""}')">View</button>
                        <button onclick="deletePassword('${password.id}')">Delete</button>
                    `;
                    passwordList.appendChild(li);
                }
    

            } 
            
        }
     catch (error) {
        console.error("Error:", error);
    }
}



async function deletePassword(passwordId) {

    
    
    try {
        
        const response = await fetch(`https://localhost:7277/api/Password/${passwordId}?salty=${encodeURIComponent(salty)}`, {
            method: "DELETE",
        });

        if (response.ok) {
            alert("Password deleted successfully.");
            fetchPasswords(); // Refresh the password list
        } else {
            alert("Error deleting password.");
        }
    } catch (error) {
        console.error("Error:", error);
    }
};


async function viewPassword(encryptedPassword, iv, userName, notes) {
    try{

        // Convert the encryption key and IV back to Uint8Array
        //const E_Key = new Uint8Array(encryptionKey.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        const E_Key = hexStringToUint8Array(hashedPassword);
        const IV = new Uint8Array(iv.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        // Decrypt the password
        const password = await decryptPassword(encryptedPassword, IV, E_Key);
        const user_name= userName;
        const Notes = notes;
        // Create a modal or alert to display the password
        const passwordDisplay = `
            <div style="padding: 20px; background: white; border-radius: 8px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);">
                <p><strong> Username:</strong> ${user_name}</p>
                <p><strong>Password:</strong> ${password}</p>
                <p><strong>Notes:</strong> ${Notes}</p>
                <button onclick="copyToClipboard('${password}')">Copy to Clipboard</button>
                <button onclick="closePasswordDisplay()">Close</button>
            </div>
        `;

        // Display the password
        const passwordDisplayDiv = document.createElement("div");
        passwordDisplayDiv.id = "password-display";
        passwordDisplayDiv.style.position = "fixed";
        passwordDisplayDiv.style.top = "50%";
        passwordDisplayDiv.style.left = "50%";
        passwordDisplayDiv.style.transform = "translate(-50%, -50%)";
        passwordDisplayDiv.style.zIndex = "1000";
        passwordDisplayDiv.innerHTML = passwordDisplay;

        document.body.appendChild(passwordDisplayDiv);
    }
    catch (error) {
        
        console.error("Error decrypting password:", error);
        alert("Failed to decrypt password.");
    }
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text)
        .then(() => {
            alert("Password copied to clipboard!");
        })
        .catch(() => {
            alert("Failed to copy password.");
        });
}

function closePasswordDisplay() {
    const passwordDisplayDiv = document.getElementById("password-display");
    if (passwordDisplayDiv) {
        passwordDisplayDiv.remove();
    }
}

// whether to set or to unlock vault

document.getElementById("register-btn").addEventListener("click", async () =>  {
    showScreen("Sign-Up");

    const masterPasswordInput = document.getElementById("master-password1");
    const confirmPasswordInput = document.getElementById("confirm-password");
    const usernameInput = document.getElementById("userinput");
    const actionBtn = document.getElementById("signup-btn");
    const backbtn = document.getElementById("Mscreen-btn");

    

    backbtn.addEventListener("click", function(){
        showScreen("login-container");
    });

    actionBtn.addEventListener("click", async function () {
        const masterPassword = masterPasswordInput.value;
        const confirmedPassword = confirmPasswordInput.value;
        const username = usernameInput.value;

        // Check if the fields are not empty and passwords match
        if (!username || !masterPassword || !confirmedPassword) {
            alert("Please fill in both password fields.");
            return;
        }

        if (masterPassword !== confirmedPassword) {
            alert("The passwords don't match, please re-enter the master password.");
            masterPasswordInput.value = "";
            confirmPasswordInput.value = "";
            masterPasswordInput.focus(); // Focus on the first field for user convenience
            return;
        }

        if (masterPassword.length < 8 || masterPassword.length > 20) {
            alert("Password must be between 8 to 20 characters in length.");
            masterPasswordInput.value = "";
            confirmPasswordInput.value = "";
            return;
        }


         // Check for at least one capital letter, one lowercase letter, one number, and one special character
         const passwordStrengthRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,20}$/;

         if (!passwordStrengthRegex.test(masterPassword)) {
             alert("Password must contain at least one capital letter, one lowercase letter, one number, and one special character.");
             masterPasswordInput.value = "";
             confirmPasswordInput.value = "";
             return;
         }

        try {
            // Hash the master password (You should hash the password before sending it to the backend)
            const hashedPassword = await hashPassword(masterPassword);
            
            // Generate a random salt
            const salt = crypto.getRandomValues(new Uint8Array(16));  // 16 bytes salt
            
            // Derive encryption key from master password and salt using PBKDF2
            const derivedKey = await deriveKey(hashedPassword, salt);

            // Convert the derived key to a base64 string
            
            const derivedKeyBase64 = arrayBufferToBase64(derivedKey);
            
            const saltBase64 = arrayBufferToBase64(salt);  // Convert salt to base64 string
            
            
            
            
            
            // Send the salt, encrypted user data, and other information to the backend
            const saveResponse = await fetch("https://localhost:7277/api/auth/save", {
                method: "POST",
                headers: { 
                    
                    "Content-Type": "application/json"
                 },
                body: JSON.stringify({ username: username, salt: saltBase64, derivedkey: derivedKeyBase64 })
            });

            const saveResponseData = await saveResponse.json(); // Read the save response body once
            

            if (saveResponse.ok) {
                alert("Master password set successfully. Please enter it again to unlock.");
                showScreen("login-container"); // After successful registration, go back to login
            } else {
                alert(saveResponseData.message);
            }

        } catch (error) {
            console.error("Error:", error);
            alert("An error occurred. Please try again.");
        }

        // Clear the password inputs after submission
        masterPasswordInput.value = "";
        confirmPasswordInput.value = "";
    });
});

let hashedPassword = "";

document.getElementById("unlock-btn").addEventListener("click", async () => {

   // const confirmPasswordInput = document.getElementById("confirm-password");
    //const actionBtn = document.getElementById("unlock-btn");
    const usernameInput = document.getElementById("userinput1");
    const masterPasswordInput = document.getElementById("master-password");
    masterPassword = masterPasswordInput.value;
    username = usernameInput.value;

    if (!username || !masterPassword) {
        alert("Please enter a master password and username.");
        return;
    }

    if (masterPassword.length < 8 || masterPassword.length > 20) {
        alert("Password must between 8 to 20 in length");
        return;
    }

    try {
        
        // Hash the master password
        hashedPassword = await hashPassword(masterPassword);
        
        
        
        // Get the salt and derivedkey from the server
        const response = await fetch("https://localhost:7277/api/auth/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({username})
        
        })
        
        const data = await response.json();
        
        
        if (!response.ok || !data.salt || !data.derivedKey) {
            throw new Error("Failed to retrieve salt or derived key.");
        }
        salty = data.salt;
    
        // Convert the received salt and derived key from Base64 to byte arrays
        const storedSalt = base64ToUint8Array(data.salt);
        const storedDerivedKey = data.derivedKey;

        // Derive encryption key from master password and stored salt
        const derivedKey = await deriveKey(hashedPassword, storedSalt);
        const convertedDerivedkey = arrayBufferToBase64(derivedKey);

        if (convertedDerivedkey !== storedDerivedKey) {
            alert("Incorrect master password.");
            return false;
        }

        // If the derived key matches, return true
        alert("Master password verified successfully.");
        masterPasswordInput.value = ""; // Clear input field
        showScreen("dashboard"); // Show the dashboard screen
        fetchPasswords(); // Load stored passwords
        
        return true;
        
        
        
    } catch (error) {
        console.error("Error:", error);
        alert("An error occurred. Please try again.");
    }

    // Clear password input field after submission
    masterPasswordInput.value = "";
});

document.getElementById("add-password-btn").addEventListener("click", () => {
    showScreen("password-form");
});

document.getElementById("cancel-btn").addEventListener("click", () => {
    showScreen("dashboard");
});

function hexStringToUint8Array(hexString) {
    if (hexString.length !== 64) {
        throw new Error("Invalid hex string length. Expected 64 characters (32 bytes).");
    }
    return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

document.getElementById("save-password-btn").addEventListener("click", async () => {
    const siteNameInput = document.getElementById("site-name").value;
    const usernameInput = document.getElementById("username").value;
    const displaynameInput = document.getElementById("display-name").value;
    const notesInput = document.getElementById("notes").value;
    const password = document.getElementById("password").value;

    if (!siteNameInput || !usernameInput || !password) {
        alert("Please fill in all fields.");
        return;
    }

    

    try {
        // Generate a random encryption key (256 bits)
        const randomKey = hexStringToUint8Array(hashedPassword);
        
        const iv = crypto.getRandomValues(new Uint8Array(12)); // Initialization vector
        // Encrypt the password
        const encryptedPassword = await encryptPassword(password, iv, randomKey);

        //const encryptedsiteName = await encryptPassword(siteNameInput, iv, randomKey);

        const encryptedusername= await encryptPassword(usernameInput, iv, randomKey);

        const encrypteddisplayname = displaynameInput;
        const encryptednotes = notesInput;
        
        if(displaynameInput){
             encrypteddisplayname = await encryptPassword(displaynameInput, iv, randomKey);
        }
        if(notesInput){
            encryptednotes = await encryptedPassword(notesInput, iv, randomKey);
        }
        

        // Send the new password to the backend
        const response = await fetch(`https://localhost:7277/api/Password/save?salty=${encodeURIComponent(salty)}`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ siteName: siteNameInput, username: encryptedusername.encryptedData, displayname: encrypteddisplayname.encryptedData, notes: encryptednotes.encryptedData ,password: encryptedPassword.encryptedData, // ✅ Send only encryptedData
                iv: encryptedPassword.iv})
            
            
        });

        if (response.ok) {
            alert("Password saved successfully.");
            // Clear input fields correctly
            document.getElementById("site-name").value = "";
            document.getElementById("username").value = "";
            document.getElementById("password").value = "";
            showScreen("dashboard"); // Return to the dashboard
            fetchPasswords(); // Refresh the password list

        } else {
            alert("Error saving password.");
        }
    } catch (error) {
        console.error("Error:", error);
        alert("An error occurred. Please try again.");
    }
});

function generatePassword(length) {
    

    // Character groups
    const lowerCase = "abcdefghijklmnopqrstuvwxyz";
    const upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const numbers = "0123456789";
    const specialChars = "!@#$%^&*()_+";
    const allChars = lowerCase + upperCase + numbers + specialChars;

    let password = "";

    // Ensure at least one character from each category
    password += lowerCase[Math.floor(Math.random() * lowerCase.length)];
    password += upperCase[Math.floor(Math.random() * upperCase.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += specialChars[Math.floor(Math.random() * specialChars.length)];

    // Fill the rest of the password length with random characters from all categories
    for (let i = password.length; i < length; i++) {
        password += allChars[Math.floor(Math.random() * allChars.length)];
    }

    // Shuffle the password to avoid predictable patterns
    password = password.split("").sort(() => Math.random() - 0.5).join("");

    return password;
}


document.getElementById("generate-password-btn").addEventListener("click", () => {

    let length = parseInt(prompt("Enter the desired password length (minimum 12, maximum 32):", "12"));

    if (isNaN(length) || length < 12 || length > 32) {
        alert("Please enter a valid length between 4 and 50.");
        return;
    }

    const passwordInput = document.getElementById("password");
    passwordInput.value = generatePassword(length);
});


document.getElementById("Generate-password-btn").addEventListener("click", () => {

    let length = parseInt(prompt("Enter the desired password length (minimum 8, maximum 32):", "12"));

    if (isNaN(length) || length < 8 || length > 32) {
        alert("Please enter a valid length between 4 and 50.");
        return;
    }

    const password = generatePassword(length); // Generate a random password

    
        // If on the dashboard, copy the password to the clipboard
        navigator.clipboard.writeText(password).then(() => {
            alert("Password copied to clipboard!"); // Optional: Notify the user
        }).catch((err) => {
            console.error("Failed to copy password: ", err);
        });

    
});


// Add event listener to the logout button
document.getElementById('logout-btn').addEventListener('click', function() {
    logout();
});


// Function to handle logout
function logout() {
    // Hide the dashboard and password form
    document.getElementById('dashboard').style.display = 'none';
    document.getElementById('password-form').style.display = 'none';

    // Show the login container
    document.getElementById('login-container').style.display = 'block';

    // Clear any sensitive data
    localStorage.removeItem('authToken'); // Example: Clear JWT token
    document.getElementById('master-password').value = ''; // Clear master password input
    document.getElementById('userinput1').value = '';
}


