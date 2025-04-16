// Detect login forms on the page
let hashedPassword="";
let salty ="";

async function getMasterPassword() {
    return new Promise((resolve) => {
        // Create modal background
        const overlay = document.createElement("div");
        overlay.style.position = "fixed";
        overlay.style.top = "0";
        overlay.style.left = "0";
        overlay.style.width = "100%";
        overlay.style.height = "100%";
        overlay.style.backgroundColor = "rgba(0, 0, 0, 0.5)";
        overlay.style.display = "flex";
        overlay.style.alignItems = "center";
        overlay.style.justifyContent = "center";
        overlay.style.zIndex = "1000";

        // Create modal box
        const modal = document.createElement("div");
        modal.style.backgroundColor = "#fff";
        modal.style.padding = "20px";
        modal.style.borderRadius = "8px";
        modal.style.boxShadow = "0 4px 10px rgba(0, 0, 0, 0.3)";
        modal.style.textAlign = "center";
        modal.style.width = "300px";

        // Email label
        const emailLabel = document.createElement("label");
        emailLabel.textContent = "Enter your Email:";
        emailLabel.style.display = "block";
        emailLabel.style.marginBottom = "5px";

        // Email input field
        const emailInput = document.createElement("input");
        emailInput.type = "email"; // Email input
        emailInput.style.width = "100%";
        emailInput.style.padding = "10px";
        emailInput.style.marginBottom = "10px";
        emailInput.style.border = "1px solid #ccc";
        emailInput.style.borderRadius = "5px";

        // Password label
        const passwordLabel = document.createElement("label");
        passwordLabel.textContent = "Enter your Master Password:";
        passwordLabel.style.display = "block";
        passwordLabel.style.marginBottom = "5px";

        // Password input field
        const passwordInput = document.createElement("input");
        passwordInput.type = "password"; // Hide text input
        passwordInput.style.width = "100%";
        passwordInput.style.padding = "10px";
        passwordInput.style.marginBottom = "10px";
        passwordInput.style.border = "1px solid #ccc";
        passwordInput.style.borderRadius = "5px";

        // Error message
        const errorMsg = document.createElement("p");
        errorMsg.textContent = "Password must be between 8 and 20 characters, and email must be valid.";
        errorMsg.style.color = "red";
        errorMsg.style.display = "none";
        errorMsg.style.marginBottom = "10px";

        // Submit button
        const submitButton = document.createElement("button");
        submitButton.textContent = "Submit";
        submitButton.style.padding = "10px 20px";
        submitButton.style.backgroundColor = "#007bff";
        submitButton.style.color = "#fff";
        submitButton.style.border = "none";
        submitButton.style.borderRadius = "5px";
        submitButton.style.cursor = "pointer";

        submitButton.addEventListener("click", () => {
            const email = emailInput.value.trim();
            const password = passwordInput.value;

            if (validateEmail(email) && password.length >= 8 && password.length <= 20) {
                resolve({ email, password }); // ✅ Return the entered email and password
                document.body.removeChild(overlay); // Remove the modal
            } else {
                errorMsg.style.display = "block"; // Show error message
            }
        });

        // Append elements
        modal.appendChild(emailLabel);
        modal.appendChild(emailInput);
        modal.appendChild(passwordLabel);
        modal.appendChild(passwordInput);
        modal.appendChild(errorMsg);
        modal.appendChild(submitButton);
        overlay.appendChild(modal);
        document.body.appendChild(overlay);

        // Focus on email input field first
        emailInput.focus();
    });
}

// ✅ Email validation function
function validateEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}


const hashPassword = async (password) => {
    // Convert the password to a Uint8Array
    const encoder = new TextEncoder();
    const data = encoder.encode(password);

    // Hash the password using SHA-256
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);

    // Convert the hash to a hexadecimal string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

    return hashHex;
};

function hexStringToUint8Array(hexString) {
    if (hexString.length !== 64) {
        throw new Error("Invalid hex string length. Expected 64 characters (32 bytes).");
    }
    return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}



 async function detectLoginForms() {
    const loginForms = document.querySelectorAll("form");

    loginForms.forEach(async (form) => {
        const usernameField = form.querySelector(
            'input[type="text"], input[type="email"], input[placeholder*="username"], input[placeholder*="benutzername"], input[placeholder*="e-mail"], input[placeholder*="login"]'
        );
        const passwordField = form.querySelector('input[type="password"]');

        if (passwordField && usernameField) {
            
            observeForm(form);

        } 
    });
}





/* Function to check if a password exists for the website
async function checkPasswordExists(siteName) {
    try {
        
        const response = await fetch(`https://localhost:7277/api/Password/check?siteName=${encodeURIComponent(siteName)}`, {
            method: "GET",
        headers: { "Content-Type": "application/json" }
      });
  
      const responseData = await response.json();
      return responseData.exists; // Assuming the backend returns { exists: true/false }
    } catch (error) {
      alert("Error checking password existence:");
      return false; // Assume no password exists if there's an error
    }
  }
*/

async function getPasswordBySiteName(siteName, salty) {
try {
    const response = await fetch(`https://localhost:7277/api/Password/get?siteName=${encodeURIComponent(siteName)}&salty=${encodeURIComponent(salty)}`, {
    method: "GET",
    headers: { "Content-Type": "application/json" }
    });

    if (response.ok) {
        const passwordData = await response.json();
        
            return passwordData; // { siteName, username, encryptedPassword, iv, encryptionKey }
        }
        
    
     
}catch (error) {
    console.error("Error fetching password:", error);
    throw error;
}
}  
  
  // Observe form for submission
async function observeForm(form) {

    const login_confirm = confirm("Please login to use the Password_Manager");
        
    if(login_confirm){

        

        
        
        const {email, password} = await getMasterPassword();

            const response = await fetch("https://localhost:7277/api/auth/verify", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ username: email }),
            });


    
            const data = await response.json();

            
        
            
            
            if (!response.ok || !data.salt || !data.derivedKey) {
                throw new Error("Failed to retrieve salt or derived key.");
            }

            

            if(response.ok){
                
                salty = data.salt;
                
                
                hashedPassword = await hashPassword(password);

                    

                
                // Convert the received salt and derived key from Base64 to byte arrays
                const storedSalt = base64ToUint8Array(data.salt);
                const storedDerivedKey = data.derivedKey;

                // Derive encryption key from master password and stored salt
                const derivedKey = await deriveKey(hashedPassword, storedSalt);
                const convertedDerivedkey = arrayBufferToBase64(derivedKey);

                
                if (convertedDerivedkey !== storedDerivedKey) {
                    alert("Incorrect master password. Reload the page to re-enter");
                    return false;
                }

                const siteName = window.location.hostname;
                const result = await getPasswordBySiteName(siteName, salty);
                console.log(result);
                
                if(result.exists){

                    // Convert the encryption key and IV back to Uint8Array
                    //const E_Key = new Uint8Array(passwordData.encryptionKey.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
                    const E_Key= hexStringToUint8Array(hashedPassword);
                    

                    for (const entry of result.passwords) {
                        try {
                          const IV = new Uint8Array(entry.iv.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
                          const decryptedPassword = await decryptPassword(entry.encryptedPassword,IV, E_Key);
                          
                          if (decryptedPassword) {
                            // Found the decryptable one — use for auto-fill
                            const decryptedUsername = await decryptPassword(entry.username, IV, E_Key);
                            
                            const usernameField = document.querySelector('input[type="text"], input[type="email"], input[placeholder*="username"], input[placeholder*="benutzername"], input[placeholder*="e-mail"], input[placeholder*="login"]');
                            const passwordField = document.querySelector('input[type="password"]');
                            usernameField.value = decryptedUsername;
                            passwordField.value = decryptedPassword;

                            break;
                          }
                        else{

                            
        
                                form.addEventListener('submit', async (event) => {
                                    console.log("action succedded");
                                    event.preventDefault();
                                  const username = form.querySelector('input[type="text"], input[type="email"]')?.value;
                                  const passwort = form.querySelector('input[type="password"]')?.value;
                                  
                            
                                  // Step 2: Prompt the user to save the password
                                  
                                 
                                    const shouldSave = confirm("Do you want to save this password?");
                                    
                            
                                    
                                    if (shouldSave) {
                                        try {
                                        
                            
                                            hashedPassword = await hashPassword(password);
                                                
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
                                               
                                                const randomKey = hexStringToUint8Array(hashedPassword); 
                                                
                                                
                                                const iv = crypto.getRandomValues(new Uint8Array(12)); // Initialization vector
                                                
                                                // Encrypt the password
                                                const encryptedPassword = await encryptPassword(passwort, iv, randomKey);
                                                
                                                const encrypteduserName = await encryptPassword(username, iv, randomKey);
                                                
                                                // Send the new password to the backend
                                                const response = await fetch(`https://localhost:7277/api/Password/save?salty=${encodeURIComponent(salty)}`, {
                                                    method: "POST",
                                                    headers: { "Content-Type": "application/json" },
                                                    body: JSON.stringify({ siteName, username: encrypteduserName.encryptedData, password: encryptedPassword.encryptedData, // ✅ Send only encryptedData
                                                        iv: encryptedPassword.iv})
                                                    
                                                    
                                                });
                            
                                            
                                    
                                            
                                            
                                
                                                if (response.ok) {
                                                    alert("Password saved successfully.");
                                                    
                                                } else {
                                                    alert("Error saving password.");
                                                }
                            
                                        }
                                            
                                        catch (error) {
                                            console.error("Error:", error);
                                            alert("An error occurred. Please try again.");
                                        }
                                    }
                            
                                    
                                    form.submit();
                                    });
                            
                            
                            

                            


                        
                        }

                        } catch (err) {
                          // Decryption failed — try next
                          continue;
                        }
                    
                    }        

                }

                else{
        
                    form.addEventListener('submit', async (event) => {
                        console.log("action succedded");
                        event.preventDefault();
                      const username = form.querySelector('input[type="text"], input[type="email"]')?.value;
                      const passwort = form.querySelector('input[type="password"]')?.value;
                      
                
                      // Step 2: Prompt the user to save the password
                      
                     
                        const shouldSave = confirm("Do you want to save this password?");
                        
                
                        
                        if (shouldSave) {
                            try {
                            
                
                                hashedPassword = await hashPassword(password);
                                    
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
                                   
                                    const randomKey = hexStringToUint8Array(hashedPassword); 
                                    
                                    
                                    const iv = crypto.getRandomValues(new Uint8Array(12)); // Initialization vector
                                    
                                    // Encrypt the password
                                    const encryptedPassword = await encryptPassword(passwort, iv, randomKey);
                                    
                                    const encrypteduserName = await encryptPassword(username, iv, randomKey);
                                    
                                    // Send the new password to the backend
                                    const response = await fetch(`https://localhost:7277/api/Password/save?salty=${encodeURIComponent(salty)}`, {
                                        method: "POST",
                                        headers: { "Content-Type": "application/json" },
                                        body: JSON.stringify({ siteName, username: encrypteduserName.encryptedData, password: encryptedPassword.encryptedData, // ✅ Send only encryptedData
                                            iv: encryptedPassword.iv})
                                        
                                        
                                    });
                
                                
                        
                                
                                
                    
                                    if (response.ok) {
                                        alert("Password saved successfully.");
                                        
                                    } else {
                                        alert("Error saving password.");
                                    }
                
                            }
                                
                            catch (error) {
                                console.error("Error:", error);
                                alert("An error occurred. Please try again.");
                            }
                        }
                
                        
                        form.submit();
                        });
                
                
                }

            }


            

            
    }
    
    
}




  // Run detection on page load
  detectLoginForms();

  async function encryptPassword(password, iv, E_Key) {
    
    const encoder = new TextEncoder();
    const data = encoder.encode(password);

    const key = await crypto.subtle.importKey(
        "raw",
        E_Key, // ✅ Use the raw Uint8Array
        { name: "AES-GCM" },
        false,
        ["encrypt"]
    );

    
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        data
    );

    // Convert the encrypted result to a Uint8Array
    const encryptedArray = new Uint8Array(encrypted);

    // The authentication tag is the last 16 bytes of the encrypted data
    const ciphertext = encryptedArray.slice(0, encryptedArray.length - 16); // Ciphertext
    const authTag = encryptedArray.slice(encryptedArray.length - 16); // Authentication tag

    // Combine ciphertext and authentication tag into one array
    const combinedEncryptedData = new Uint8Array(encryptedArray.length);
    combinedEncryptedData.set(ciphertext, 0);
    combinedEncryptedData.set(authTag, ciphertext.length);

    return {
        iv: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(''),
        encryptedData: Array.from(combinedEncryptedData).map(b => b.toString(16).padStart(2, '0')).join('') // Convert to hex string
    };
}



  async function decryptPassword(encryptedPassword, iv, E_Key) {
    // Check if parameters are valid
    if (!encryptedPassword || !iv) {
        console.error("Decryption Error: Missing encrypted data or IV.");
        return null;
    }

    try {
        // Convert hex IV and encrypted data back to Uint8Array
        //const ivArray = new Uint8Array(iv.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        const encryptedArray = new Uint8Array(encryptedPassword.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        const ivArray = iv;
        
        // Ensure the IV is 12 bytes for AES-GCM
        if (ivArray.length !== 12) {
            console.error("Decryption Error: IV length must be 12 bytes for AES-GCM.");
            return null;
        }

        // Ensure encryption key is a properly formatted Uint8Array (32 bytes)
        const keyBuffer = await crypto.subtle.importKey(
            "raw",
            E_Key, // This must be a Uint8Array (not a string)
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );

        // Split encrypted data into ciphertext and authentication tag (last 16 bytes)
        const authTagLength = 16; // AES-GCM authentication tag length is 16 bytes
        const ciphertext = encryptedArray.slice(0, encryptedArray.length - authTagLength); // Ciphertext without the auth tag
        const authTag = encryptedArray.slice(encryptedArray.length - authTagLength); // Last 16 bytes are the authentication tag

        // Ensure the total length matches
        if (ciphertext.length + authTag.length !== encryptedArray.length) {
            console.error("Decryption Error: Incorrect encrypted data structure.");
            return null;
        }

        

        // Decrypt the password (include the authentication tag)
        const decrypted = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: ivArray,
                additionalData: new Uint8Array(), // You can include additional data here if used
                tagLength: authTagLength * 8, // Tag length in bits (16 bytes = 128 bits)
            },
            keyBuffer,
            encryptedArray // Pass the combined array (ciphertext + auth tag)
        );

        return new TextDecoder().decode(decrypted);

    } catch (error) {
        console.error("Decryption failed:", error);
        return null;
    }
}

// Derive key from password and salt
async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password); // Convert password to bytes
    const saltBytes = new TextEncoder().encode(salt); // Convert salt to bytes
    
    // Import the password as a key material with the 'extractable' property set to true
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw", 
        passwordBytes, 
        { name: "PBKDF2" }, 
        false, 
        ["deriveKey"]
    );
    
    // Derive the key using PBKDF2, specifying 'extractable' as true for the derived key
    const derivedKey = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: saltBytes,
            iterations: 100000, // Number of iterations
            hash: "SHA-256" // Hashing algorithm
        },
        keyMaterial, 
        { name: "AES-GCM", length: 256 }, // You can adjust the key length here
        true, // Mark the derived key as extractable
        ["encrypt", "decrypt"] // Specify the key usages
    );
    
    // Export the derived key as a raw binary buffer
    const derivedKeyBuffer = await window.crypto.subtle.exportKey("raw", derivedKey);
    
    return derivedKeyBuffer; // Return the derived key as an ArrayBuffer
}


// Convert Uint8Array to Base64 string
function arrayBufferToBase64(arrayBuffer) {
    const uint8Array = new Uint8Array(arrayBuffer);
    let binary = '';
    for (let i = 0; i < uint8Array.length; i++) {
        binary += String.fromCharCode(uint8Array[i]);
    }
    return window.btoa(binary); // Use the global btoa function to encode in base64
}


function base64ToUint8Array(base64String) {
    // Decode base64 string to binary string
    const binaryString = window.atob(base64String);

    // Create an array of bytes from the binary string
    const byteArray = new Uint8Array(binaryString.length);

    // Fill the byte array with values from the binary string
    for (let i = 0; i < binaryString.length; i++) {
        byteArray[i] = binaryString.charCodeAt(i);
    }

    return byteArray;
}

function saveMasterPassword(hashedPassword) {
    const timestamp = Date.now();
    sessionStorage.setItem("masterPassword", hashedPassword);
    sessionStorage.setItem("timestamp", timestamp.toString());
}

function getValidMasterPassword() {
    const stored = sessionStorage.getItem("masterPassword");
    const timestamp = parseInt(sessionStorage.getItem("timestamp"));

    if (!stored || isNaN(timestamp)) return null;

    const now = Date.now();
    const THIRTY_MINUTES = 30 * 60 * 1000;

    if (now - timestamp > THIRTY_MINUTES) {
        sessionStorage.removeItem("masterPassword");
        sessionStorage.removeItem("timestamp");
        return null;
    }

    return stored;
}
