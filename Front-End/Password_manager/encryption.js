
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
        console.log("IV Array:", ivArray);
        console.log("Encrypted Array:", encryptedArray);

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

        console.log("All okay, till here");

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



