// Encryption using Web Crypto API
async function encrypt(text, key) {
    const enc = new TextEncoder();
    const encodedText = enc.encode(text);
    const derivedKey = await deriveKey(key);

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedData = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        derivedKey,
        encodedText
    );

    return JSON.stringify({ iv: Array.from(iv), data: Array.from(new Uint8Array(encryptedData)) });
}

async function decrypt(encryptedText, key) {
    const parsed = JSON.parse(encryptedText);
    const derivedKey = await deriveKey(key);

    const decryptedData = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: new Uint8Array(parsed.iv) },
        derivedKey,
        new Uint8Array(parsed.data)
    );

    return new TextDecoder().decode(decryptedData);
}

async function deriveKey(password) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: new Uint8Array(16),
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}
