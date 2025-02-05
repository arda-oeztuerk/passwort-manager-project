document.getElementById('unlock-btn').addEventListener('click', unlockVault);
document.getElementById('add-password-btn').addEventListener('click', showAddForm);
document.getElementById('save-password-btn').addEventListener('click', savePassword);
document.getElementById('cancel-btn').addEventListener('click', hideAddForm);

let masterPassword = '';

function showScreen(screenId) {
    // Hide all screens first
    document.querySelectorAll('.screen').forEach(screen => {
        screen.style.display = 'none';
    });

    // Show only the target screen
    const screen = document.getElementById(screenId);
    screen.style.display = 'block';
    screen.classList.remove('screen'); // Remove and re-add for animation
    void screen.offsetWidth; // Force reflow
    screen.classList.add('screen');
}

function unlockVault() {
    masterPassword = document.getElementById('master-password').value;
    if (masterPassword) {
        // Hide login container and show dashboard
        document.getElementById('login-container').style.display = 'none'; 
        showScreen('dashboard');
        loadPasswords();
    }
}

function showAddForm() {
    showScreen('password-form');
}

function hideAddForm() {
    showScreen('dashboard');
}

async function savePassword() {
    const site = document.getElementById('site-name').value;
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    if (site && username && password) {
        const encryptedPassword = await encrypt(password, masterPassword);
        
        const storedData = { site, username, encryptedPassword };
        let passwords = JSON.parse(localStorage.getItem('passwords')) || [];
        passwords.push(storedData);
        localStorage.setItem('passwords', JSON.stringify(passwords));

        loadPasswords();
        hideAddForm();
    } else {
        alert('Please fill all fields.');
    }
}

function loadPasswords() {
    let passwords = JSON.parse(localStorage.getItem('passwords')) || [];
    let list = document.getElementById('password-list');
    list.innerHTML = '';

    passwords.forEach((entry, index) => {
        let li = document.createElement('li');
        li.innerHTML = `${entry.site} - ${entry.username} 
            <button onclick="viewPassword(${index})">👁️</button> 
            <button onclick="deletePassword(${index})">❌</button>`;
        list.appendChild(li);
    });
}

async function viewPassword(index) {
    let passwords = JSON.parse(localStorage.getItem('passwords')) || [];
    const decryptedPassword = await decrypt(passwords[index].encryptedPassword, masterPassword);
    alert(`Password for ${passwords[index].site}: ${decryptedPassword}`);
}

function deletePassword(index) {
    let passwords = JSON.parse(localStorage.getItem('passwords')) || [];
    passwords.splice(index, 1);
    localStorage.setItem('passwords', JSON.stringify(passwords));
    loadPasswords();
}
