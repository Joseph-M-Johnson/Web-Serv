const loginForm = document.querySelector('#login-form');
const loginMessage = document.querySelector('#login-message');
const status = document.querySelector('#status');
const loginSection = document.querySelector('#login-section');
const logoutButton = document.querySelector('#logout-button');

async function checkAuthState() {
    try {
        const response = await fetch('/api/whoami');
        const data = await response.json();

        if (data.loggedIn) {
            status.innerHTML = `
                <div class="eyebrow">Welcome back</div>
                <h1>You're signed in.</h1>
                <p>Your workspace is ready to go. Open the dashboard to view your projects and continue managing the app.</p>
                <div class="hero-actions">
                    <a href="/dashboard" class="primary-button">Open dashboard</a>
                </div>
            `;
            loginSection.hidden = true;
            logoutButton.hidden = false;
        } else {
            status.innerHTML = `
                <div class="eyebrow">Landing page</div>
                <h1>Welcome to your Express app.</h1>
                <p>Log in with your password to access protected routes, manage the dashboard, and explore the project workspace.</p>
            `;
            loginSection.hidden = false;
            logoutButton.hidden = true;
        }
    } catch (error) {
        status.innerHTML = `
            <div class="eyebrow">Landing page</div>
            <h1>Welcome to your Express app.</h1>
            <p>Log in with your password to access protected routes.</p>
        `;
        loginSection.hidden = false;
        logoutButton.hidden = true;
    }
}

loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();

    const password = document.querySelector('#password').value;
    const rememberMe = event.target.rememberMe.checked;
    const response = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password, rememberMe })
    });

    const data = await response.json().catch(() => ({ success: false }));

    if (data.success) {
        loginMessage.textContent = 'Login successful!';
        loginForm.reset();
        await checkAuthState();
        window.location.href = '/';
    } else {
        loginMessage.textContent = data.error || 'Login failed. Please check your password.';
    }
});

logoutButton.addEventListener('click', async () => {
    const response = await fetch('/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    });

    const data = await response.json().catch(() => ({ success: false }));

    if (data.success) {
        window.location.href = '/';
    }
});

checkAuthState();
