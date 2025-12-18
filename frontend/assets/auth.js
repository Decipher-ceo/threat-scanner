// Authentication state management
// BYPASS: Mock user permanently set
let currentUser = {
    username: 'Developer',
    email: 'dev@local.host',
    is_admin: true,
    id: 1
};
const API_BASE_URL = window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost'
    ? 'http://localhost:5000/api'
    : '/api'; // Adjusted for Vercel rewrites

// Initialize auth state
function initAuth() {
    console.log('Initializing auth (BYPASS MODE)...');
    // Always set currentUser if it got cleared somehow, though variable init handles it
    if (!currentUser) {
        currentUser = {
            username: 'Developer',
            email: 'dev@local.host',
            is_admin: true,
            id: 1
        };
    }
    // Fake token presence
    localStorage.setItem('authToken', 'mock-token');
    localStorage.setItem('currentUser', JSON.stringify(currentUser));

    return Promise.resolve();
}

/**
 * Call this on protected pages (Dashboard, Reports, etc.)
 * Redirects to login if NOT authenticated.
 */
/**
 * Call this on protected pages (Dashboard, Reports, etc.)
 * Redirects to login if NOT authenticated.
 */
function protectRoute() {
    // BYPASS: Do nothing, allow access
    console.log('protectRoute called: Bypass active, access granted.');
}

/**
 * Call this on public auth pages (Login, Signup)
 * Redirects to dashboard if ALREADY authenticated.
 */
/**
 * Call this on public auth pages (Login, Signup)
 * Redirects to dashboard if ALREADY authenticated.
 */
function redirectIfLoggedIn() {
    // BYPASS: Do nothing, or optionally redirect if you want to force dashboard
    // For now, let's just log it.
    console.log('redirectIfLoggedIn called: Bypass active.');
}

// Verify token and get current user from backend
async function verifyTokenAndGetUser() {
    // BYPASS: Always return mock user
    console.log('verifyTokenAndGetUser called: Returning mock user.');
    return currentUser;
}

// Get auth token for API requests
function getAuthToken() {
    return localStorage.getItem('authToken');
}

// Update UI based on auth state
function updateAuthUI() {
    if (currentUser) {
        const userDisplay = document.getElementById('currentUserEmail');
        if (userDisplay) {
            userDisplay.textContent = `Logged in as: ${currentUser.email || currentUser.username}`;
        }

        // Show/hide auth-specific elements
        const authElements = document.querySelectorAll('.auth-required');
        authElements.forEach(el => el.style.display = 'block');

        const unauthElements = document.querySelectorAll('.unauth-only');
        unauthElements.forEach(el => el.style.display = 'none');
    } else {
        const authElements = document.querySelectorAll('.auth-required');
        authElements.forEach(el => el.style.display = 'none');

        const unauthElements = document.querySelectorAll('.unauth-only');
        unauthElements.forEach(el => el.style.display = 'block');
    }
}

// Handle logout
async function handleLogout() {
    // Show loading state if button exists
    const logoutBtn = document.getElementById('logoutBtn');
    const originalText = logoutBtn ? logoutBtn.textContent : '';
    if (logoutBtn) {
        logoutBtn.disabled = true;
        logoutBtn.textContent = 'Logging out...';
    }

    try {
        const token = getAuthToken();
        if (token) {
            // Call logout endpoint (optional, mainly for server-side session cleanup if needed)
            // Use a timeout to prevent hanging if server is unreachable
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3000); // 3 second timeout

            try {
                await fetch(`${API_BASE_URL}/auth/logout`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    },
                    signal: controller.signal
                });
            } catch (fetchError) {
                // Ignore fetch errors - we'll logout client-side anyway
                console.log('Logout request failed (continuing with client-side logout):', fetchError);
            } finally {
                clearTimeout(timeoutId);
            }
        }
    } catch (error) {
        console.error('Logout error:', error);
        // Continue with logout even if there's an error
    } finally {
        // Clear all auth data
        localStorage.removeItem('authToken');
        localStorage.removeItem('currentUser');
        currentUser = null;

        // Clear any session data
        sessionStorage.clear();

        // Clear any cookies
        document.cookie.split(";").forEach(function (c) {
            document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/");
        });

        // Redirect to login page
        window.location.href = 'login.html';
    }
}

// Update current user display on settings page
function updateUserDisplay() {
    const userEmailElement = document.getElementById('currentUserEmail');
    if (userEmailElement && currentUser) {
        userEmailElement.textContent = `Logged in as: ${currentUser.email || currentUser.username}`;
    }
}

// DOM Elements
const loginForm = document.getElementById('loginForm');
const signupForm = document.getElementById('signupForm');

// Check if user is logged in
function checkAuth() {
    if (currentUser) {
        // Redirect to dashboard if already logged in
        if (!window.location.pathname.includes('dashboard.html')) {
            window.location.href = 'dashboard.html';
        }
    } else if (!window.location.pathname.includes('login.html') &&
        !window.location.pathname.includes('signup.html')) {
        // Redirect to login if not on auth pages
        window.location.href = 'login.html';
    }
}

// Show error message
function showError(message, formId = '') {
    const errorElement = document.querySelector(`${formId} #errorMessage`);
    if (errorElement) {
        errorElement.textContent = message;
        errorElement.style.display = 'block';

        // Hide error after 5 seconds
        setTimeout(() => {
            errorElement.style.display = 'none';
        }, 5000);
    } else {
        alert(message);
    }
}

// Show success message
function showSuccess(message, formId = '') {
    const successElement = document.querySelector(`${formId} #successMessage`);
    if (successElement) {
        successElement.textContent = message;
        successElement.style.display = 'block';

        // Hide success message after 3 seconds
        setTimeout(() => {
            successElement.style.display = 'none';
        }, 3000);
    }
}

// Handle login
async function handleLogin(username, password) {
    try {
        const response = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Login failed');
        }

        // Store the token and user data
        localStorage.setItem('authToken', data.token);
        localStorage.setItem('currentUser', JSON.stringify(data.user));
        currentUser = data.user;

        // Update UI and redirect
        updateAuthUI();
        window.location.href = 'dashboard.html';
        return true;
    } catch (error) {
        console.error('Login error:', error);
        showError(error.message || 'Login failed. Please try again.', 'loginForm');
        return false;
    }
}

// Handle signup
async function handleSignup(username, email, password) {
    try {
        // Basic validation
        const confirmPassword = document.getElementById('confirmPassword')?.value;
        if (password !== confirmPassword) {
            showError('Passwords do not match', '#signupForm');
            return;
        }

        if (password.length < 6) {
            showError('Password must be at least 6 characters long', '#signupForm');
            return;
        }

        if (username.length < 3) {
            showError('Username must be at least 3 characters long', '#signupForm');
            return;
        }

        const response = await fetch(`${API_BASE_URL}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                email: email,
                password: password
            })
        });

        const data = await response.json();

        if (response.ok) {
            // Store token and user data
            localStorage.setItem('authToken', data.token);
            localStorage.setItem('currentUser', JSON.stringify(data.user));
            currentUser = data.user;

            showSuccess('Account created successfully! Redirecting...', '#signupForm');

            // Redirect to dashboard after a short delay
            setTimeout(() => {
                window.location.href = 'dashboard.html';
            }, 1500);
        } else {
            showError(data.error || 'An error occurred during signup', '#signupForm');
        }
    } catch (error) {
        console.error('Signup error:', error);
        showError('An error occurred during signup. Please check if the backend server is running.', '#signupForm');
    }
}

// Event Listeners
if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;

        if (!username || !password) {
            showError('Please fill in all fields', '#loginForm');
            return;
        }

        await handleLogin(username, password);
    });
}

if (signupForm) {
    signupForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value.trim();
        const email = document.getElementById('email').value.trim();
        const password = document.getElementById('password').value;

        if (!username || !email || !password) {
            showError('Please fill in all fields', '#signupForm');
            return;
        }

        await handleSignup(username, email, password);
    });
}

// Setup logout button handler (can be called multiple times safely)
function setupLogoutButton() {
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn && !logoutBtn.hasAttribute('data-logout-setup')) {
        logoutBtn.setAttribute('data-logout-setup', 'true');
        logoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            handleLogout();
        });
    }
}

// Check authentication on page load
document.addEventListener('DOMContentLoaded', () => {
    // Set up logout button if it exists
    setupLogoutButton();

    // Also setup logout buttons that might be added dynamically
    // Use MutationObserver to catch dynamically added logout buttons
    const observer = new MutationObserver(() => {
        setupLogoutButton();
    });

    // Observe the document body for changes
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });

    // Update user display if on settings page
    updateUserDisplay();

    // Initialize auth
    initAuth();
    updateAuthUI();

    // Verify token on page load
    if (currentUser) {
        verifyTokenAndGetUser();
    }
});

// Export for use in other scripts
window.auth = {
    currentUser: () => currentUser,
    logout: handleLogout,
    requireAuth: () => true, // Always true
    getToken: getAuthToken,
    protectRoute: protectRoute,
    redirectIfLoggedIn: redirectIfLoggedIn,
    isAuthenticated: async () => true // Always true
};
