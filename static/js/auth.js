/**
 * TraceX - Authentication Client Handler
 * Validates credentials, manages loading states, and handles AJAX authentication.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Login Form Handler
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      const usernameInput = document.getElementById('username');
      const passwordInput = document.getElementById('password');
      const submitBtn = document.getElementById('login-submit-btn');
      const errorBox = document.getElementById('auth-error-box');

      const username = usernameInput ? usernameInput.value.trim() : '';
      const password = passwordInput ? passwordInput.value : '';

      // Reset error box
      if (errorBox) {
        errorBox.style.display = 'none';
        errorBox.textContent = '';
      }

      if (!username || !password) {
        showAuthError('Please enter both username and password.');
        return;
      }

      // Loading state
      const originalText = submitBtn.textContent;
      submitBtn.disabled = true;
      submitBtn.textContent = 'Logging in...';

      try {
        const response = await fetch('/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          body: JSON.stringify({ username, password })
        });

        const data = await response.json().catch(() => ({}));

        if (response.ok && data.success) {
          submitBtn.textContent = 'Success! Redirecting...';
          showToast('Login successful. Loading dashboard...', 'success');
          setTimeout(() => {
            window.location.href = '/dashboard';
          }, 400);
        } else {
          const errMsg = data.error || 'Authentication failed. Please verify credentials.';
          showAuthError(errMsg);
          submitBtn.disabled = false;
          submitBtn.textContent = originalText;
        }
      } catch (err) {
        console.error('Login network error:', err);
        showAuthError('A network error occurred. Please verify your connection.');
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
      }
    });
  }

  // Register Form Handler
  const registerForm = document.getElementById('register-form');
  if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      const usernameInput = document.getElementById('reg-username');
      const passwordInput = document.getElementById('reg-password');
      const confirmInput = document.getElementById('reg-confirm-password');
      const submitBtn = document.getElementById('reg-submit-btn');
      const errorBox = document.getElementById('auth-error-box');

      const username = usernameInput ? usernameInput.value.trim() : '';
      const password = passwordInput ? passwordInput.value : '';
      const confirmPassword = confirmInput ? confirmInput.value : '';

      // Reset error box
      if (errorBox) {
        errorBox.style.display = 'none';
        errorBox.textContent = '';
      }

      // Client validation
      if (!username) {
        showAuthError('Username is required.');
        return;
      }

      if (username.length < 3) {
        showAuthError('Username must be at least 3 characters long.');
        return;
      }

      if (password.length < 8) {
        showAuthError('Password must be at least 8 characters long.');
        return;
      }

      if (password !== confirmPassword) {
        showAuthError('Passwords do not match.');
        return;
      }

      // Loading state
      const originalText = submitBtn.textContent;
      submitBtn.disabled = true;
      submitBtn.textContent = 'Creating account...';

      try {
        const response = await fetch('/register', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          body: JSON.stringify({
            username: username,
            password: password,
            confirm_password: confirmPassword
          })
        });

        const data = await response.json().catch(() => ({}));

        if (response.ok && data.success) {
          submitBtn.textContent = 'Account Created!';
          showToast('Account registered successfully. Redirecting to login...', 'success');
          setTimeout(() => {
            window.location.href = '/login';
          }, 800);
        } else {
          const errMsg = data.error || 'Registration failed. Please try a different username.';
          showAuthError(errMsg);
          submitBtn.disabled = false;
          submitBtn.textContent = originalText;
        }
      } catch (err) {
        console.error('Registration network error:', err);
        showAuthError('A network error occurred. Please check connection and try again.');
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
      }
    });
  }

  function showAuthError(msg) {
    const errorBox = document.getElementById('auth-error-box');
    if (errorBox) {
      errorBox.textContent = msg;
      errorBox.style.display = 'flex';
    } else {
      showToast(msg, 'danger');
    }
  }
});
