import {
  getCsrfToken,
  fetchWithAutoRefresh,
  parseResponse,
  showResult,
  csrfTokenRef
} from './fetchUtils.js';

async function register() {
  const u = document.getElementById('username').value;
  const p = document.getElementById('password').value;
  try {
    const res = await fetch('/auth/register', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfTokenRef.value
      },
      body: JSON.stringify({ username: u, password: p })
    });
    const data = await parseResponse(res);
    showResult(res.ok ? 'Registered' : 'Register failed', res, data);
  } catch (err) {
    document.getElementById('response').innerText = 'Register error: ' + err;
  }
}

async function login() {
  const u = document.getElementById('username').value;
  const p = document.getElementById('password').value;
  try {
    const res = await fetch('/auth/login', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfTokenRef.value
      },
      body: JSON.stringify({ username: u, password: p })
    });
    const data = await parseResponse(res);
    if (!res.ok) return showResult('Login failed', res, data);

    // update CSRF token and show logout
    csrfTokenRef.value = data.csrfToken || csrfTokenRef.value;
    showLogoutButton();

    // fetch protected data
    const prot = await fetchWithAutoRefresh('/protected');
    const pd = await parseResponse(prot);
    showResult('Protected data', prot, pd);
  } catch (err) {
    document.getElementById('response').innerText = 'Login error: ' + err;
  }
}

async function logout() {
  try {
    const res = await fetch('/auth/logout', {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-CSRF-Token': csrfTokenRef.value }
    });
    const data = await parseResponse(res);
    if (res.ok) {
      document.getElementById('response').innerText = 'Logged out';
      hideLogoutButton();
      await getCsrfToken();
    } else {
      document.getElementById('response').innerText = 'Logout failed: ' + data.error;
    }
  } catch (err) {
    document.getElementById('response').innerText = 'Logout error: ' + err;
  }
}

function showLogoutButton() {
  const btn = document.getElementById('logoutBtn');
  if (btn) btn.style.display = 'block';
}
function hideLogoutButton() {
  const btn = document.getElementById('logoutBtn');
  if (btn) btn.style.display = 'none';
}

// bind events
document.getElementById('loginBtn').addEventListener('click', login);
document.getElementById('registerBtn').addEventListener('click', register);
document.getElementById('logoutBtn').addEventListener('click', logout);

window.addEventListener('DOMContentLoaded', async () => {
  const params = new URLSearchParams(window.location.search);
  if (params.get('oauth') === 'success') {
    await getCsrfToken();       // important for logout
    showLogoutButton();
    try {
      const res = await fetchWithAutoRefresh('/protected');
      const data = await parseResponse(res);
      showResult('Protected data', res, data);
    } catch (err) {
      document.getElementById('response').innerText = 'OAuth error: ' + err;
    }
  } else {
    hideLogoutButton();
    await getCsrfToken();
  }
});
