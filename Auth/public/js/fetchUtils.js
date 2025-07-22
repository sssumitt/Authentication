// fetchUtils.js
export const csrfTokenRef = { value: '' };

export async function getCsrfToken() {
  try {
    const res = await fetch('/auth/csrf-token', { credentials: 'include' });
    if (!res.ok) throw new Error(`Status ${res.status}`);
    const { csrfToken } = await res.json();
    csrfTokenRef.value = csrfToken;
    document.getElementById('response').innerText = 'CSRF token ready.';
  } catch (err) {
    document.getElementById('response').innerText = 'CSRF error: ' + err;
  }
}

export async function fetchWithAutoRefresh(url, opts = {}) {
  opts.credentials = 'include';
  if (opts.method && opts.method !== 'GET') {
    opts.headers = { ...opts.headers, 'X-CSRF-Token': csrfTokenRef.value };
  }

  let res = await fetch(url, opts);
  if (res.status === 401 && url !== '/auth/refresh') {
    // attempt refresh
    const r = await fetch('/auth/refresh', {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-CSRF-Token': csrfTokenRef.value }
    });
    if (!r.ok) throw new Error('Refresh failed');
    const { csrfToken } = await r.json();
    csrfTokenRef.value = csrfToken || csrfTokenRef.value;
    res = await fetch(url, opts);
  }
  return res;
}

export async function parseResponse(res) {
  const ct = res.headers.get('Content-Type') || '';
  if (ct.includes('application/json')) return res.json();
  return { message: await res.text() };
}

export function showResult(prefix, res, data) {
  const msg = data.error || data.message || 'No content';
  document.getElementById('response').innerText = `${prefix} (${res.status}): ${msg}`;
}
