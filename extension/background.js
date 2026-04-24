// Background service worker for Calendur
// Uses authorization code flow with refresh tokens for persistent auth

const REDIRECT_URI = chrome.identity.getRedirectURL();
const SCOPES = [
  'https://www.googleapis.com/auth/calendar',
  'https://www.googleapis.com/auth/userinfo.email',
].join(' ');

let cachedAccessToken = null;
let cachedAccessTokenExpiresAt = null;
let cachedRefreshToken = null;
let refreshPromise = null;

// Restore tokens from storage on service worker startup
chrome.storage.local.get(
  ['accessToken', 'accessTokenExpiresAt', 'refreshToken', 'authToken'],
  (result) => {
    // Migrate from old implicit flow storage keys
    if (result.authToken && !result.accessToken) {
      chrome.storage.local.remove(['authToken', 'authTokenExpiresAt']);
      return;
    }
    if (result.accessToken) {
      cachedAccessToken = result.accessToken;
      cachedAccessTokenExpiresAt = result.accessTokenExpiresAt || null;
    }
    if (result.refreshToken) {
      cachedRefreshToken = result.refreshToken;
    }
  }
);

function getClientId() {
  return chrome.runtime.getManifest().oauth2.client_id;
}

async function getBackendUrl() {
  const { backendUrl } = await chrome.storage.sync.get({ backendUrl: '' });
  return backendUrl;
}

function isTokenFresh() {
  if (!cachedAccessToken || !cachedAccessTokenExpiresAt) return false;
  return Date.now() < cachedAccessTokenExpiresAt - 60000;
}

function saveTokens(accessToken, expiresIn, refreshToken) {
  const expiresAt = Date.now() + expiresIn * 1000;
  cachedAccessToken = accessToken;
  cachedAccessTokenExpiresAt = expiresAt;
  const data = { accessToken, accessTokenExpiresAt: expiresAt };
  if (refreshToken) {
    cachedRefreshToken = refreshToken;
    data.refreshToken = refreshToken;
  }
  chrome.storage.local.set(data);
}

function clearTokens() {
  cachedAccessToken = null;
  cachedAccessTokenExpiresAt = null;
  cachedRefreshToken = null;
  chrome.storage.local.remove(['accessToken', 'accessTokenExpiresAt', 'refreshToken']);
}

function extractAuthCode(redirectUrl) {
  const url = new URL(redirectUrl);
  return url.searchParams.get('code');
}

async function exchangeCodeForTokens(code) {
  const backendUrl = await getBackendUrl();
  if (!backendUrl) throw new Error('Backend URL not configured. Set it in Settings.');
  const res = await fetch(`${backendUrl}/api/auth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code, redirect_uri: REDIRECT_URI }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `Token exchange failed (${res.status})`);
  }
  return res.json();
}

async function refreshAccessToken() {
  const backendUrl = await getBackendUrl();
  if (!backendUrl) throw new Error('Backend URL not configured. Set it in Settings.');
  const res = await fetch(`${backendUrl}/api/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: cachedRefreshToken }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    if (res.status === 400 || res.status === 401) {
      clearTokens(); // Refresh token revoked/invalid
    }
    throw new Error(err.error || `Token refresh failed (${res.status})`);
  }
  return res.json();
}

async function doInteractiveAuth() {
  const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  authUrl.searchParams.set('client_id', getClientId());
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', SCOPES);
  authUrl.searchParams.set('access_type', 'offline');
  authUrl.searchParams.set('prompt', 'consent');

  return new Promise((resolve, reject) => {
    chrome.identity.launchWebAuthFlow(
      { url: authUrl.toString(), interactive: true },
      async (redirectUrl) => {
        try {
          if (chrome.runtime.lastError) {
            throw new Error(chrome.runtime.lastError.message);
          }
          if (!redirectUrl) {
            throw new Error('No redirect URL received');
          }
          const code = extractAuthCode(redirectUrl);
          if (!code) {
            throw new Error('No authorization code in response');
          }
          const data = await exchangeCodeForTokens(code);
          saveTokens(data.access_token, data.expires_in, data.refresh_token);
          resolve(cachedAccessToken);
        } catch (err) {
          reject(err);
        }
      }
    );
  });
}

async function getValidToken(interactive) {
  if (refreshPromise) return refreshPromise;

  // Fast path: in-memory token is fresh
  if (cachedAccessToken && isTokenFresh()) return cachedAccessToken;

  // Check storage (service worker may have restarted)
  const stored = await chrome.storage.local.get([
    'accessToken', 'accessTokenExpiresAt', 'refreshToken',
  ]);
  if (stored.accessToken) {
    cachedAccessToken = stored.accessToken;
    cachedAccessTokenExpiresAt = stored.accessTokenExpiresAt || null;
    cachedRefreshToken = stored.refreshToken || cachedRefreshToken;
    if (isTokenFresh()) return cachedAccessToken;
  }

  // Silent refresh if we have a refresh token
  if (cachedRefreshToken) {
    refreshPromise = (async () => {
      try {
        const data = await refreshAccessToken();
        saveTokens(data.access_token, data.expires_in);
        return cachedAccessToken;
      } catch {
        // Refresh failed — fall through to interactive if allowed
        if (!interactive) return null;
        return doInteractiveAuth();
      }
    })().finally(() => { refreshPromise = null; });
    return refreshPromise;
  }

  // No refresh token — need interactive auth
  if (!interactive) return null;

  refreshPromise = doInteractiveAuth().finally(() => { refreshPromise = null; });
  return refreshPromise;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'getAuthToken') {
    getValidToken(message.interactive !== false)
      .then(token => sendResponse({ token }))
      .catch(err => sendResponse({ error: err.message }));
    return true;
  }

  if (message.type === 'removeCachedToken') {
    clearTokens();
    sendResponse({ success: true });
    return true;
  }

  if (message.type === 'getUserInfo') {
    (async () => {
      try {
        const token = await getValidToken(false);
        if (!token) {
          sendResponse({ error: 'Not authenticated' });
          return;
        }
        const res = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.status === 401) {
          clearTokens();
          sendResponse({ error: 'Token expired' });
          return;
        }
        const info = await res.json();
        sendResponse({ email: info.email, name: info.name });
      } catch (err) {
        sendResponse({ error: err.message });
      }
    })();
    return true;
  }
});
