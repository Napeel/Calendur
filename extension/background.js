// Background service worker for Calendur
// Uses launchWebAuthFlow for OAuth (works with unpacked extensions in Brave/Chrome)

const REDIRECT_URI = chrome.identity.getRedirectURL();
const SCOPES = [
  'https://www.googleapis.com/auth/calendar',
  'https://www.googleapis.com/auth/userinfo.email',
].join(' ');

let cachedToken = null;

// Restore token from storage on service worker startup
chrome.storage.local.get('authToken', (result) => {
  if (result.authToken) cachedToken = result.authToken;
});

function getClientId() {
  return chrome.runtime.getManifest().oauth2.client_id;
}

function buildAuthUrl(prompt) {
  const clientId = getClientId();
  const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('response_type', 'token');
  authUrl.searchParams.set('scope', SCOPES);
  if (prompt) authUrl.searchParams.set('prompt', prompt);
  return authUrl.toString();
}

function extractToken(redirectUrl) {
  const url = new URL(redirectUrl);
  const hash = url.hash.substring(1);
  const params = new URLSearchParams(hash);
  return params.get('access_token');
}

function saveToken(token) {
  cachedToken = token;
  chrome.storage.local.set({ authToken: token });
}

function clearToken() {
  cachedToken = null;
  chrome.storage.local.remove('authToken');
}

// Try silent re-auth first (no popup), fall back to interactive if needed
async function refreshTokenSilently() {
  return new Promise((resolve) => {
    chrome.identity.launchWebAuthFlow(
      { url: buildAuthUrl('none'), interactive: false },
      (redirectUrl) => {
        if (chrome.runtime.lastError || !redirectUrl) {
          resolve(null);
          return;
        }
        const token = extractToken(redirectUrl);
        if (token) {
          saveToken(token);
          resolve(token);
        } else {
          resolve(null);
        }
      }
    );
  });
}

async function launchAuth(interactive) {
  if (cachedToken) return cachedToken;

  // Check storage in case service worker restarted before async restore finished
  const stored = await chrome.storage.local.get('authToken');
  if (stored.authToken) {
    cachedToken = stored.authToken;
    return cachedToken;
  }

  // Try silent renewal first (uses existing Google session cookie)
  const silentToken = await refreshTokenSilently();
  if (silentToken) return silentToken;

  if (!interactive) return null;

  // Fall back to interactive consent
  return new Promise((resolve, reject) => {
    chrome.identity.launchWebAuthFlow(
      { url: buildAuthUrl('consent'), interactive: true },
      (redirectUrl) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        if (!redirectUrl) {
          reject(new Error('No redirect URL received'));
          return;
        }
        const token = extractToken(redirectUrl);
        if (token) {
          saveToken(token);
          resolve(token);
        } else {
          reject(new Error('No access token in response'));
        }
      }
    );
  });
}

// Validate token, silently refresh if expired
async function getValidToken() {
  let token = cachedToken;
  if (!token) {
    const stored = await chrome.storage.local.get('authToken');
    token = stored.authToken || null;
    if (token) cachedToken = token;
  }
  if (!token) return null;

  // Quick validation
  const res = await fetch('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=' + token);
  if (res.ok) return token;

  // Token expired — try silent refresh
  clearToken();
  return refreshTokenSilently();
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'getAuthToken') {
    launchAuth(message.interactive !== false)
      .then(token => sendResponse({ token }))
      .catch(err => sendResponse({ error: err.message }));
    return true;
  }

  if (message.type === 'removeCachedToken') {
    clearToken();
    sendResponse({ success: true });
    return true;
  }

  if (message.type === 'getUserInfo') {
    (async () => {
      try {
        const token = await getValidToken();
        if (!token) {
          sendResponse({ error: 'Not authenticated' });
          return;
        }
        const res = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) {
          clearToken();
          sendResponse({ error: 'Failed to get user info' });
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
