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

async function launchAuth(interactive) {
  if (cachedToken) return cachedToken;

  // Check storage in case service worker restarted before async restore finished
  const stored = await chrome.storage.local.get('authToken');
  if (stored.authToken) {
    cachedToken = stored.authToken;
    return cachedToken;
  }

  if (!interactive) return null;

  const clientId = getClientId();
  const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('response_type', 'token');
  authUrl.searchParams.set('scope', SCOPES);
  authUrl.searchParams.set('prompt', 'consent');

  return new Promise((resolve, reject) => {
    chrome.identity.launchWebAuthFlow(
      { url: authUrl.toString(), interactive },
      (redirectUrl) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        if (!redirectUrl) {
          reject(new Error('No redirect URL received'));
          return;
        }
        const url = new URL(redirectUrl);
        const hash = url.hash.substring(1);
        const params = new URLSearchParams(hash);
        const token = params.get('access_token');
        if (token) {
          cachedToken = token;
          chrome.storage.local.set({ authToken: token });
          resolve(token);
        } else {
          reject(new Error('No access token in response'));
        }
      }
    );
  });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'getAuthToken') {
    launchAuth(message.interactive !== false)
      .then(token => sendResponse({ token }))
      .catch(err => sendResponse({ error: err.message }));
    return true;
  }

  if (message.type === 'removeCachedToken') {
    cachedToken = null;
    chrome.storage.local.remove('authToken');
    sendResponse({ success: true });
    return true;
  }

  if (message.type === 'getUserInfo') {
    (async () => {
      try {
        let token = cachedToken;
        if (!token) {
          const stored = await chrome.storage.local.get('authToken');
          token = stored.authToken || null;
          if (token) cachedToken = token;
        }
        if (!token) {
          sendResponse({ error: 'Not authenticated' });
          return;
        }
        const res = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.status === 401) {
          // Token expired — clear it so user can re-authenticate
          cachedToken = null;
          chrome.storage.local.remove('authToken');
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
