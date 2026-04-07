// Background service worker for Calendur
// Uses launchWebAuthFlow for OAuth (works with unpacked extensions in Brave/Chrome)

const EXTENSION_ID = 'ckjcklpepkfibnjihnmngpblljdafmha';
const REDIRECT_URI = `https://${EXTENSION_ID}.chromiumapp.org/`;
const SCOPES = [
  'https://www.googleapis.com/auth/calendar',
  'https://www.googleapis.com/auth/userinfo.email',
].join(' ');

let cachedToken = null;

async function getClientId() {
  const manifest = chrome.runtime.getManifest();
  return manifest.oauth2.client_id;
}

async function launchAuth(interactive) {
  if (cachedToken) return cachedToken;

  if (!interactive) return null;

  const clientId = await getClientId();
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
    sendResponse({ success: true });
    return true;
  }

  if (message.type === 'getUserInfo') {
    (async () => {
      try {
        const token = cachedToken;
        if (!token) {
          sendResponse({ error: 'Not authenticated' });
          return;
        }
        const res = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
          headers: { Authorization: `Bearer ${token}` },
        });
        const info = await res.json();
        sendResponse({ email: info.email, name: info.name });
      } catch (err) {
        sendResponse({ error: err.message });
      }
    })();
    return true;
  }
});
