// ---- State management ----

const states = {
  input: document.getElementById('state-input'),
  preview: document.getElementById('state-preview'),
  confirm: document.getElementById('state-confirm'),
};

let parsedEvent = null;
let createdEventLink = null;

function showState(name) {
  Object.values(states).forEach(el => el.classList.remove('active'));
  states[name].classList.add('active');
  hideError();
}

// ---- Error handling ----

const errorBanner = document.getElementById('error-banner');
const errorText = document.getElementById('error-text');
const errorRetry = document.getElementById('error-retry');

let lastRetryFn = null;

function showError(message, retryFn) {
  errorText.textContent = message;
  errorBanner.classList.add('visible');
  lastRetryFn = retryFn || null;
  errorRetry.style.display = retryFn ? 'inline' : 'none';
}

function hideError() {
  errorBanner.classList.remove('visible');
  lastRetryFn = null;
}

errorRetry.addEventListener('click', () => {
  if (lastRetryFn) lastRetryFn();
});

// ---- Settings helpers ----

async function getSettings() {
  return new Promise(resolve => {
    chrome.storage.sync.get(
      {
        backendUrl: 'http://localhost:3000',
        defaultCalendarId: 'primary',
        defaultDuration: 30,
        defaultReminders: [{ method: 'popup', minutes: 10 }],
      },
      resolve
    );
  });
}

// ---- Parse ----

const eventText = document.getElementById('event-text');
const btnParse = document.getElementById('btn-parse');

async function parseEvent() {
  const text = eventText.value.trim();
  if (!text) return;

  btnParse.disabled = true;
  btnParse.innerHTML = '<span class="loading"></span> Parsing...';
  hideError();

  try {
    const settings = await getSettings();
    const response = await fetch(`${settings.backendUrl}/api/parse`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        currentDate: new Date().toISOString(),
        defaultDuration: settings.defaultDuration,
      }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Server error (${response.status})`);
    }

    parsedEvent = await response.json();
    populatePreview(parsedEvent);
    showState('preview');
  } catch (err) {
    showError(err.message || 'Failed to parse event. Check your connection.', parseEvent);
  } finally {
    btnParse.disabled = false;
    btnParse.textContent = 'Parse Event →';
  }
}

btnParse.addEventListener('click', parseEvent);

// Allow Ctrl+Enter / Cmd+Enter to submit
eventText.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
    parseEvent();
  }
});

// ---- Preview ----

const previewTitle = document.getElementById('preview-title');
const previewDate = document.getElementById('preview-date');
const previewTime = document.getElementById('preview-time');
const previewLocation = document.getElementById('preview-location');
const locationField = document.getElementById('location-field');
const previewRecurrence = document.getElementById('preview-recurrence');
const recurrenceField = document.getElementById('recurrence-field');
const previewCalendar = document.getElementById('preview-calendar');

function populatePreview(event) {
  previewTitle.value = event.title || '';

  // Parse start datetime for date and time fields
  if (event.start) {
    const startDate = new Date(event.start);
    previewDate.value = event.start.split('T')[0];

    const startTime = formatTime(startDate);
    let timeStr = startTime;
    if (event.end) {
      const endTime = formatTime(new Date(event.end));
      timeStr = `${startTime} – ${endTime}`;
    }
    previewTime.value = timeStr;
  }

  // Location
  if (event.location) {
    previewLocation.value = event.location;
    locationField.style.display = 'block';
  } else {
    locationField.style.display = 'none';
  }

  // Recurrence
  if (event.recurrence && event.recurrence.length > 0) {
    previewRecurrence.textContent = rruleToHuman(event.recurrence[0]);
    recurrenceField.style.display = 'block';
  } else {
    recurrenceField.style.display = 'none';
  }

  // Load calendars
  loadCalendars();
}

function formatTime(date) {
  return date.toLocaleTimeString('en-US', {
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
  });
}

function rruleToHuman(rrule) {
  const parts = rrule.replace('RRULE:', '').split(';');
  const map = {};
  parts.forEach(p => {
    const [k, v] = p.split('=');
    map[k] = v;
  });

  const dayNames = { MO: 'Monday', TU: 'Tuesday', WE: 'Wednesday', TH: 'Thursday', FR: 'Friday', SA: 'Saturday', SU: 'Sunday' };
  const freqMap = { DAILY: 'Daily', WEEKLY: 'Weekly', MONTHLY: 'Monthly', YEARLY: 'Yearly' };

  let str = freqMap[map.FREQ] || map.FREQ;
  if (map.BYDAY) {
    const days = map.BYDAY.split(',').map(d => dayNames[d] || d).join(', ');
    str += ` on ${days}`;
  }
  if (map.COUNT) str += ` (${map.COUNT} times)`;
  if (map.UNTIL) str += ` until ${map.UNTIL}`;
  return str;
}

async function loadCalendars() {
  try {
    const token = await getAuthToken();
    if (!token) return;

    const res = await fetch('https://www.googleapis.com/calendar/v3/users/me/calendarList', {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!res.ok) return;
    const data = await res.json();
    const settings = await getSettings();

    previewCalendar.innerHTML = '';
    (data.items || []).forEach(cal => {
      const opt = document.createElement('option');
      opt.value = cal.id;
      opt.textContent = cal.summary;
      if (cal.id === settings.defaultCalendarId) opt.selected = true;
      previewCalendar.appendChild(opt);
    });
  } catch {
    // Silently fall back to primary
  }
}

// ---- Auth ----

function getAuthToken() {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: 'getAuthToken', interactive: true }, (response) => {
      if (response && response.token) {
        resolve(response.token);
      } else {
        resolve(null);
      }
    });
  });
}

// ---- Create Event ----

const btnCreate = document.getElementById('btn-create');
const btnBack = document.getElementById('btn-back');

btnCreate.addEventListener('click', createEvent);
btnBack.addEventListener('click', () => showState('input'));

async function createEvent() {
  btnCreate.disabled = true;
  btnCreate.innerHTML = '<span class="loading"></span> Creating...';
  hideError();

  try {
    const token = await getAuthToken();
    if (!token) {
      throw new Error('Google account not connected. Go to Settings to connect.');
    }

    const settings = await getSettings();

    // Build start/end from edited fields
    const dateVal = previewDate.value;
    const timeVal = previewTime.value;
    const { startISO, endISO } = parseTimeRange(dateVal, timeVal, parsedEvent);

    const eventBody = {
      summary: previewTitle.value,
      start: {
        dateTime: startISO,
        timeZone: parsedEvent.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone,
      },
      end: {
        dateTime: endISO,
        timeZone: parsedEvent.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone,
      },
      reminders: {
        useDefault: false,
        overrides: settings.defaultReminders,
      },
    };

    if (previewLocation.value) {
      eventBody.location = previewLocation.value;
    }

    if (parsedEvent.recurrence && parsedEvent.recurrence.length > 0) {
      eventBody.recurrence = parsedEvent.recurrence;
    }

    if (parsedEvent.description) {
      eventBody.description = parsedEvent.description;
    }

    const calendarId = previewCalendar.value || 'primary';
    const res = await fetch(
      `https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calendarId)}/events`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(eventBody),
      }
    );

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error?.message || `Calendar API error (${res.status})`);
    }

    const created = await res.json();
    createdEventLink = created.htmlLink;

    // Show confirmation
    document.getElementById('confirm-title').textContent = previewTitle.value;
    document.getElementById('confirm-datetime').textContent =
      `${formatDateHuman(dateVal)} · ${timeVal}`;
    document.getElementById('confirm-link').href = createdEventLink;

    showState('confirm');
  } catch (err) {
    showError(err.message || 'Failed to create event.', createEvent);
  } finally {
    btnCreate.disabled = false;
    btnCreate.textContent = 'Create Event ✓';
  }
}

function parseTimeRange(dateStr, timeStr, fallbackEvent) {
  // Try to use the parsed event's original ISO times if user didn't change them
  // Otherwise, do best-effort parsing from the editable fields
  const startISO = fallbackEvent.start;
  const endISO = fallbackEvent.end;
  return { startISO, endISO };
}

function formatDateHuman(dateStr) {
  const d = new Date(dateStr + 'T00:00:00');
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

// ---- Add Another ----

document.getElementById('btn-another').addEventListener('click', () => {
  eventText.value = '';
  parsedEvent = null;
  createdEventLink = null;
  showState('input');
});

// ---- Settings ----

document.getElementById('open-settings').addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});
