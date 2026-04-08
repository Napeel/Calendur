// ---- Defaults ----

const DEFAULTS = {
  backendUrl: '',
  defaultCalendarId: 'primary',
  defaultDuration: 30,
  defaultReminders: [{ method: 'popup', minutes: 10 }],
};

const REMINDER_OPTIONS = [
  { label: '5 minutes before', minutes: 5 },
  { label: '10 minutes before', minutes: 10 },
  { label: '15 minutes before', minutes: 15 },
  { label: '30 minutes before', minutes: 30 },
  { label: '1 hour before', minutes: 60 },
  { label: '2 hours before', minutes: 120 },
  { label: '1 day before', minutes: 1440 },
  { label: '2 days before', minutes: 2880 },
];

// ---- Elements ----

const backendUrl = document.getElementById('backend-url');
const defaultCalendar = document.getElementById('default-calendar');
const durationChips = document.getElementById('duration-chips');
const remindersList = document.getElementById('reminders-list');
const addReminderBtn = document.getElementById('add-reminder');
const btnSave = document.getElementById('btn-save');
const toast = document.getElementById('toast');

let selectedDuration = DEFAULTS.defaultDuration;

// ---- Duration chips ----

durationChips.addEventListener('click', (e) => {
  const chip = e.target.closest('.chip');
  if (!chip) return;
  selectedDuration = parseInt(chip.dataset.value);
  updateDurationChips();
});

function updateDurationChips() {
  durationChips.querySelectorAll('.chip').forEach(chip => {
    chip.classList.toggle('active', parseInt(chip.dataset.value) === selectedDuration);
  });
}

// ---- Reminders ----

function createReminderRow(minutes = 10) {
  const row = document.createElement('div');
  row.className = 'reminder-row';

  const select = document.createElement('select');
  REMINDER_OPTIONS.forEach(opt => {
    const option = document.createElement('option');
    option.value = opt.minutes;
    option.textContent = opt.label;
    if (opt.minutes === minutes) option.selected = true;
    select.appendChild(option);
  });

  const removeBtn = document.createElement('button');
  removeBtn.className = 'reminder-remove';
  removeBtn.textContent = '×';
  removeBtn.addEventListener('click', () => {
    row.remove();
    updateAddButton();
  });

  row.appendChild(select);
  row.appendChild(removeBtn);
  remindersList.appendChild(row);
  updateAddButton();
}

function updateAddButton() {
  const count = remindersList.querySelectorAll('.reminder-row').length;
  addReminderBtn.style.display = count >= 5 ? 'none' : 'inline';
}

addReminderBtn.addEventListener('click', () => {
  createReminderRow(10);
});

function getReminders() {
  const rows = remindersList.querySelectorAll('.reminder-row');
  return Array.from(rows).map(row => ({
    method: 'popup',
    minutes: parseInt(row.querySelector('select').value),
  }));
}

// ---- Google Account ----

const accountConnected = document.getElementById('account-connected');
const accountDisconnected = document.getElementById('account-disconnected');
const accountEmail = document.getElementById('account-email');
const accountInitial = document.getElementById('account-initial');

async function checkAccount() {
  try {
    const response = await new Promise(resolve => {
      chrome.runtime.sendMessage({ type: 'getUserInfo' }, resolve);
    });

    if (response && response.email) {
      accountEmail.textContent = response.email;
      accountInitial.textContent = (response.name || response.email)[0].toUpperCase();
      accountConnected.style.display = 'flex';
      accountDisconnected.style.display = 'none';
      loadCalendars();
    } else {
      accountConnected.style.display = 'none';
      accountDisconnected.style.display = 'block';
    }
  } catch {
    accountConnected.style.display = 'none';
    accountDisconnected.style.display = 'block';
  }
}

document.getElementById('btn-connect').addEventListener('click', async () => {
  const response = await new Promise(resolve => {
    chrome.runtime.sendMessage({ type: 'getAuthToken', interactive: true }, resolve);
  });
  if (response && response.token) {
    checkAccount();
  }
});

document.getElementById('btn-disconnect').addEventListener('click', async () => {
  // Revoke token with Google (best effort)
  const tokenResponse = await new Promise(resolve => {
    chrome.runtime.sendMessage({ type: 'getAuthToken', interactive: false }, resolve);
  });
  if (tokenResponse && tokenResponse.token) {
    try {
      await fetch(`https://oauth2.googleapis.com/revoke?token=${tokenResponse.token}`, {
        method: 'POST',
      });
    } catch {
      // Revocation is best-effort
    }
  }
  await new Promise(resolve => {
    chrome.runtime.sendMessage({ type: 'removeCachedToken' }, resolve);
  });
  checkAccount();
});

// ---- Calendars ----

async function loadCalendars() {
  try {
    const tokenResponse = await new Promise(resolve => {
      chrome.runtime.sendMessage({ type: 'getAuthToken', interactive: false }, resolve);
    });

    if (!tokenResponse || !tokenResponse.token) return;

    const res = await fetch('https://www.googleapis.com/calendar/v3/users/me/calendarList', {
      headers: { Authorization: `Bearer ${tokenResponse.token}` },
    });

    if (!res.ok) return;
    const data = await res.json();

    const currentVal = defaultCalendar.value;
    defaultCalendar.innerHTML = '';

    (data.items || []).forEach(cal => {
      const opt = document.createElement('option');
      opt.value = cal.id;
      opt.textContent = cal.summary;
      if (cal.id === currentVal) opt.selected = true;
      defaultCalendar.appendChild(opt);
    });
  } catch {
    // Keep default "Primary" option
  }
}

// ---- Save / Load ----

function showToast() {
  toast.classList.add('visible');
  setTimeout(() => toast.classList.remove('visible'), 2000);
}

btnSave.addEventListener('click', () => {
  const settings = {
    backendUrl: backendUrl.value.replace(/\/+$/, ''),
    defaultCalendarId: defaultCalendar.value,
    defaultDuration: selectedDuration,
    defaultReminders: getReminders(),
  };

  chrome.storage.sync.set(settings, () => {
    showToast();
  });
});

function loadSettings() {
  chrome.storage.sync.get(DEFAULTS, (settings) => {
    backendUrl.value = settings.backendUrl;
    defaultCalendar.value = settings.defaultCalendarId;
    selectedDuration = settings.defaultDuration;
    updateDurationChips();

    // Clear and rebuild reminders
    remindersList.innerHTML = '';
    (settings.defaultReminders || []).forEach(r => createReminderRow(r.minutes));
  });
}

// ---- Init ----

loadSettings();
checkAccount();
