/* =============================================
   DIAA STORE 2FA — TOTP Generator
   Pure JavaScript TOTP Implementation
   ============================================= */

// ============================================
// TOTP CORE — RFC 6238 Implementation
// ============================================

/**
 * Decode Base32 string to Uint8Array
 */
function base32Decode(encoded) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  // Clean input: remove spaces, dashes, convert to uppercase
  const cleaned = encoded.replace(/[\s-]+/g, '').toUpperCase().replace(/=+$/, '');
  
  if (cleaned.length === 0) return null;
  
  // Validate characters
  for (let i = 0; i < cleaned.length; i++) {
    if (alphabet.indexOf(cleaned[i]) === -1) return null;
  }
  
  let bits = '';
  for (let i = 0; i < cleaned.length; i++) {
    const val = alphabet.indexOf(cleaned[i]);
    bits += val.toString(2).padStart(5, '0');
  }
  
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.substr(i * 8, 8), 2);
  }
  
  return bytes;
}

/**
 * HMAC-SHA1 implementation using Web Crypto API
 */
async function hmacSha1(key, message) {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, message);
  return new Uint8Array(signature);
}

/**
 * Generate TOTP code
 * @param {string} secret - Base32 encoded secret
 * @param {number} period - Time period in seconds (default: 30)
 * @param {number} digits - Number of digits (default: 6)
 * @returns {Promise<string>} - TOTP code
 */
async function generateTOTP(secret, period = 30, digits = 6) {
  const key = base32Decode(secret);
  if (!key || key.length === 0) {
    throw new Error('Invalid secret key');
  }
  
  // Get time counter
  const time = Math.floor(Date.now() / 1000);
  const counter = Math.floor(time / period);
  
  // Convert counter to 8-byte big-endian
  const counterBytes = new Uint8Array(8);
  let temp = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = temp & 0xff;
    temp = Math.floor(temp / 256);
  }
  
  // Calculate HMAC-SHA1
  const hmac = await hmacSha1(key, counterBytes);
  
  // Dynamic truncation
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = (
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff)
  ) % Math.pow(10, digits);

  return code.toString().padStart(digits, '0');
}

/**
 * Get remaining seconds in current TOTP period
 */
function getRemainingSeconds(period = 30) {
  return period - (Math.floor(Date.now() / 1000) % period);
}


// ============================================
// LOCAL STORAGE — Saved Keys
// ============================================

const STORAGE_KEY = 'diaa_store_2fa_keys';

function getSavedKeys() {
  try {
    const data = localStorage.getItem(STORAGE_KEY);
    return data ? JSON.parse(data) : [];
  } catch (e) {
    return [];
  }
}

function saveKey(name, secret) {
  const keys = getSavedKeys();
  // Prevent duplicates
  const existing = keys.findIndex(k => k.secret === secret);
  if (existing !== -1) {
    keys[existing].name = name;
  } else {
    keys.push({ id: Date.now(), name, secret });
  }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(keys));
}

function deleteKey(id) {
  const keys = getSavedKeys().filter(k => k.id !== id);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(keys));
}


// ============================================
// UI CONTROLLER
// ============================================

let currentSecret = '';
let timerInterval = null;
let currentCode = '';

// DOM elements
const $ = id => document.getElementById(id);

const elements = {
  secretInput: $('secret-input'),
  pasteBtn: $('paste-secret-btn'),
  generateBtn: $('generate-btn'),
  secretError: $('secret-error'),
  inputSection: $('input-section'),
  codeDisplay: $('code-display'),
  activeKeyText: $('active-key-text'),
  changeKeyBtn: $('change-key-btn'),
  copyCodeBtn: $('copy-code-btn'),
  timerBarFill: $('timer-bar-fill'),
  timerCountdown: $('timer-countdown'),
  timerProgress: $('timer-progress'),
  timerSeconds: $('timer-seconds'),
  savedKeysList: $('saved-keys-list'),
  savedKeysEmpty: $('saved-keys-empty'),
  heroParticles: $('hero-particles'),
};

// ---- Initialize ----
document.addEventListener('DOMContentLoaded', () => {
  initParticles();
  initEventListeners();
  renderSavedKeys();
  
  // Check for secret in URL path (e.g. /a3fztrscx734b6qy4cuxfjrownt35zly)
  const rawPathCode = window.location.pathname.replace(/^\//, '').replace(/\/$/, '');
  // Strip ALL whitespace and non-alphanumeric characters, keep only letters and digits
  const pathCode = rawPathCode.replace(/[^a-zA-Z0-9]/g, '');
  if (pathCode && pathCode.length >= 16 && /^[A-Za-z2-7]+=*$/i.test(pathCode.toUpperCase().replace(/[0-9]/g, '')||'A')) {
    elements.secretInput.value = pathCode;
    startGenerator(pathCode);
    return;
  }
  
  // Fallback: check for secret in URL query params
  const urlParams = new URLSearchParams(window.location.search);
  const secretParam = urlParams.get('secret') || urlParams.get('key');
  if (secretParam) {
    elements.secretInput.value = secretParam;
    startGenerator(secretParam);
  }
});

function initEventListeners() {
  // Paste button
  elements.pasteBtn.addEventListener('click', async () => {
    try {
      const text = await navigator.clipboard.readText();
      elements.secretInput.value = text.trim();
      elements.secretInput.focus();
    } catch (e) {
      showToast('Unable to access clipboard', 'error');
    }
  });
  
  // Generate button
  elements.generateBtn.addEventListener('click', () => {
    // Strip ALL whitespace and spaces from input
    const secret = elements.secretInput.value.replace(/\s+/g, '').trim();
    if (!secret) {
      showError(elements.secretError, 'Please enter a secret key');
      elements.secretInput.classList.add('error');
      return;
    }
    startGenerator(secret);
  });
  
  // Enter key on input
  elements.secretInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      elements.generateBtn.click();
    }
  });
  
  // Clear error on input
  elements.secretInput.addEventListener('input', () => {
    hideError(elements.secretError);
    elements.secretInput.classList.remove('error');
  });
  
  // Change key button
  elements.changeKeyBtn.addEventListener('click', () => {
    stopGenerator();
    elements.codeDisplay.classList.remove('active');
    elements.inputSection.classList.remove('hidden');
    elements.inputSection.style.display = '';
    elements.secretInput.value = '';
    elements.secretInput.focus();
    // Reset URL back to root
    window.history.pushState({}, '', '/');
  });
  
  // Copy code button
  elements.copyCodeBtn.addEventListener('click', () => {
    if (!currentCode) return;
    navigator.clipboard.writeText(currentCode).then(() => {
      elements.copyCodeBtn.classList.add('copied');
      elements.copyCodeBtn.querySelector('.copy-text').textContent = 'Copied!';
      showToast('Code copied to clipboard!', 'success');
      setTimeout(() => {
        elements.copyCodeBtn.classList.remove('copied');
        elements.copyCodeBtn.querySelector('.copy-text').textContent = 'Copy';
      }, 2000);
    }).catch(() => {
      showToast('Failed to copy', 'error');
    });
  });
}

// ---- Generator Logic ----
async function startGenerator(secret) {
  // Strip ALL whitespace, spaces, dashes — keep only alphanumeric chars
  const cleanedSecret = secret.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
  
  try {
    const testCode = await generateTOTP(cleanedSecret);
    if (!testCode) throw new Error('Invalid');
  } catch (e) {
    showError(elements.secretError, 'Invalid Base32 secret key. Please check and try again.');
    elements.secretInput.classList.add('error');
    return;
  }
  
  currentSecret = cleanedSecret;
  
  // Auto-update URL to show the secret key after /
  const newUrl = '/' + cleanedSecret.toLowerCase();
  if (window.location.pathname !== newUrl) {
    window.history.pushState({}, '', newUrl);
  }
  
  // Switch to code display
  elements.inputSection.style.display = 'none';
  elements.codeDisplay.classList.add('active');
  
  // Mask the key for display
  const masked = currentSecret.length > 8 
    ? currentSecret.substring(0, 4) + '••••' + currentSecret.substring(currentSecret.length - 4)
    : '••••••••';
  elements.activeKeyText.textContent = `Key: ${masked}`;
  
  // Add save key button if not already present
  addSaveKeyButton();
  
  // Start generating
  updateCode();
  startTimer();
}

function stopGenerator() {
  if (timerInterval) {
    clearInterval(timerInterval);
    timerInterval = null;
  }
  currentSecret = '';
  currentCode = '';
}

async function updateCode() {
  if (!currentSecret) return;
  
  try {
    const code = await generateTOTP(currentSecret);
    currentCode = code;
    
    // Update digits with animation
    for (let i = 0; i < 6; i++) {
      const digitEl = $(`digit-${i}`);
      if (digitEl.textContent !== code[i]) {
        digitEl.textContent = code[i];
        digitEl.classList.remove('animate');
        // Force reflow
        void digitEl.offsetWidth;
        digitEl.classList.add('animate');
      }
    }
  } catch (e) {
    console.error('TOTP generation failed:', e);
  }
}

function startTimer() {
  if (timerInterval) clearInterval(timerInterval);
  
  const circumference = 2 * Math.PI * 54; // r=54 from SVG
  let lastRemaining = -1;
  
  function tick() {
    const remaining = getRemainingSeconds();
    const percentage = remaining / 30;
    
    // Update bar
    elements.timerBarFill.style.width = `${percentage * 100}%`;
    
    // Update countdown text
    elements.timerCountdown.textContent = `${remaining}s`;
    
    // Update circular timer
    const offset = circumference * (1 - percentage);
    elements.timerProgress.style.strokeDashoffset = offset;
    elements.timerSeconds.textContent = remaining;
    
    // Warning state when less than 5 seconds
    const isWarning = remaining <= 5;
    elements.timerBarFill.classList.toggle('warning', isWarning);
    elements.timerCountdown.classList.toggle('warning', isWarning);
    elements.timerProgress.classList.toggle('warning', isWarning);
    elements.timerSeconds.classList.toggle('warning', isWarning);
    
    // Regenerate code when timer resets (detect rollover)
    if (remaining > lastRemaining && lastRemaining !== -1) {
      updateCode();
    }
    lastRemaining = remaining;
  }
  
  tick();
  timerInterval = setInterval(tick, 1000);
}

// ---- Save Key ----
function addSaveKeyButton() {
  // Remove existing save section if any
  const existing = document.querySelector('.save-key-section');
  if (existing) existing.remove();
  
  const saveSection = document.createElement('div');
  saveSection.className = 'save-key-section';
  
  const isAlreadySaved = getSavedKeys().some(k => k.secret === currentSecret);
  
  saveSection.innerHTML = `
    <button class="btn-save-key ${isAlreadySaved ? 'saved' : ''}" id="save-key-btn">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/></svg>
      ${isAlreadySaved ? 'Key Saved' : 'Save Key for Quick Access'}
    </button>
  `;
  
  elements.codeDisplay.appendChild(saveSection);
  
  saveSection.querySelector('#save-key-btn').addEventListener('click', () => {
    if (isAlreadySaved) {
      showToast('Key is already saved', 'success');
      return;
    }
    showSaveModal();
  });
}

function showSaveModal() {
  // Create modal
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay active';
  overlay.innerHTML = `
    <div class="modal">
      <h3 class="modal-title">Save Secret Key</h3>
      <p class="modal-desc">Give this key a name for easy identification</p>
      <input type="text" class="modal-input" id="modal-key-name" placeholder="e.g. Facebook, GitHub, Google..." autofocus />
      <div class="modal-actions">
        <button class="btn-modal-cancel" id="modal-cancel">Cancel</button>
        <button class="btn-modal-save" id="modal-save">Save Key</button>
      </div>
    </div>
  `;
  
  document.body.appendChild(overlay);
  
  // Focus input
  setTimeout(() => overlay.querySelector('#modal-key-name').focus(), 100);
  
  // Events
  overlay.querySelector('#modal-cancel').addEventListener('click', () => {
    overlay.remove();
  });
  
  overlay.querySelector('#modal-save').addEventListener('click', () => {
    const name = overlay.querySelector('#modal-key-name').value.trim();
    if (!name) {
      overlay.querySelector('#modal-key-name').style.borderColor = 'var(--color-error)';
      return;
    }
    saveKey(name, currentSecret);
    overlay.remove();
    renderSavedKeys();
    addSaveKeyButton(); // Refresh button state
    showToast('Key saved successfully!', 'success');
  });
  
  overlay.querySelector('#modal-key-name').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') overlay.querySelector('#modal-save').click();
    if (e.key === 'Escape') overlay.remove();
  });
  
  // Click outside to close
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) overlay.remove();
  });
}

// ---- Render Saved Keys ----
function renderSavedKeys() {
  const keys = getSavedKeys();
  
  if (keys.length === 0) {
    elements.savedKeysEmpty.classList.remove('hidden');
    elements.savedKeysEmpty.style.display = '';
    elements.savedKeysList.innerHTML = '';
    return;
  }
  
  elements.savedKeysEmpty.classList.add('hidden');
  elements.savedKeysEmpty.style.display = 'none';
  
  elements.savedKeysList.innerHTML = keys.map(key => {
    const masked = key.secret.length > 12
      ? key.secret.substring(0, 6) + '••••' + key.secret.substring(key.secret.length - 4)
      : key.secret.substring(0, 3) + '••••';
    
    const initials = key.name.substring(0, 2).toUpperCase();
    
    return `
      <div class="saved-key-item" data-secret="${key.secret}" data-id="${key.id}">
        <div class="saved-key-icon">${initials}</div>
        <div class="saved-key-info">
          <div class="saved-key-name">${escapeHtml(key.name)}</div>
          <div class="saved-key-secret">${masked}</div>
        </div>
        <div class="saved-key-actions">
          <button class="saved-key-btn use-key" title="Use this key" data-secret="${key.secret}">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
          </button>
          <button class="saved-key-btn delete" title="Delete key" data-id="${key.id}">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
          </button>
        </div>
      </div>
    `;
  }).join('');
  
  // Attach events
  elements.savedKeysList.querySelectorAll('.use-key').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const secret = btn.dataset.secret;
      elements.secretInput.value = secret;
      startGenerator(secret);
      document.getElementById('generator-section').scrollIntoView({ behavior: 'smooth' });
    });
  });
  
  elements.savedKeysList.querySelectorAll('.saved-key-item').forEach(item => {
    item.addEventListener('click', () => {
      const secret = item.dataset.secret;
      elements.secretInput.value = secret;
      startGenerator(secret);
      document.getElementById('generator-section').scrollIntoView({ behavior: 'smooth' });
    });
  });
  
  elements.savedKeysList.querySelectorAll('.delete').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = parseInt(btn.dataset.id);
      deleteKey(id);
      renderSavedKeys();
      showToast('Key deleted', 'success');
    });
  });
}

// ---- Particles ----
function initParticles() {
  const container = elements.heroParticles;
  if (!container) return;
  
  for (let i = 0; i < 20; i++) {
    const particle = document.createElement('div');
    particle.className = 'particle';
    particle.style.left = Math.random() * 100 + '%';
    particle.style.top = Math.random() * 100 + '%';
    particle.style.animationDelay = Math.random() * 8 + 's';
    particle.style.animationDuration = (6 + Math.random() * 6) + 's';
    particle.style.width = (2 + Math.random() * 3) + 'px';
    particle.style.height = particle.style.width;
    particle.style.opacity = Math.random() * 0.5;
    container.appendChild(particle);
  }
}

// ---- Toast Notification ----
function showToast(message, type = 'success') {
  // Remove existing toast
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();
  
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  
  const icon = type === 'success' 
    ? '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>'
    : '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
  
  toast.innerHTML = `${icon} ${message}`;
  document.body.appendChild(toast);
  
  // Trigger animation
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      toast.classList.add('visible');
    });
  });
  
  setTimeout(() => {
    toast.classList.remove('visible');
    setTimeout(() => toast.remove(), 400);
  }, 3000);
}

// ---- Error helpers ----
function showError(el, message) {
  el.textContent = message;
  el.classList.add('visible');
}

function hideError(el) {
  el.classList.remove('visible');
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ---- Navbar scroll effect ----
window.addEventListener('scroll', () => {
  const navbar = document.getElementById('navbar');
  if (window.scrollY > 50) {
    navbar.style.background = 'rgba(9, 9, 11, 0.85)';
    navbar.style.borderBottomColor = 'rgba(139, 92, 246, 0.15)';
  } else {
    navbar.style.background = 'rgba(9, 9, 11, 0.6)';
    navbar.style.borderBottomColor = '';
  }
});
