"use strict";

const translations = {
  ar: {
    skip: "انتقل إلى مولّد الأكواد",
    navGenerator: "مولّد الكود",
    navStores: "تواصل معنا",
    eyebrow: "حماية ذكية. نتيجة فورية.",
    heroLineOne: "رمز التحقق الخاص بك،",
    heroLineTwo: "في ثوانٍ.",
    heroDescription: "ولّد رموز التحقق بخطوتين مباشرة على جهازك. بدون تسجيل، وبدون إرسال مفتاحك لأي خادم.",
    trustLocal: "يعمل محليًا",
    trustPrivate: "لا يتم حفظ المفتاح",
    trustFast: "تحديث تلقائي",
    secureStatus: "اتصال آمن",
    generatorTitle: "مولّد رمز 2FA",
    secretLabel: "المفتاح السري",
    paste: "لصق",
    localNote: "تتم المعالجة داخل متصفحك فقط — مفتاحك لا يغادر جهازك.",
    generate: "إنشاء رمز التحقق",
    codeActive: "الرمز نشط الآن",
    newKey: "مفتاح جديد",
    currentCode: "رمزك الحالي",
    refreshIn: "رمز جديد تلقائيًا خلال",
    seconds: "ثانية",
    copyCode: "نسخ الرمز",
    copied: "تم النسخ",
    saveKey: "حفظ المفتاح باسم",
    savedKicker: "وصول سريع",
    savedTitle: "المفاتيح المحفوظة",
    deviceOnly: "على هذا الجهاز",
    savedEmpty: "بعد إنشاء الرمز، احفظ المفتاح باسم للوصول إليه بضغطة واحدة.",
    saveDialogTitle: "حفظ المفتاح",
    saveDialogDescription: "اكتب اسمًا واضحًا للحساب لتجده بسرعة لاحقًا.",
    keyNameLabel: "اسم الحساب",
    keyNamePlaceholder: "مثال: Facebook الرئيسي",
    cancel: "إلغاء",
    confirmSave: "حفظ",
    nameRequired: "اكتب اسمًا للمفتاح أولًا.",
    keySaved: "تم حفظ المفتاح على هذا الجهاز.",
    keyDeleted: "تم حذف المفتاح المحفوظ.",
    useSavedKey: "استخدام المفتاح",
    deleteSavedKey: "حذف المفتاح",
    storesKicker: "الدعم الرسمي",
    storesTitle: "نحن هنا لمساعدتك",
    storesDescription: "تواصل مباشرة مع فريق المتجر المناسب عبر الصفحات والأرقام الرسمية.",
    officialStore: "متجر رسمي",
    diaaDescription: "حلول رقمية ودعم مباشر باهتمام وسرعة.",
    getproDescription: "تجربة احترافية وخدمات رقمية موثوقة.",
    privacyTitle: "خصوصيتك جزء من التصميم",
    privacyDescription: "تتم عملية التوليد داخل متصفحك ولا نحفظ مفتاحك في قاعدة بيانات. تنبيه: استخدام المفتاح في الرابط قد يجعله ظاهرًا في سجل المتصفح.",
    footerBy: "بواسطة Diaa Store × GetPro Store",
    rights: "جميع الحقوق محفوظة.",
    emptyError: "أدخل المفتاح السري أولًا.",
    invalidError: "المفتاح غير صالح. استخدم مفتاح Base32 أو رابط otpauth صحيحًا.",
    clipboardError: "تعذر الوصول إلى الحافظة. الصق المفتاح يدويًا.",
    pasteSuccess: "تم لصق المفتاح.",
    copySuccess: "تم نسخ الرمز.",
    copyError: "تعذر نسخ الرمز.",
    showSecret: "إظهار المفتاح",
    hideSecret: "إخفاء المفتاح"
  },
  en: {
    skip: "Skip to code generator",
    navGenerator: "Code generator",
    navStores: "Contact us",
    eyebrow: "SMART SECURITY. INSTANT RESULT.",
    heroLineOne: "Your verification code,",
    heroLineTwo: "in seconds.",
    heroDescription: "Generate two-factor authentication codes directly on your device. No account and no secret sent to any server.",
    trustLocal: "Runs locally",
    trustPrivate: "Secret is never saved",
    trustFast: "Auto refresh",
    secureStatus: "Secure session",
    generatorTitle: "2FA Code Generator",
    secretLabel: "Secret key",
    paste: "Paste",
    localNote: "Processing happens only in your browser — your secret never leaves your device.",
    generate: "Generate verification code",
    codeActive: "Code is active",
    newKey: "New key",
    currentCode: "Your current code",
    refreshIn: "New code automatically in",
    seconds: "seconds",
    copyCode: "Copy code",
    copied: "Copied",
    saveKey: "Save key with a name",
    savedKicker: "QUICK ACCESS",
    savedTitle: "Saved keys",
    deviceOnly: "On this device",
    savedEmpty: "After generating a code, save the key with a name for one-tap access.",
    saveDialogTitle: "Save key",
    saveDialogDescription: "Give this account a clear name so you can find it quickly later.",
    keyNameLabel: "Account name",
    keyNamePlaceholder: "Example: Main Facebook",
    cancel: "Cancel",
    confirmSave: "Save",
    nameRequired: "Enter a name for this key first.",
    keySaved: "Key saved on this device.",
    keyDeleted: "Saved key deleted.",
    useSavedKey: "Use key",
    deleteSavedKey: "Delete key",
    storesKicker: "OFFICIAL SUPPORT",
    storesTitle: "We are here to help",
    storesDescription: "Contact the right store team directly through the official pages and numbers.",
    officialStore: "Official store",
    diaaDescription: "Digital solutions and fast, attentive support.",
    getproDescription: "A professional experience and reliable digital services.",
    privacyTitle: "Privacy is built in",
    privacyDescription: "Generation happens locally and we do not store your secret in a database. Note: using the secret in the URL may expose it in browser history.",
    footerBy: "By Diaa Store × GetPro Store",
    rights: "All rights reserved.",
    emptyError: "Enter your secret key first.",
    invalidError: "Invalid secret. Use a Base32 key or a valid otpauth URL.",
    clipboardError: "Clipboard access failed. Paste the secret manually.",
    pasteSuccess: "Secret pasted.",
    copySuccess: "Code copied.",
    copyError: "Could not copy the code.",
    showSecret: "Show secret",
    hideSecret: "Hide secret"
  }
};

const elements = {
  html: document.documentElement,
  form: document.getElementById("generator-form"),
  inputState: document.getElementById("input-state"),
  resultState: document.getElementById("result-state"),
  secretInput: document.getElementById("secret-input"),
  secretField: document.getElementById("secret-field"),
  error: document.getElementById("secret-error"),
  pasteButton: document.getElementById("paste-button"),
  revealButton: document.getElementById("reveal-button"),
  generateButton: document.getElementById("generate-button"),
  newKeyButton: document.getElementById("new-key-button"),
  otpCode: document.getElementById("otp-code"),
  countdownRing: document.getElementById("countdown-ring"),
  countdownNumber: document.getElementById("countdown-number"),
  expiresSeconds: document.getElementById("expires-seconds"),
  progressFill: document.getElementById("progress-fill"),
  copyButton: document.getElementById("copy-button"),
  copyButtonText: document.getElementById("copy-button-text"),
  saveKeyButton: document.getElementById("save-key-button"),
  savedAccounts: document.getElementById("saved-accounts"),
  savedEmpty: document.getElementById("saved-empty"),
  savedList: document.getElementById("saved-list"),
  saveDialog: document.getElementById("save-dialog"),
  saveForm: document.getElementById("save-form"),
  keyNameInput: document.getElementById("key-name-input"),
  dialogError: document.getElementById("dialog-error"),
  languageToggle: document.getElementById("language-toggle"),
  toast: document.getElementById("toast"),
  currentYear: document.getElementById("current-year")
};

let currentLanguage = "ar";
let currentSecret = "";
let currentCode = "";
let timerId = null;
let lastCounter = null;
let toastTimer = null;
const STORAGE_KEY = "secure_hub_saved_keys_v1";

function translate(key) {
  return translations[currentLanguage][key] || key;
}

function applyLanguage(language) {
  currentLanguage = language === "en" ? "en" : "ar";
  const isArabic = currentLanguage === "ar";

  elements.html.lang = currentLanguage;
  elements.html.dir = isArabic ? "rtl" : "ltr";
  elements.languageToggle.textContent = isArabic ? "EN" : "عربي";

  document.querySelectorAll("[data-i18n]").forEach((node) => {
    const key = node.dataset.i18n;
    if (translations[currentLanguage][key]) {
      node.textContent = translations[currentLanguage][key];
    }
  });

  updateRevealLabel();
  elements.keyNameInput.placeholder = translate("keyNamePlaceholder");
  renderSavedKeys();
  if (elements.copyButton.classList.contains("copied")) {
    elements.copyButtonText.textContent = translate("copied");
  }
}

function updateRevealLabel() {
  const isVisible = elements.secretInput.type === "text";
  const label = translate(isVisible ? "hideSecret" : "showSecret");
  elements.revealButton.setAttribute("aria-label", label);
  elements.revealButton.title = label;
}

function normalizeSecret(value) {
  const trimmed = String(value || "").trim();
  let candidate = trimmed;

  if (/^otpauth:\/\//i.test(trimmed)) {
    try {
      const otpUrl = new URL(trimmed);
      if (otpUrl.protocol !== "otpauth:" || otpUrl.hostname.toLowerCase() !== "totp") {
        return "";
      }
      candidate = otpUrl.searchParams.get("secret") || "";
    } catch {
      return "";
    }
  }

  return candidate.replace(/[\s-]+/g, "").replace(/=+$/g, "").toUpperCase();
}

function getSavedKeys() {
  try {
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    if (!Array.isArray(stored)) return [];
    return stored.filter((item) => (
      item && typeof item.name === "string" && typeof item.secret === "string"
    ));
  } catch {
    return [];
  }
}

function writeSavedKeys(keys) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(keys));
}

function saveCurrentKey(name) {
  if (!currentSecret) return;

  const keys = getSavedKeys();
  const existing = keys.find((item) => item.secret === currentSecret);
  if (existing) {
    existing.name = name;
  } else {
    keys.unshift({
      id: crypto.randomUUID ? crypto.randomUUID() : String(Date.now()),
      name,
      secret: currentSecret
    });
  }

  writeSavedKeys(keys);
  renderSavedKeys();
}

function removeSavedKey(id) {
  writeSavedKeys(getSavedKeys().filter((item) => item.id !== id));
  renderSavedKeys();
  showToast(translate("keyDeleted"));
}

function maskSecret(secret) {
  if (secret.length <= 8) return "••••••••";
  return `${secret.slice(0, 4)}••••${secret.slice(-4)}`;
}

function renderSavedKeys() {
  const keys = getSavedKeys();
  elements.savedList.replaceChildren();
  elements.savedEmpty.hidden = keys.length > 0;

  keys.forEach((item) => {
    const row = document.createElement("div");
    row.className = "saved-item";

    const useButton = document.createElement("button");
    useButton.type = "button";
    useButton.className = "saved-item-main";
    useButton.title = translate("useSavedKey");

    const avatar = document.createElement("span");
    avatar.className = "saved-avatar";
    avatar.textContent = item.name.trim().slice(0, 2).toUpperCase() || "2F";

    const details = document.createElement("span");
    details.className = "saved-details";
    const name = document.createElement("strong");
    name.textContent = item.name;
    const secret = document.createElement("small");
    secret.textContent = maskSecret(item.secret);
    details.append(name, secret);
    useButton.append(avatar, details);
    useButton.addEventListener("click", () => {
      startGenerator(item.secret);
      document.getElementById("generator").scrollIntoView({ behavior: "smooth", block: "start" });
    });

    const deleteButton = document.createElement("button");
    deleteButton.type = "button";
    deleteButton.className = "saved-delete";
    deleteButton.title = translate("deleteSavedKey");
    deleteButton.setAttribute("aria-label", `${translate("deleteSavedKey")}: ${item.name}`);
    deleteButton.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6h18M8 6V4h8v2m-9 0 1 15h8l1-15M10 10v7m4-7v7"/></svg>';
    deleteButton.addEventListener("click", () => removeSavedKey(item.id));

    row.append(useButton, deleteButton);
    elements.savedList.appendChild(row);
  });
}

function getSecretFromPath() {
  const encodedPath = window.location.pathname.replace(/^\/+|\/+$/g, "");
  if (!encodedPath) return "";

  let pathValue = "";
  try {
    pathValue = decodeURIComponent(encodedPath);
  } catch {
    return "";
  }

  return pathValue;
}

function decodeBase32(secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = normalizeSecret(secret);

  if (normalized.length < 8 || !/^[A-Z2-7]+$/.test(normalized)) {
    throw new Error("Invalid Base32 secret");
  }

  let accumulator = 0;
  let bitCount = 0;
  const bytes = [];

  for (const character of normalized) {
    accumulator = (accumulator << 5) | alphabet.indexOf(character);
    bitCount += 5;

    while (bitCount >= 8) {
      bitCount -= 8;
      bytes.push((accumulator >>> bitCount) & 0xff);
    }
  }

  if (!bytes.length) {
    throw new Error("Invalid Base32 payload");
  }

  return new Uint8Array(bytes);
}

async function generateTotp(secret, timestamp = Date.now(), period = 30, digits = 6) {
  const keyBytes = decodeBase32(secret);
  const counter = Math.floor(timestamp / 1000 / period);
  const counterBytes = new ArrayBuffer(8);
  const counterView = new DataView(counterBytes);
  const high = Math.floor(counter / 0x100000000);
  const low = counter >>> 0;

  counterView.setUint32(0, high, false);
  counterView.setUint32(4, low, false);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, counterBytes));
  const offset = signature[signature.length - 1] & 0x0f;
  const binary = (
    ((signature[offset] & 0x7f) << 24) |
    ((signature[offset + 1] & 0xff) << 16) |
    ((signature[offset + 2] & 0xff) << 8) |
    (signature[offset + 3] & 0xff)
  );

  return String(binary % (10 ** digits)).padStart(digits, "0");
}

async function refreshCode(forceAnimation = false) {
  if (!currentSecret) return;

  try {
    const code = await generateTotp(currentSecret);
    if (code !== currentCode || forceAnimation) {
      currentCode = code;
      elements.otpCode.textContent = `${code.slice(0, 3)} ${code.slice(3)}`;
      elements.otpCode.classList.remove("bump");
      void elements.otpCode.offsetWidth;
      elements.otpCode.classList.add("bump");
    }
  } catch {
    resetGenerator();
    showError(translate("invalidError"));
  }
}

function updateTimer() {
  if (!currentSecret) return;

  const now = Date.now();
  const elapsed = (now / 1000) % 30;
  const remainingPrecise = 30 - elapsed;
  const remaining = Math.ceil(remainingPrecise);
  const progress = Math.max(0, Math.min(1, remainingPrecise / 30));
  const counter = Math.floor(now / 1000 / 30);
  const isWarning = remaining <= 5;

  elements.countdownNumber.textContent = String(remaining);
  elements.expiresSeconds.textContent = String(remaining);
  elements.countdownRing.style.setProperty("--progress", progress.toFixed(4));
  elements.countdownRing.classList.toggle("warning", isWarning);
  elements.progressFill.style.transform = `scaleX(${progress})`;
  elements.progressFill.classList.toggle("warning", isWarning);

  if (lastCounter !== null && counter !== lastCounter) {
    refreshCode(true);
  }
  lastCounter = counter;
}

function startTimer() {
  stopTimer();
  lastCounter = Math.floor(Date.now() / 1000 / 30);
  updateTimer();
  timerId = window.setInterval(updateTimer, 250);
}

function stopTimer() {
  if (timerId !== null) {
    window.clearInterval(timerId);
    timerId = null;
  }
  lastCounter = null;
}

async function startGenerator(rawSecret) {
  const secret = normalizeSecret(rawSecret);
  if (!secret) {
    showError(rawSecret.trim() ? translate("invalidError") : translate("emptyError"));
    return;
  }

  setLoading(true);
  clearError();

  try {
    currentSecret = secret;
    currentCode = await generateTotp(currentSecret);
    // Keep the normalized secret in the URL for direct-link workflows.
    // Whitespace and dashes are removed by normalizeSecret before this point.
    const secretPath = `/${encodeURIComponent(currentSecret)}`;
    if (window.location.pathname !== secretPath) {
      window.history.replaceState({}, "", secretPath);
    }
    elements.otpCode.textContent = `${currentCode.slice(0, 3)} ${currentCode.slice(3)}`;
    elements.inputState.hidden = true;
    elements.resultState.hidden = false;
    elements.secretInput.value = "";
    elements.secretInput.type = "password";
    elements.revealButton.classList.remove("visible");
    updateRevealLabel();
    startTimer();
  } catch {
    currentSecret = "";
    currentCode = "";
    showError(translate("invalidError"));
  } finally {
    setLoading(false);
  }
}

function resetGenerator() {
  stopTimer();
  currentSecret = "";
  currentCode = "";
  elements.otpCode.textContent = "--- ---";
  elements.resultState.hidden = true;
  elements.inputState.hidden = false;
  elements.copyButton.classList.remove("copied");
  elements.copyButtonText.textContent = translate("copyCode");
  elements.secretInput.value = "";
  elements.secretInput.type = "password";
  elements.revealButton.classList.remove("visible");
  updateRevealLabel();
  if (window.location.pathname !== "/") {
    window.history.replaceState({}, "", "/");
  }
  window.setTimeout(() => elements.secretInput.focus(), 50);
}

function setLoading(isLoading) {
  elements.generateButton.disabled = isLoading;
}

function showError(message) {
  elements.error.textContent = message;
  elements.error.classList.add("visible");
  elements.secretField.classList.add("error");
  elements.secretInput.setAttribute("aria-invalid", "true");
}

function clearError() {
  elements.error.textContent = "";
  elements.error.classList.remove("visible");
  elements.secretField.classList.remove("error");
  elements.secretInput.removeAttribute("aria-invalid");
}

function showToast(message, type = "success") {
  window.clearTimeout(toastTimer);
  elements.toast.textContent = message;
  elements.toast.className = `toast ${type} visible`;
  toastTimer = window.setTimeout(() => {
    elements.toast.classList.remove("visible");
  }, 2600);
}

async function readClipboard() {
  try {
    const value = await navigator.clipboard.readText();
    if (!value.trim()) throw new Error("Empty clipboard");
    elements.secretInput.value = value.trim();
    clearError();
    elements.secretInput.focus();
    showToast(translate("pasteSuccess"));
  } catch {
    showToast(translate("clipboardError"), "error");
    elements.secretInput.focus();
  }
}

async function copyCode() {
  if (!currentCode) return;

  try {
    await navigator.clipboard.writeText(currentCode);
    elements.copyButton.classList.add("copied");
    elements.copyButtonText.textContent = translate("copied");
    showToast(translate("copySuccess"));
    window.setTimeout(() => {
      elements.copyButton.classList.remove("copied");
      elements.copyButtonText.textContent = translate("copyCode");
    }, 1800);
  } catch {
    showToast(translate("copyError"), "error");
  }
}

elements.form.addEventListener("submit", (event) => {
  event.preventDefault();
  startGenerator(elements.secretInput.value);
});

elements.secretInput.addEventListener("input", clearError);
elements.pasteButton.addEventListener("click", readClipboard);
elements.copyButton.addEventListener("click", copyCode);
elements.newKeyButton.addEventListener("click", resetGenerator);
elements.saveKeyButton.addEventListener("click", () => {
  if (!currentSecret) return;
  const existing = getSavedKeys().find((item) => item.secret === currentSecret);
  elements.keyNameInput.value = existing?.name || "";
  elements.dialogError.textContent = "";
  elements.saveDialog.showModal();
  window.setTimeout(() => elements.keyNameInput.focus(), 50);
});

elements.saveForm.addEventListener("submit", (event) => {
  if (event.submitter?.value === "cancel") return;
  event.preventDefault();
  const name = elements.keyNameInput.value.trim();
  if (!name) {
    elements.dialogError.textContent = translate("nameRequired");
    elements.keyNameInput.focus();
    return;
  }
  saveCurrentKey(name);
  elements.saveDialog.close();
  showToast(translate("keySaved"));
});

elements.saveDialog.addEventListener("click", (event) => {
  if (event.target === elements.saveDialog) elements.saveDialog.close();
});

elements.revealButton.addEventListener("click", () => {
  const shouldShow = elements.secretInput.type === "password";
  elements.secretInput.type = shouldShow ? "text" : "password";
  elements.revealButton.classList.toggle("visible", shouldShow);
  updateRevealLabel();
  elements.secretInput.focus();
});

elements.languageToggle.addEventListener("click", () => {
  applyLanguage(currentLanguage === "ar" ? "en" : "ar");
});

document.addEventListener("visibilitychange", () => {
  if (!document.hidden && currentSecret) {
    refreshCode();
    updateTimer();
  }
});

window.addEventListener("pagehide", () => {
  stopTimer();
  currentSecret = "";
  currentCode = "";
});

window.addEventListener("pageshow", (event) => {
  if (event.persisted) {
    resetGenerator();
  }
});

elements.currentYear.textContent = String(new Date().getFullYear());
applyLanguage("ar");

const pathSecret = getSecretFromPath();
if (pathSecret) {
  startGenerator(pathSecret);
}
