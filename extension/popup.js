const storageKey = 'fluxoWeb3WalletVault';
const legacyStorageKey = 'goWeb3WalletVault';
const autoLockMs = 5 * 60 * 1000;

let address = null;
let sessionId = null;
let autoLockTimer = null;

const els = {
  status: document.getElementById('status'),
  setupView: document.getElementById('setupView'),
  lockedView: document.getElementById('lockedView'),
  walletView: document.getElementById('walletView'),
  setupPassword: document.getElementById('setupPassword'),
  unlockPassword: document.getElementById('unlockPassword'),
  lockedAddress: document.getElementById('lockedAddress'),
  vaultMeta: document.getElementById('vaultMeta'),
  walletAddress: document.getElementById('walletAddress'),
  message: document.getElementById('message'),
  signature: document.getElementById('signature'),
  createWallet: document.getElementById('createWallet'),
  unlockWallet: document.getElementById('unlockWallet'),
  signMessage: document.getElementById('signMessage'),
  copyAddress: document.getElementById('copyAddress'),
  copySignature: document.getElementById('copySignature'),
  lockWallet: document.getElementById('lockWallet'),
  resetWallet: document.getElementById('resetWallet')
};

boot().catch(error => {
  setStatus(error.message || 'failed');
});

async function boot() {
  await loadWasm();
  await hardenStorageAccess().catch(() => {
    setStatus('storage hardening unavailable');
  });
  let vault = null;
  try {
    vault = await getVault();
  } catch (_) {
    lockAllSessions();
    renderSetup();
    setStatus('vault data invalid');
    return;
  }
  if (!vault) {
    renderSetup();
    return;
  }
  renderLocked(getVaultAddress(vault), vault);
}

async function loadWasm() {
  const go = new Go();
  const result = await WebAssembly.instantiateStreaming(fetch('wallet.wasm'), go.importObject);
  go.run(result.instance);
  await waitForWalletCore();
}

els.createWallet.addEventListener('click', async () => {
  withButtonLock(els.createWallet, 'creating', async () => {
    const password = requirePassword(els.setupPassword.value);
    const response = callCore('createVault', password);
    await storeVault(response.vault);
    sessionId = response.sessionId;
    address = response.address;
    renderWallet(response.address);
  }, error => {
    lockAllSessions();
    setStatus(error.message || 'create failed');
  });
});

els.unlockWallet.addEventListener('click', async () => {
  withButtonLock(els.unlockWallet, 'unlocking', async () => {
    const password = requirePassword(els.unlockPassword.value);
    const vault = await getVault();
    if (!vault) throw new Error('vault missing');
    const response = callCore('unlockVault', JSON.stringify(vault), password);
    if (response.migratedVault) {
      await storeVault(response.migratedVault);
    }
    sessionId = response.sessionId;
    address = response.address;
    renderWallet(response.address);
  }, () => {
    lockAllSessions();
    lockMemory();
    setStatus('unlock failed');
  });
});

els.signMessage.addEventListener('click', async () => {
  withButtonLock(els.signMessage, 'signing', async () => {
    if (!sessionId) throw new Error('wallet locked');
    const message = els.message.value.trim();
    if (!message) throw new Error('message required');
    const signed = callCore('signMessage', sessionId, message);
    els.signature.value = signed.signature;
    setStatus('signed');
  }, error => {
    setStatus(error.message || 'sign failed');
  });
});

els.copyAddress.addEventListener('click', async () => {
  armAutoLock();
  if (address) await navigator.clipboard.writeText(address);
  setStatus('address copied');
});

els.copySignature.addEventListener('click', async () => {
  armAutoLock();
  if (els.signature.value) await navigator.clipboard.writeText(els.signature.value);
  setStatus('signature copied');
});

els.lockWallet.addEventListener('click', () => {
  lockActiveSession();
  lockMemory();
  renderLockedFromStorage(address);
});

els.resetWallet.addEventListener('click', async () => {
  if (!confirm('Delete the encrypted local vault from this browser profile?')) return;
  lockAllSessions();
  await chrome.storage.local.remove(storageKey);
  lockMemory();
  renderSetup();
});

window.addEventListener('pagehide', () => {
  lockActiveSession();
});

window.addEventListener('beforeunload', () => {
  lockActiveSession();
});

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') {
    const lockedAddress = address;
    lockActiveSession();
    lockMemory();
    renderLockedFromStorage(lockedAddress);
  }
});

['click', 'keydown', 'input'].forEach(eventName => {
  document.addEventListener(eventName, armAutoLock, { passive: true });
});

function callCore(method, ...args) {
  const raw = globalThis.walletCore[method](...args);
  const parsed = JSON.parse(raw);
  if (!parsed.ok) {
    throw new Error(parsed.error || 'wallet core error');
  }
  return parsed.data;
}

async function waitForWalletCore() {
  for (let attempt = 0; attempt < 50; attempt++) {
    if (globalThis.walletCore) return;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error('wallet core unavailable');
}

async function getVault() {
  const result = await chrome.storage.local.get([storageKey, legacyStorageKey]);
  const vault = result[storageKey] || result[legacyStorageKey] || null;
  if (!vault) return null;
  const normalized = normalizeStoredVault(vault);
  if (!result[storageKey] && result[legacyStorageKey]) {
    await storeVault(normalized);
    await chrome.storage.local.remove(legacyStorageKey);
  }
  return normalized;
}

async function storeVault(vault) {
  await chrome.storage.local.set({ [storageKey]: normalizeStoredVault(vault) });
}

function requirePassword(password) {
  if (!password || password.length < 12) {
    throw new Error('password must be 12+ characters');
  }
  return password;
}

function lockMemory() {
  sessionId = null;
  clearAutoLock();
  els.signature.value = '';
}

function renderSetup() {
  setStatus('new vault');
  showOnly(els.setupView);
}

function renderLocked(walletAddress, vault = null) {
  address = walletAddress || null;
  els.lockedAddress.textContent = walletAddress || '-';
  els.vaultMeta.textContent = formatVaultMeta(vault);
  els.unlockPassword.value = '';
  setStatus('locked');
  showOnly(els.lockedView);
}

function renderWallet(walletAddress) {
  address = walletAddress;
  els.walletAddress.textContent = walletAddress;
  els.setupPassword.value = '';
  els.unlockPassword.value = '';
  setStatus('unlocked');
  armAutoLock();
  showOnly(els.walletView);
}

function showOnly(view) {
  [els.setupView, els.lockedView, els.walletView].forEach(item => item.classList.add('hidden'));
  view.classList.remove('hidden');
}

function setStatus(value) {
  els.status.textContent = value;
}

function lockActiveSession() {
  if (!sessionId || !globalThis.walletCore) return;
  try {
    callCore('lock', sessionId);
  } catch (_) {
    // Lock is best effort during popup teardown.
  }
}

function lockAllSessions() {
  if (!globalThis.walletCore) return;
  try {
    callCore('lockAll');
  } catch (_) {
    // Lock is best effort after failed setup or reset.
  }
}

function getVaultAddress(vault) {
  return vault?.header?.address || vault?.address || null;
}

async function hardenStorageAccess() {
  if (!chrome.storage.local.setAccessLevel) return;
  await chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
}

function normalizeStoredVault(vault) {
  if (!vault || typeof vault !== 'object') {
    throw new Error('stored vault is invalid');
  }
  if (vault.header?.version === 2) {
    const header = vault.header;
    requireString(header.address, 'vault address');
    requireString(header.cipher, 'vault cipher');
    requireString(header.kdf, 'vault kdf');
    requireString(header.createdAt, 'vault createdAt');
    if (!header.kdfParams || typeof header.kdfParams !== 'object') {
      throw new Error('vault kdf params missing');
    }
    requireString(vault.salt, 'vault salt');
    requireString(vault.nonce, 'vault nonce');
    requireString(vault.ciphertext, 'vault ciphertext');
    return vault;
  }
  if (vault.version === 1) {
    requireString(vault.address, 'legacy vault address');
    requireString(vault.salt, 'legacy vault salt');
    requireString(vault.iv, 'legacy vault iv');
    requireString(vault.ciphertext, 'legacy vault ciphertext');
    return vault;
  }
  throw new Error('unsupported stored vault version');
}

function requireString(value, field) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`${field} is invalid`);
  }
}

async function renderLockedFromStorage(fallbackAddress = null) {
  try {
    const vault = await getVault();
    renderLocked(getVaultAddress(vault) || fallbackAddress, vault);
  } catch (_) {
    renderLocked(fallbackAddress);
  }
}

function formatVaultMeta(vault) {
  if (!vault) return 'encrypted local vault';
  if (vault.header?.version === 2) {
    const params = vault.header.kdfParams || {};
    const memoryMiB = params.memoryKiB ? Math.round(params.memoryKiB / 1024) : '?';
    return `v2 / ${vault.header.cipher} / ${vault.header.kdf} ${memoryMiB} MiB`;
  }
  if (vault.version === 1) {
    return `legacy v1 / ${vault.kdf || 'PBKDF2-SHA256'}`;
  }
  return 'unknown vault format';
}

async function withButtonLock(button, status, task, onError) {
  if (button.disabled) return;
  button.disabled = true;
  setStatus(status);
  try {
    await task();
  } catch (error) {
    onError(error);
  } finally {
    button.disabled = false;
  }
}

function armAutoLock() {
  if (!sessionId) return;
  clearAutoLock();
  autoLockTimer = setTimeout(() => {
    const lockedAddress = address;
    lockActiveSession();
    lockMemory();
    renderLockedFromStorage(lockedAddress);
  }, autoLockMs);
}

function clearAutoLock() {
  if (!autoLockTimer) return;
  clearTimeout(autoLockTimer);
  autoLockTimer = null;
}
