const storageKey = 'goWeb3WalletVault';

let address = null;
let sessionId = null;

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
  const vault = await getVault();
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
  if (address) await navigator.clipboard.writeText(address);
  setStatus('address copied');
});

els.copySignature.addEventListener('click', async () => {
  if (els.signature.value) await navigator.clipboard.writeText(els.signature.value);
  setStatus('signature copied');
});

els.lockWallet.addEventListener('click', () => {
  lockActiveSession();
  lockMemory();
  getVault().then(vault => renderLocked(address, vault)).catch(() => renderLocked(address));
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
  const result = await chrome.storage.local.get(storageKey);
  return result[storageKey] || null;
}

async function storeVault(vault) {
  await chrome.storage.local.set({ [storageKey]: vault });
}

function requirePassword(password) {
  if (!password || password.length < 12) {
    throw new Error('password must be 12+ characters');
  }
  return password;
}

function lockMemory() {
  sessionId = null;
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
