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
  renderLocked(getVaultAddress(vault));
}

async function loadWasm() {
  const go = new Go();
  const result = await WebAssembly.instantiateStreaming(fetch('wallet.wasm'), go.importObject);
  go.run(result.instance);
  await waitForWalletCore();
}

els.createWallet.addEventListener('click', async () => {
  try {
    const password = requirePassword(els.setupPassword.value);
    const response = callCore('createVault', password);
    await storeVault(response.vault);
    sessionId = response.sessionId;
    address = response.address;
    renderWallet(response.address);
  } catch (error) {
    lockAllSessions();
    setStatus(error.message || 'create failed');
  }
});

els.unlockWallet.addEventListener('click', async () => {
  try {
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
  } catch (error) {
    lockMemory();
    setStatus('unlock failed');
  }
});

els.signMessage.addEventListener('click', async () => {
  try {
    if (!sessionId) throw new Error('wallet locked');
    const message = els.message.value.trim();
    if (!message) throw new Error('message required');
    const signed = callCore('signMessage', sessionId, message);
    els.signature.value = signed.signature;
    setStatus('signed');
  } catch (error) {
    setStatus(error.message || 'sign failed');
  }
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
  renderLocked(address);
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

function renderLocked(walletAddress) {
  address = walletAddress || null;
  els.lockedAddress.textContent = walletAddress || '-';
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
