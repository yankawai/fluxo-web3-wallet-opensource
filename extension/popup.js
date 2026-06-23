const storageKey = 'goWeb3WalletVault';
const kdfIterations = 250000;

let privateKey = null;
let address = null;

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
  renderLocked(vault.address);
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
    const wallet = callCore('generateWallet');
    const vault = await encryptPrivateKey(wallet.privateKey, password, wallet.address);
    await chrome.storage.local.set({ [storageKey]: vault });
    privateKey = wallet.privateKey;
    address = wallet.address;
    renderWallet(wallet.address);
  } catch (error) {
    setStatus(error.message || 'create failed');
  }
});

els.unlockWallet.addEventListener('click', async () => {
  try {
    const password = requirePassword(els.unlockPassword.value);
    const vault = await getVault();
    if (!vault) throw new Error('vault missing');
    privateKey = await decryptPrivateKey(vault, password);
    address = callCore('addressFromPrivateKey', privateKey).address;
    renderWallet(address);
  } catch (error) {
    lockMemory();
    setStatus('unlock failed');
  }
});

els.signMessage.addEventListener('click', async () => {
  try {
    if (!privateKey) throw new Error('wallet locked');
    const message = els.message.value.trim();
    if (!message) throw new Error('message required');
    const signed = callCore('signMessage', privateKey, message);
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
  lockMemory();
  renderLocked(address);
});

els.resetWallet.addEventListener('click', async () => {
  if (!confirm('Delete the encrypted local vault from this browser profile?')) return;
  await chrome.storage.local.remove(storageKey);
  lockMemory();
  renderSetup();
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

async function encryptPrivateKey(key, password, walletAddress) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cryptoKey = await deriveKey(password, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    new TextEncoder().encode(key)
  );
  return {
    version: 1,
    address: walletAddress,
    kdf: 'PBKDF2-SHA256',
    iterations: kdfIterations,
    salt: toBase64(salt),
    iv: toBase64(iv),
    ciphertext: toBase64(new Uint8Array(ciphertext))
  };
}

async function decryptPrivateKey(vault, password) {
  const salt = fromBase64(vault.salt);
  const iv = fromBase64(vault.iv);
  const ciphertext = fromBase64(vault.ciphertext);
  const cryptoKey = await deriveKey(password, salt);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    ciphertext
  );
  return new TextDecoder().decode(plaintext);
}

async function deriveKey(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: kdfIterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function requirePassword(password) {
  if (!password || password.length < 12) {
    throw new Error('password must be 12+ characters');
  }
  return password;
}

function lockMemory() {
  privateKey = null;
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

function toBase64(bytes) {
  let binary = '';
  bytes.forEach(byte => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
