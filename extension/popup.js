const storageKey = 'fluxoWeb3WalletVault';
const legacyStorageKey = 'goWeb3WalletVault';
const settingsKey = 'fluxoWalletSettings';
const autoLockMs = 5 * 60 * 1000;

let address = null;
let sessionId = null;
let account = null;
let accounts = [];
let networks = [];
let activeChainId = 1;
let autoLockTimer = null;
let copyFeedbackTimer = null;

const els = {
  status: document.getElementById('status'),
  setupView: document.getElementById('setupView'),
  backupView: document.getElementById('backupView'),
  lockedView: document.getElementById('lockedView'),
  walletView: document.getElementById('walletView'),
  createMode: document.getElementById('createMode'),
  importMode: document.getElementById('importMode'),
  createPanel: document.getElementById('createPanel'),
  importPanel: document.getElementById('importPanel'),
  setupPassword: document.getElementById('setupPassword'),
  setupPasswordConfirm: document.getElementById('setupPasswordConfirm'),
  importMnemonic: document.getElementById('importMnemonic'),
  importPassword: document.getElementById('importPassword'),
  createWallet: document.getElementById('createWallet'),
  importWallet: document.getElementById('importWallet'),
  seedGrid: document.getElementById('seedGrid'),
  backupConfirmed: document.getElementById('backupConfirmed'),
  finishBackup: document.getElementById('finishBackup'),
  unlockPassword: document.getElementById('unlockPassword'),
  lockedAddress: document.getElementById('lockedAddress'),
  vaultMeta: document.getElementById('vaultMeta'),
  unlockWallet: document.getElementById('unlockWallet'),
  accountName: document.getElementById('accountName'),
  walletAddressShort: document.getElementById('walletAddressShort'),
  copyState: document.getElementById('copyState'),
  networkSelect: document.getElementById('networkSelect'),
  networkIcon: document.getElementById('networkIcon'),
  networkName: document.getElementById('networkName'),
  networkMeta: document.getElementById('networkMeta'),
  balanceValue: document.getElementById('balanceValue'),
  balanceSymbol: document.getElementById('balanceSymbol'),
  balanceHint: document.getElementById('balanceHint'),
  chartDelta: document.getElementById('chartDelta'),
  refreshBalance: document.getElementById('refreshBalance'),
  openExplorer: document.getElementById('openExplorer'),
  focusSigner: document.getElementById('focusSigner'),
  assetSync: document.getElementById('assetSync'),
  assetList: document.getElementById('assetList'),
  accountList: document.getElementById('accountList'),
  derivationPath: document.getElementById('derivationPath'),
  signingDetails: document.getElementById('signingDetails'),
  message: document.getElementById('message'),
  signature: document.getElementById('signature'),
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
  await hardenStorageAccess().catch(() => setStatus('storage limited'));
  const settings = await getSettings();
  activeChainId = settings.activeChainId || activeChainId;

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

els.createMode.addEventListener('click', () => setSetupMode('create'));
els.importMode.addEventListener('click', () => setSetupMode('import'));

els.createWallet.addEventListener('click', () => {
  withButtonLock(els.createWallet, 'creating', async () => {
    const password = requirePasswordPair(els.setupPassword.value, els.setupPasswordConfirm.value);
    const response = callCore('createVault', password);
    await storeVault(response.vault);
    await hydrateSession(response);
    renderBackup(response.mnemonic);
  }, error => {
    lockAllSessions();
    setStatus(error.message || 'create failed');
  });
});

els.importWallet.addEventListener('click', () => {
  withButtonLock(els.importWallet, 'importing', async () => {
    const password = requirePassword(els.importPassword.value);
    const mnemonic = normalizeMnemonic(els.importMnemonic.value);
    if (mnemonic.split(' ').length < 12) throw new Error('seed phrase required');
    const response = callCore('importVault', password, mnemonic);
    await storeVault(response.vault);
    await hydrateSession(response);
    renderWallet();
    refreshBalance();
  }, error => {
    lockAllSessions();
    setStatus(error.message || 'import failed');
  });
});

els.backupConfirmed.addEventListener('change', () => {
  els.finishBackup.disabled = !els.backupConfirmed.checked;
});

els.finishBackup.addEventListener('click', () => {
  els.seedGrid.textContent = '';
  renderWallet();
  refreshBalance();
});

els.unlockWallet.addEventListener('click', () => {
  withButtonLock(els.unlockWallet, 'unlocking', async () => {
    const password = requirePassword(els.unlockPassword.value);
    const vault = await getVault();
    if (!vault) throw new Error('vault missing');
    const response = callCore('unlockVault', JSON.stringify(vault), password);
    if (response.migratedVault) await storeVault(response.migratedVault);
    await hydrateSession(response);
    renderWallet();
    refreshBalance();
  }, () => {
    lockAllSessions();
    lockMemory();
    setStatus('unlock failed');
  });
});

els.networkSelect.addEventListener('change', async () => {
  activeChainId = Number(els.networkSelect.value);
  await storeSettings({ activeChainId });
  renderNetwork();
  refreshBalance();
});

els.refreshBalance.addEventListener('click', () => refreshBalance());

els.openExplorer.addEventListener('click', () => {
  const network = getActiveNetwork();
  if (!network || !address) return;
  const url = `${network.explorerUrl}/address/${address}`;
  if (chrome.tabs?.create) {
    chrome.tabs.create({ url });
    return;
  }
  window.open(url, '_blank', 'noopener,noreferrer');
});

els.copyAddress.addEventListener('click', async () => {
  armAutoLock();
  if (!address) return;
  try {
    await navigator.clipboard.writeText(address);
    showCopyFeedback('Copied');
    setStatus('address copied');
  } catch (_) {
    showCopyFeedback('Copy failed');
    setStatus('clipboard blocked');
  }
});

els.focusSigner.addEventListener('click', () => {
  armAutoLock();
  els.signingDetails.open = true;
  document.getElementById('signingPanel')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  els.message.focus();
});

els.signMessage.addEventListener('click', () => {
  withButtonLock(els.signMessage, 'signing', async () => {
    if (!sessionId) throw new Error('wallet locked');
    const message = els.message.value.trim();
    if (!message) throw new Error('message required');
    const signed = callCore('signMessage', sessionId, message);
    els.signature.value = signed.signature;
    setStatus('signed');
  }, error => setStatus(error.message || 'sign failed'));
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

document.querySelectorAll('.range-tab').forEach(button => {
  button.addEventListener('click', () => {
    document.querySelectorAll('.range-tab').forEach(item => item.classList.remove('active'));
    button.classList.add('active');
  });
});

document.querySelectorAll('[data-jump]').forEach(button => {
  button.addEventListener('click', () => {
    const target = document.getElementById(button.dataset.jump);
    if (!target) return;
    document.querySelectorAll('[data-jump]').forEach(item => item.classList.remove('active'));
    button.classList.add('active');
    if (target.id === 'signingPanel') els.signingDetails.open = true;
    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    armAutoLock();
  });
});

els.resetWallet.addEventListener('click', async () => {
  if (!confirm('Delete the encrypted local vault from this browser profile?')) return;
  lockAllSessions();
  await chrome.storage.local.remove([storageKey, legacyStorageKey, settingsKey]);
  lockMemory();
  renderSetup();
});

window.addEventListener('pagehide', () => lockActiveSession());
window.addEventListener('beforeunload', () => lockActiveSession());

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
  if (!parsed.ok) throw new Error(parsed.error || 'wallet core error');
  return parsed.data;
}

async function waitForWalletCore() {
  for (let attempt = 0; attempt < 50; attempt++) {
    if (globalThis.walletCore) return;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error('wallet core unavailable');
}

async function hydrateSession(response) {
  sessionId = response.sessionId;
  address = response.address;
  account = response.account;
  accounts = response.accounts || (account ? [account] : []);
  networks = response.networks || networks;
  if (!networks.some(network => network.chainId === activeChainId)) {
    activeChainId = response.activeChainId || networks[0]?.chainId || 1;
    await storeSettings({ activeChainId });
  }
  armAutoLock();
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

async function getSettings() {
  const result = await chrome.storage.local.get(settingsKey);
  return result[settingsKey] || {};
}

async function storeSettings(partial) {
  const current = await getSettings();
  await chrome.storage.local.set({ [settingsKey]: { ...current, ...partial } });
}

function renderSetup() {
  lockMemory();
  setSetupMode('create');
  setStatus('new wallet');
  showOnly(els.setupView);
}

function setSetupMode(mode) {
  const importing = mode === 'import';
  els.createMode.classList.toggle('active', !importing);
  els.importMode.classList.toggle('active', importing);
  els.createPanel.classList.toggle('hidden', importing);
  els.importPanel.classList.toggle('hidden', !importing);
}

function renderBackup(mnemonic) {
  els.backupConfirmed.checked = false;
  els.finishBackup.disabled = true;
  els.seedGrid.textContent = '';
  mnemonic.split(' ').forEach((word, index) => {
    const item = document.createElement('div');
    item.className = 'seed-word';
    item.innerHTML = `<span>${index + 1}</span><strong>${word}</strong>`;
    els.seedGrid.appendChild(item);
  });
  setStatus('backup');
  showOnly(els.backupView);
}

function renderLocked(walletAddress, vault = null) {
  address = walletAddress || null;
  els.lockedAddress.textContent = shortAddress(walletAddress) || '-';
  els.vaultMeta.textContent = formatVaultMeta(vault);
  els.unlockPassword.value = '';
  setStatus('locked');
  showOnly(els.lockedView);
}

function renderWallet() {
  if (!address || !sessionId) return renderSetup();
  const network = getActiveNetwork();
  els.accountName.textContent = account?.path === 'imported' ? 'Imported account' : `Account ${(account?.index || 0) + 1}`;
  els.walletAddressShort.textContent = shortAddress(address);
  els.derivationPath.textContent = account?.path || 'imported';
  renderNetworkOptions();
  renderNetwork();
  renderAssets('-.----');
  renderAccounts();
  els.setupPassword.value = '';
  els.setupPasswordConfirm.value = '';
  els.importMnemonic.value = '';
  els.importPassword.value = '';
  els.unlockPassword.value = '';
  els.balanceValue.textContent = '-.----';
  els.balanceSymbol.textContent = network?.symbol || 'ETH';
  els.balanceHint.textContent = network ? `Native balance on ${network.name}` : 'Live native balance';
  els.assetSync.textContent = 'waiting';
  els.chartDelta.textContent = 'RPC live';
  els.signature.value = '';
  setStatus('unlocked');
  showOnly(els.walletView);
  armAutoLock();
}

function renderNetworkOptions() {
  els.networkSelect.textContent = '';
  networks.forEach(network => {
    const option = document.createElement('option');
    option.value = String(network.chainId);
    option.textContent = `${network.name} (${network.symbol})`;
    option.selected = network.chainId === activeChainId;
    els.networkSelect.appendChild(option);
  });
}

function renderNetwork() {
  const network = getActiveNetwork();
  if (!network) return;
  const key = normalizeNetworkKey(network);
  els.networkIcon.dataset.network = key;
  els.networkName.textContent = shortNetworkName(network.name);
  els.networkMeta.textContent = `Chain ${network.chainId}`;
  els.balanceSymbol.textContent = network.symbol;
  els.balanceHint.textContent = `Native balance on ${network.name}`;
  els.networkSelect.value = String(network.chainId);
  renderAssets(els.balanceValue.textContent);
}

function renderAccounts() {
  els.accountList.textContent = '';
  accounts.forEach(item => {
    const row = document.createElement('div');
    row.className = 'account-row active';
    row.innerHTML = `
      <span>${item.path === 'imported' ? 'Imported' : `Account ${item.index + 1}`}</span>
      <code>${shortAddress(item.address)}</code>
    `;
    els.accountList.appendChild(row);
  });
}

function renderAssets(balanceText) {
  const network = getActiveNetwork();
  if (!network || !els.assetList) return;
  els.assetList.textContent = '';
  const row = document.createElement('div');
  row.className = 'asset-row';

  const main = document.createElement('div');
  main.className = 'asset-main';

  const icon = document.createElement('span');
  icon.className = 'asset-icon';
  icon.dataset.network = normalizeNetworkKey(network);

  const copy = document.createElement('span');
  copy.className = 'asset-copy';
  const title = document.createElement('strong');
  title.textContent = network.symbol;
  const subtitle = document.createElement('small');
  subtitle.textContent = `${network.name} native asset`;
  copy.append(title, subtitle);

  const value = document.createElement('span');
  value.className = 'asset-value';
  const amount = document.createElement('strong');
  amount.textContent = formatAssetAmount(balanceText, network.symbol);
  const meta = document.createElement('small');
  meta.textContent = network.chainId === 1 ? 'Ethereum mainnet' : `Chain ${network.chainId}`;
  value.append(amount, meta);

  main.append(icon, copy);
  row.append(main, value);
  els.assetList.appendChild(row);
}

async function refreshBalance() {
  if (!address || !sessionId) return;
  const network = getActiveNetwork();
  if (!network) return;
  setStatus('syncing');
  els.balanceValue.textContent = 'loading';
  els.balanceHint.textContent = `Querying ${network.name}`;
  els.assetSync.textContent = 'syncing';
  els.chartDelta.textContent = 'syncing';
  renderAssets('loading');
  try {
    const balanceHex = await rpcCall(network.rpcUrl, 'eth_getBalance', [address, 'latest']);
    const value = formatNativeBalance(balanceHex);
    els.balanceValue.textContent = value;
    els.balanceSymbol.textContent = network.symbol;
    els.balanceHint.textContent = `Updated from ${network.name}`;
    els.assetSync.textContent = 'live';
    els.chartDelta.textContent = 'RPC live';
    renderAssets(value);
    setStatus('online');
  } catch (_) {
    els.balanceValue.textContent = 'offline';
    els.balanceHint.textContent = `${network.name} RPC unavailable`;
    els.assetSync.textContent = 'offline';
    els.chartDelta.textContent = 'RPC offline';
    renderAssets('offline');
    setStatus('rpc offline');
  }
}

async function rpcCall(rpcUrl, method, params) {
  const response = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: Date.now(), method, params })
  });
  if (!response.ok) throw new Error(`rpc status ${response.status}`);
  const payload = await response.json();
  if (payload.error) throw new Error(payload.error.message || 'rpc error');
  return payload.result;
}

function formatNativeBalance(hexValue) {
  const wei = BigInt(hexValue || '0x0');
  const whole = wei / 10n ** 18n;
  const fraction = (wei % 10n ** 18n).toString().padStart(18, '0').slice(0, 4);
  return `${whole}.${fraction}`;
}

function getActiveNetwork() {
  return networks.find(network => network.chainId === activeChainId) || networks[0] || null;
}

function normalizeNetworkKey(network) {
  if (!network?.key) return 'ethereum';
  if (network.key === 'sepolia') return 'sepolia';
  return network.key;
}

function shortNetworkName(name) {
  return name.replace(' One', '').replace('Mainnet', '').trim();
}

function formatAssetAmount(value, symbol) {
  if (!value || value === '-.----') return `-.---- ${symbol}`;
  if (value === 'loading') return `syncing ${symbol}`;
  if (value === 'unavailable' || value === 'offline') return 'offline';
  return `${value} ${symbol}`;
}

function requirePassword(password) {
  if (!password || password.length < 12) throw new Error('password must be 12+ characters');
  return password;
}

function requirePasswordPair(password, confirmation) {
  requirePassword(password);
  if (password !== confirmation) throw new Error('passwords do not match');
  return password;
}

function normalizeMnemonic(value) {
  return value.trim().toLowerCase().replace(/\s+/g, ' ');
}

function lockMemory() {
  sessionId = null;
  account = null;
  accounts = [];
  clearAutoLock();
  showCopyFeedback('Copy', false);
  if (els.signature) els.signature.value = '';
}

function showOnly(view) {
  [els.setupView, els.backupView, els.lockedView, els.walletView].forEach(item => item.classList.add('hidden'));
  view.classList.remove('hidden');
}

function setStatus(value) {
  els.status.textContent = value;
}

function showCopyFeedback(value, temporary = true) {
  clearTimeout(copyFeedbackTimer);
  els.copyState.textContent = value;
  els.copyAddress.classList.toggle('copied', value === 'Copied');
  if (!temporary) return;
  copyFeedbackTimer = setTimeout(() => {
    els.copyState.textContent = 'Copy';
    els.copyAddress.classList.remove('copied');
  }, 1400);
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
  if (!vault || typeof vault !== 'object') throw new Error('stored vault is invalid');
  if (vault.header?.version === 3 || vault.header?.version === 2) {
    const header = vault.header;
    requireString(header.address, 'vault address');
    requireString(header.cipher, 'vault cipher');
    requireString(header.kdf, 'vault kdf');
    requireString(header.createdAt, 'vault createdAt');
    if (!header.kdfParams || typeof header.kdfParams !== 'object') throw new Error('vault kdf params missing');
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
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`${field} is invalid`);
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
  if (vault.header?.version === 3) return 'HD vault / seed phrase / Argon2id';
  if (vault.header?.version === 2) return 'legacy key vault / Argon2id';
  if (vault.version === 1) return `legacy v1 / ${vault.kdf || 'PBKDF2-SHA256'}`;
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

function shortAddress(value) {
  if (!value) return '';
  return `${value.slice(0, 6)}...${value.slice(-4)}`;
}
