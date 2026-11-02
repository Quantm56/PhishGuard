/**
 * PhishGuard Extension - Popup Controller
 *
 * Communicates with the background service worker to fetch and display the current tab's
 * URL scan result. Adheres strictly to security requirements:
 * 1. Plain-text rendering for all API reasons and summaries (no innerHTML evaluation).
 * 2. Clear state handling: Checking, Completed, Error, Unsupported URL.
 * 3. Never treats an error as legitimate.
 * 4. Includes manual "Scan again" functionality.
 */

// UI Elements
const targetUrlEl = document.getElementById('targetUrl');
const stateUnsupportedEl = document.getElementById('stateUnsupported');
const stateCheckingEl = document.getElementById('stateChecking');
const stateErrorEl = document.getElementById('stateError');
const stateResultEl = document.getElementById('stateResult');

const errorDetailsEl = document.getElementById('errorDetails');
const verdictBadgeEl = document.getElementById('verdictBadge');
const scoreValueEl = document.getElementById('scoreValue');
const scoreBarFillEl = document.getElementById('scoreBarFill');
const summaryTextEl = document.getElementById('summaryText');
const reasonsListEl = document.getElementById('reasonsList');
const reasonsSectionEl = document.getElementById('reasonsSection');
const domainMetaEl = document.getElementById('domainMeta');
const modelMetaEl = document.getElementById('modelMeta');
const rescanBtn = document.getElementById('rescanBtn');

let currentTabId = null;
let currentUrl = null;

/**
 * Hides all state sections.
 */
function hideAllStates() {
  stateUnsupportedEl.classList.add('hide');
  stateCheckingEl.classList.add('hide');
  stateErrorEl.classList.add('hide');
  stateResultEl.classList.add('hide');
}

/**
 * Renders an unsupported page state (e.g. chrome://, about:blank).
 */
function renderUnsupported(url) {
  hideAllStates();
  targetUrlEl.textContent = url || 'Blank / Internal Page';
  stateUnsupportedEl.classList.remove('hide');
  rescanBtn.disabled = true;
}

/**
 * Renders the in-progress checking state.
 */
function renderChecking(url) {
  hideAllStates();
  targetUrlEl.textContent = url || 'Loading URL...';
  stateCheckingEl.classList.remove('hide');
  rescanBtn.disabled = true;
}

/**
 * Renders the scan failure or unreachable API state.
 */
function renderError(url, message) {
  hideAllStates();
  targetUrlEl.textContent = url || 'Unknown URL';
  errorDetailsEl.textContent = message || 'Unable to scan. The PhishGuard API is stopped or unreachable.';
  stateErrorEl.classList.remove('hide');
  rescanBtn.disabled = false;
}

/**
 * Renders a successful scan response from the PhishGuard API.
 * Uses textContent exclusively to prevent XSS.
 */
function renderResult(url, data) {
  hideAllStates();
  targetUrlEl.textContent = url;
  rescanBtn.disabled = false;

  const verdict = data.verdict || 'UNKNOWN';
  const score = typeof data.final_score === 'number' ? data.final_score : 0.0;
  const scorePct = (score * 100).toFixed(1) + '%';

  // Badge mapping
  verdictBadgeEl.className = 'verdict-badge';
  if (verdict === 'LEGITIMATE') {
    verdictBadgeEl.textContent = 'SAFE';
    verdictBadgeEl.classList.add('SAFE');
    scoreBarFillEl.style.backgroundColor = 'var(--safe-green)';
  } else if (verdict === 'SUSPICIOUS') {
    verdictBadgeEl.textContent = 'CHECK';
    verdictBadgeEl.classList.add('CHECK');
    scoreBarFillEl.style.backgroundColor = 'var(--check-amber)';
  } else if (verdict === 'PHISHING') {
    verdictBadgeEl.textContent = 'RISK';
    verdictBadgeEl.classList.add('RISK');
    scoreBarFillEl.style.backgroundColor = 'var(--risk-red)';
  } else {
    verdictBadgeEl.textContent = '?';
    scoreBarFillEl.style.backgroundColor = 'var(--neutral-grey)';
  }

  scoreValueEl.textContent = scorePct;
  scoreBarFillEl.style.width = Math.min(100, Math.max(0, score * 100)) + '%';

  // High-level plain-text reason
  summaryTextEl.textContent = data.reason || 'No summary reason provided.';

  // Build plain text explanations & signals securely
  while (reasonsListEl.firstChild) {
    reasonsListEl.removeChild(reasonsListEl.firstChild);
  }

  const items = [];

  // 1. Threat Intel listed feeds
  if (data.osint && Array.isArray(data.osint.threat_intel)) {
    data.osint.threat_intel.forEach((t) => {
      if (t.status === 'listed') {
        items.push({
          tag: 'RISK',
          type: 'up',
          text: `Listed by ${t.source}: ${t.detail || 'Verified threat'}`
        });
      }
    });
  }

  // 2. Rule signals
  if (Array.isArray(data.signals)) {
    data.signals.forEach((s) => {
      const weight = typeof s.weight === 'number' ? s.weight : 0;
      const type = weight > 0 ? 'up' : weight < 0 ? 'down' : 'neutral';
      const pts = (weight >= 0 ? '+' : '') + (weight * 100).toFixed(0) + ' pts';
      items.push({
        tag: pts,
        type,
        text: s.detail || s.name
      });
    });
  }

  // 3. Model feature explanation
  if (Array.isArray(data.explanation)) {
    data.explanation.slice(0, 4).forEach((e) => {
      const effect = typeof e.effect === 'number' ? e.effect : 0;
      const type = effect > 0 ? 'up' : effect < 0 ? 'down' : 'neutral';
      const pts = (effect >= 0 ? '+' : '') + (effect * 100).toFixed(1) + '%';
      items.push({
        tag: pts,
        type,
        text: `${e.meaning} (observed: ${e.value})`
      });
    });
  }

  if (items.length > 0) {
    reasonsSectionEl.classList.remove('hide');
    items.slice(0, 5).forEach((item) => {
      const li = document.createElement('li');
      li.className = 'reason-item';

      const tagSpan = document.createElement('span');
      tagSpan.className = `reason-tag ${item.type}`;
      tagSpan.textContent = item.tag;

      const textSpan = document.createElement('span');
      textSpan.className = 'reason-text';
      textSpan.textContent = item.text;

      li.appendChild(tagSpan);
      li.appendChild(textSpan);
      reasonsListEl.appendChild(li);
    });
  } else {
    const li = document.createElement('li');
    li.className = 'reason-item';
    const textSpan = document.createElement('span');
    textSpan.className = 'reason-text';
    textSpan.textContent = 'No adverse signals or prominent risk indicators triggered.';
    li.appendChild(textSpan);
    reasonsListEl.appendChild(li);
  }

  // Metadata
  domainMetaEl.textContent = `Domain: ${data.registered_domain || data.host || '-'}`;
  modelMetaEl.textContent = `Model: ${data.model_used || data.model_name || '-'}`;

  stateResultEl.classList.remove('hide');
}

/**
 * Applies the received state to the popup view.
 */
function applyState(state) {
  if (!state) {
    renderError(currentUrl, 'No scan state recorded for this tab.');
    return;
  }

  if (state.status === 'unsupported') {
    renderUnsupported(state.url || currentUrl);
  } else if (state.status === 'checking') {
    renderChecking(state.url || currentUrl);
  } else if (state.status === 'completed' && state.result) {
    renderResult(state.url || currentUrl, state.result);
  } else if (state.status === 'error') {
    renderError(state.url || currentUrl, state.details || state.error);
  } else {
    renderError(state.url || currentUrl, 'Unrecognized status from background worker.');
  }
}

/**
 * Initializes the popup by querying the active tab and requesting its status.
 */
async function initPopup() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) {
      renderError('', 'No active browser tab detected.');
      return;
    }

    currentTabId = tab.id;
    currentUrl = tab.url || '';

    // If currently on the pre-visit checking page, extract destination URL
    if (currentUrl.includes('/checking.html?url=')) {
      const idx = currentUrl.indexOf('/checking.html?url=');
      const raw = currentUrl.slice(idx + '/checking.html?url='.length);
      try {
        currentUrl = decodeURI(raw);
      } catch {
        currentUrl = raw;
      }
    }

    targetUrlEl.textContent = currentUrl;

    // Check scheme first
    if (!currentUrl.startsWith('http://') && !currentUrl.startsWith('https://')) {
      renderUnsupported(currentUrl);
      return;
    }

    renderChecking(currentUrl);

    // Request status from background worker
    chrome.runtime.sendMessage(
      { action: 'GET_TAB_STATUS', tabId: currentTabId, url: currentUrl },
      (response) => {
        if (chrome.runtime.lastError) {
          renderError(currentUrl, 'Could not connect to background service worker.');
          return;
        }
        applyState(response);
      }
    );
  } catch (err) {
    renderError(currentUrl, err.message || 'Error initializing popup.');
  }
}

// "Scan again" button handler
rescanBtn.addEventListener('click', () => {
  if (!currentTabId || !currentUrl) return;

  renderChecking(currentUrl);
  chrome.runtime.sendMessage(
    { action: 'RESCAN_TAB', tabId: currentTabId, url: currentUrl },
    (response) => {
      if (chrome.runtime.lastError) {
        renderError(currentUrl, 'Scan again request failed.');
        return;
      }
      applyState(response);
    }
  );
});

// Start initialization
document.addEventListener('DOMContentLoaded', initPopup);

