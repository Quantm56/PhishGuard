/**
 * PhishGuard Extension - Pre-Visit Checking Controller
 *
 * Runs inside the checking.html extension tab when a top-level navigation is intercepted.
 * 1. Safely parses the original destination URL from location.href.
 * 2. Immediately displays the checking state with the target URL.
 * 3. Dispatches POST /api/predict to the local PhishGuard API with bounded timeout.
 * 4. If verdict is LEGITIMATE: requests scoped ALLOW_ONCE rule from background and forwards to destination.
 * 5. If verdict is SUSPICIOUS or PHISHING: renders warning page with plain-text reasons, offering Go Back and Proceed Anyway.
 * 6. If API is offline/error: renders explicit user choice and never assumes safety.
 */

import { CONFIG } from './config.js';

// DOM Views
const viewChecking = document.getElementById('viewChecking');
const viewPassing = document.getElementById('viewPassing');
const viewWarning = document.getElementById('viewWarning');
const viewError = document.getElementById('viewError');

// DOM Elements
const targetUrlDisplay = document.getElementById('targetUrlDisplay');
const statusChip = document.getElementById('statusChip');
const footerMeta = document.getElementById('footerMeta');

// Warning View Elements
const warningBanner = document.getElementById('warningBanner');
const warningBannerText = document.getElementById('warningBannerText');
const warningBadge = document.getElementById('warningBadge');
const warningScore = document.getElementById('warningScore');
const warningScoreFill = document.getElementById('warningScoreFill');
const warningSummaryReason = document.getElementById('warningSummaryReason');
const warningReasonsList = document.getElementById('warningReasonsList');
const btnWarningBack = document.getElementById('btnWarningBack');
const btnWarningProceedPrompt = document.getElementById('btnWarningProceedPrompt');
const confirmProceedPanel = document.getElementById('confirmProceedPanel');
const btnConfirmProceed = document.getElementById('btnConfirmProceed');
const btnCancelProceed = document.getElementById('btnCancelProceed');

// Error View Elements
const errorDescription = document.getElementById('errorDescription');
const btnErrorBack = document.getElementById('btnErrorBack');
const btnErrorRetry = document.getElementById('btnErrorRetry');
const btnErrorProceedPrompt = document.getElementById('btnErrorProceedPrompt');
const confirmErrorProceedPanel = document.getElementById('confirmErrorProceedPanel');
const btnConfirmErrorProceed = document.getElementById('btnConfirmErrorProceed');
const btnCancelErrorProceed = document.getElementById('btnCancelErrorProceed');

let targetUrl = '';

/**
 * Extracts and decodes the intended destination URL from window.location.href.
 */
function extractTargetUrl() {
  const fullHref = window.location.href;
  const marker = '/checking.html?url=';
  const idx = fullHref.indexOf(marker);
  if (idx !== -1) {
    const raw = fullHref.slice(idx + marker.length);
    try {
      // Decode if percentage encoded, but fall back gracefully
      return decodeURI(raw);
    } catch {
      return raw;
    }
  }
  try {
    const parsed = new URL(fullHref);
    return parsed.searchParams.get('url') || '';
  } catch {
    return '';
  }
}

/**
 * Validates whether the URL string is an HTTP or HTTPS scheme.
 */
function isValidWebUrl(urlString) {
  if (!urlString) return false;
  try {
    const parsed = new URL(urlString);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Switches the active card view state.
 */
function showView(viewElement) {
  viewChecking.classList.add('hide');
  viewPassing.classList.add('hide');
  viewWarning.classList.add('hide');
  viewError.classList.add('hide');

  viewElement.classList.remove('hide');
}

/**
 * Communicates with the background service worker to update tab badge and stored status.
 */
function notifyBackgroundStatus(status, result = null, error = null) {
  chrome.runtime.sendMessage({
    action: 'SET_TAB_STATUS',
    url: targetUrl,
    status,
    result,
    error
  }).catch(() => {});
}

/**
 * Requests the background worker to install a temporary session allow rule for this tab,
 * then navigates to the target URL without being re-intercepted.
 */
async function proceedToDestination() {
  try {
    const response = await chrome.runtime.sendMessage({
      action: 'ALLOW_ONCE',
      url: targetUrl
    });

    if (response && response.success) {
      window.location.replace(targetUrl);
    } else {
      throw new Error('Failed to obtain navigation clearance from background service worker.');
    }
  } catch (err) {
    console.error('Error proceeding to destination:', err);
    alert('Security Notice: Unable to authorize navigation pass-through. Please try again.');
  }
}

/**
 * Navigates back in browser history or closes the tab if no history exists.
 */
function handleGoBack() {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.close();
  }
}

/**
 * Renders the warning view for SUSPICIOUS or PHISHING verdicts.
 * Populates all dynamic text exclusively with textContent.
 */
function renderWarning(data) {
  showView(viewWarning);
  notifyBackgroundStatus('completed', data);

  const verdict = data.verdict || 'SUSPICIOUS';
  const score = typeof data.final_score === 'number' ? data.final_score : 0.0;
  const scorePct = (score * 100).toFixed(1) + '%';

  statusChip.textContent = verdict === 'PHISHING' ? 'High Risk Threat' : 'Suspicious Site';

  // Banner
  warningBanner.className = 'warning-banner ' + verdict;
  warningBannerText.textContent = verdict === 'PHISHING'
    ? 'Warning: High-Risk Phishing Threat Detected'
    : 'Warning: Suspicious Website Detected';

  // Badge
  warningBadge.className = 'verdict-badge ' + (verdict === 'PHISHING' ? 'RISK' : 'CHECK');
  warningBadge.textContent = verdict === 'PHISHING' ? 'RISK' : 'CHECK';

  // Score
  warningScore.textContent = scorePct;
  warningScoreFill.style.width = Math.min(100, Math.max(0, score * 100)) + '%';
  warningScoreFill.style.backgroundColor = verdict === 'PHISHING' ? 'var(--danger-red)' : 'var(--amber-warning)';

  // Summary reason
  warningSummaryReason.textContent = data.reason || 'Model score and rule adjustments exceed security threshold.';

  // Build plain-text explanations safely
  while (warningReasonsList.firstChild) {
    warningReasonsList.removeChild(warningReasonsList.firstChild);
  }

  const items = [];

  // Threat Intel listings
  if (data.osint && Array.isArray(data.osint.threat_intel)) {
    data.osint.threat_intel.forEach((t) => {
      if (t.status === 'listed') {
        items.push({
          tag: 'THREAT',
          type: 'up',
          text: `Listed by ${t.source}: ${t.detail || 'Verified threat feed entry'}`
        });
      }
    });
  }

  // Rule signals
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

  // Model explanation features
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
    items.slice(0, 5).forEach((item) => {
      const li = document.createElement('li');
      li.className = 'reason-item';

      const tagSpan = document.createElement('span');
      tagSpan.className = `reason-badge ${item.type}`;
      tagSpan.textContent = item.tag;

      const textSpan = document.createElement('span');
      textSpan.className = 'reason-text';
      textSpan.textContent = item.text;

      li.appendChild(tagSpan);
      li.appendChild(textSpan);
      warningReasonsList.appendChild(li);
    });
  } else {
    const li = document.createElement('li');
    li.className = 'reason-item';
    const textSpan = document.createElement('span');
    textSpan.className = 'reason-text';
    textSpan.textContent = 'Adverse indicators exceeded heuristic risk baseline.';
    li.appendChild(textSpan);
    warningReasonsList.appendChild(li);
  }

  footerMeta.textContent = `Registered Domain: ${data.registered_domain || data.host || '-'} &middot; Model: ${data.model_used || data.model_name || '-'}`;
}

/**
 * Renders the error / API offline state. Never assumes safe.
 */
function renderError(message) {
  showView(viewError);
  notifyBackgroundStatus('error', null, message);
  statusChip.textContent = 'Verification Error';
  errorDescription.textContent = message || 'Could not connect to the local PhishGuard API at http://127.0.0.1:5000. Verify the server is running.';
}

/**
 * Initiates the pre-visit verification scan via the local PhishGuard Flask API.
 */
async function runPreVisitCheck() {
  targetUrl = extractTargetUrl();

  // Validate URL scheme
  if (!isValidWebUrl(targetUrl)) {
    targetUrlDisplay.textContent = targetUrl || 'Invalid URL';
    renderError('This page cannot be verified. Only HTTP and HTTPS navigations can be evaluated.');
    return;
  }

  // Display target URL securely
  targetUrlDisplay.textContent = targetUrl;
  showView(viewChecking);
  statusChip.textContent = 'Analyzing Site...';
  notifyBackgroundStatus('checking');

  try {
    const controller = new AbortController();
    const timeoutTimer = setTimeout(() => controller.abort(), CONFIG.CHECK_TIMEOUT_MS);

    const response = await fetch(`${CONFIG.API_BASE_URL}${CONFIG.ENDPOINTS.PREDICT}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        url: targetUrl,
        live: CONFIG.LIVE_CHECKS
      }),
      signal: controller.signal
    });

    clearTimeout(timeoutTimer);

    if (!response.ok) {
      let errText = `API error (HTTP ${response.status})`;
      try {
        const errJson = await response.json();
        if (errJson && errJson.error) {
          errText = errJson.error;
        }
      } catch {}
      throw new Error(errText);
    }

    const data = await response.json();
    if (!data || typeof data.verdict !== 'string') {
      throw new Error('Invalid response structure received from PhishGuard API.');
    }

    // Evaluate verdict
    if (data.verdict === 'LEGITIMATE') {
      showView(viewPassing);
      statusChip.textContent = 'Safe Site';
      notifyBackgroundStatus('completed', data);
      // Automatically continue to destination
      await proceedToDestination();
    } else {
      // SUSPICIOUS or PHISHING: Halt and present warning screen
      renderWarning(data);
    }
  } catch (err) {
    console.warn('PhishGuard pre-visit check failed:', err);
    if (err.name === 'AbortError') {
      renderError('Verification timed out after ' + (CONFIG.CHECK_TIMEOUT_MS / 1000) + ' seconds. The target domain or PhishGuard API took too long to respond.');
    } else {
      renderError('Could not connect to the local PhishGuard API at ' + CONFIG.API_BASE_URL + ' (' + (err.message || 'connection failed') + ').');
    }
  }
}

// Event Listeners for Warning Screen Buttons
btnWarningBack.addEventListener('click', handleGoBack);

btnWarningProceedPrompt.addEventListener('click', () => {
  confirmProceedPanel.classList.remove('hide');
  btnWarningProceedPrompt.classList.add('hide');
});

btnConfirmProceed.addEventListener('click', () => {
  proceedToDestination();
});

btnCancelProceed.addEventListener('click', () => {
  confirmProceedPanel.classList.add('hide');
  btnWarningProceedPrompt.classList.remove('hide');
});

// Event Listeners for Error Screen Buttons
btnErrorBack.addEventListener('click', handleGoBack);

btnErrorRetry.addEventListener('click', () => {
  runPreVisitCheck();
});

btnErrorProceedPrompt.addEventListener('click', () => {
  confirmErrorProceedPanel.classList.remove('hide');
  btnErrorProceedPrompt.classList.add('hide');
});

btnConfirmErrorProceed.addEventListener('click', () => {
  proceedToDestination();
});

btnCancelErrorProceed.addEventListener('click', () => {
  confirmErrorProceedPanel.classList.add('hide');
  btnErrorProceedPrompt.classList.remove('hide');
});

// Start pre-visit verification when page loads
document.addEventListener('DOMContentLoaded', runPreVisitCheck);

