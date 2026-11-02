/**
 * PhishGuard Extension - Background Service Worker
 *
 * Pre-visit checking architecture:
 * 1. Declarative Net Request (DNR) dynamically intercepts all top-level main_frame
 *    HTTP and HTTPS navigations before any network connection to the target site is made.
 * 2. Redirects the navigation to an internal extension page: checking.html?url=<targetUrl>.
 * 3. Exempts local API traffic (127.0.0.1 and localhost) from interception.
 * 4. Manages tightly-scoped, short-lived session-level 'allow' rules on a per-tab and
 *    per-URL basis when a site is verified as safe or when the user proceeds anyway.
 * 5. Automatically revokes allow rules upon navigation completion or expiration to guarantee
 *    that repeat visits and subsequent navigations are re-verified.
 */

import { CONFIG } from './config.js';

// Map of active session-scoped allow rules: tabId -> { ruleId, url, timer }
const activeAllowRules = new Map();

/**
 * Initializes Declarative Net Request dynamic rules for main_frame interception.
 */
async function initDNRRules() {
  const extensionId = chrome.runtime.id;
  const redirectTarget = `chrome-extension://${extensionId}/checking.html?url=\\0`;

  const rulesToAdd = [
    // Rule 1: Always allow local Flask API on 127.0.0.1
    {
      id: CONFIG.RULES.ALLOW_LOCAL_IP,
      priority: 3,
      action: { type: 'allow' },
      condition: {
        urlFilter: '||127.0.0.1',
        resourceTypes: ['main_frame', 'xmlhttprequest']
      }
    },
    // Rule 2: Always allow localhost
    {
      id: CONFIG.RULES.ALLOW_LOCALHOST,
      priority: 3,
      action: { type: 'allow' },
      condition: {
        urlFilter: '||localhost',
        resourceTypes: ['main_frame', 'xmlhttprequest']
      }
    },
    // Rule 10: Intercept all other top-level HTTP/HTTPS navigations and redirect to checking page
    {
      id: CONFIG.RULES.REDIRECT_MAIN_FRAME,
      priority: 1,
      action: {
        type: 'redirect',
        redirect: {
          regexSubstitution: redirectTarget
        }
      },
      condition: {
        regexFilter: '^https?://.+',
        resourceTypes: ['main_frame']
      }
    }
  ];

  try {
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const existingIds = existingRules.map((r) => r.id);
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existingIds,
      addRules: rulesToAdd
    });
    console.log('PhishGuard: DNR pre-visit interception rules initialized.');
  } catch (err) {
    console.error('PhishGuard: Failed to initialize DNR dynamic rules', err);
  }
}

/**
 * Updates the extension badge text and background color for a specific tab.
 */
async function setTabBadge(tabId, badgeConfig) {
  if (!tabId || tabId < 0) return;
  try {
    await chrome.action.setBadgeText({ tabId, text: badgeConfig.text });
    if (badgeConfig.color) {
      await chrome.action.setBadgeBackgroundColor({ tabId, color: badgeConfig.color });
    }
  } catch (err) {
    console.debug('Failed to set badge for tab', tabId, err);
  }
}

/**
 * Maps PhishGuard API verdict to the appropriate badge configuration.
 */
function getBadgeForVerdict(verdict) {
  switch (verdict) {
    case 'LEGITIMATE':
      return CONFIG.BADGES.SAFE;
    case 'SUSPICIOUS':
      return CONFIG.BADGES.CHECK;
    case 'PHISHING':
      return CONFIG.BADGES.RISK;
    default:
      return CONFIG.BADGES.ERROR;
  }
}

/**
 * Removes any temporary session allow rule for the specified tab.
 */
async function removeSessionAllowRule(tabId, specificRuleId = null) {
  const active = activeAllowRules.get(tabId);
  const ruleIdToRemove = specificRuleId || (active ? active.ruleId : null);

  if (!ruleIdToRemove) return;

  if (active && active.timer) {
    clearTimeout(active.timer);
  }
  activeAllowRules.delete(tabId);

  try {
    await chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: [ruleIdToRemove]
    });
    console.debug(`PhishGuard: Removed session allow rule ${ruleIdToRemove} for tab ${tabId}`);
  } catch (err) {
    console.debug('Failed to remove session rule', ruleIdToRemove, err);
  }
}

/**
 * Creates a narrow, short-lived session allow rule for a specific tab and URL.
 * Higher priority (2) than the redirect rule (1), allowing the navigation to pass through.
 */
async function allowOnceForTab(tabId, targetUrl) {
  if (!tabId || !targetUrl) return false;

  // Clean the URL (strip fragment anchor)
  const cleanUrl = targetUrl.split('#')[0];
  const ruleId = CONFIG.RULES.SESSION_ALLOW_BASE_ID + (Math.abs(tabId) % 5000);

  // Clear any existing rule for this tab first
  await removeSessionAllowRule(tabId);

  const allowRule = {
    id: ruleId,
    priority: 2,
    action: { type: 'allow' },
    condition: {
      urlFilter: '|' + cleanUrl,
      tabIds: [tabId],
      resourceTypes: ['main_frame']
    }
  };

  try {
    await chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: [ruleId],
      addRules: [allowRule]
    });

    // Auto-expire rule after TTL as a safety backstop
    const timer = setTimeout(() => {
      console.debug(`PhishGuard: Expiring allow rule ${ruleId} for tab ${tabId}`);
      removeSessionAllowRule(tabId, ruleId);
    }, CONFIG.ALLOW_RULE_TTL_MS);

    activeAllowRules.set(tabId, {
      ruleId,
      url: cleanUrl,
      timestamp: Date.now(),
      timer
    });

    console.debug(`PhishGuard: Created scoped allow rule ${ruleId} for tab ${tabId} (${cleanUrl})`);
    return true;
  } catch (err) {
    console.error('PhishGuard: Failed to create session allow rule', err);
    return false;
  }
}

/**
 * Saves tab state into chrome.storage.session.
 */
async function saveTabState(tabId, state) {
  if (!tabId || tabId < 0) return;
  const key = `tab_${tabId}`;
  try {
    await chrome.storage.session.set({ [key]: state });
  } catch (err) {
    console.debug('Failed to save tab state', tabId, err);
  }
}

/**
 * Retrieves tab state from chrome.storage.session.
 */
async function getTabState(tabId) {
  if (!tabId || tabId < 0) return null;
  const key = `tab_${tabId}`;
  try {
    const data = await chrome.storage.session.get(key);
    return data[key] || null;
  } catch {
    return null;
  }
}

// Service worker lifecycle initialization
chrome.runtime.onInstalled.addListener(initDNRRules);
chrome.runtime.onStartup.addListener(initDNRRules);
initDNRRules();

/**
 * Tab Navigation Event Listener:
 * When the destination site finishes loading after being allowed,
 * immediately remove the session-scoped allow rule so future visits are intercepted.
 */
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  const active = activeAllowRules.get(tabId);
  if (active && changeInfo.status === 'complete') {
    // Check if the current URL matches or belongs to the allowed destination
    const currentClean = (tab.url || '').split('#')[0];
    if (currentClean && !currentClean.startsWith('chrome-extension://')) {
      console.debug(`PhishGuard: Navigation complete for ${currentClean}. Revoking temporary allow rule.`);
      await removeSessionAllowRule(tabId);
    }
  }

  // If user navigates away from an extension checking page to another page manually
  if (changeInfo.url && active && !changeInfo.url.startsWith(active.url)) {
    await removeSessionAllowRule(tabId);
  }
});

/**
 * Tab Removed Event Listener:
 * Clean up active allow rules and session storage when tabs close.
 */
chrome.tabs.onRemoved.addListener(async (tabId) => {
  await removeSessionAllowRule(tabId);
  chrome.storage.session.remove(`tab_${tabId}`).catch(() => {});
});

/**
 * Message Listener:
 * Handles ALLOW_ONCE, SET_TAB_STATUS, and GET_TAB_STATUS from checking.html and popup.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.action) return false;

  const tabId = sender.tab ? sender.tab.id : message.tabId;

  if (message.action === 'ALLOW_ONCE') {
    (async () => {
      const ok = await allowOnceForTab(tabId, message.url);
      sendResponse({ success: ok, tabId });
    })();
    return true;
  }

  if (message.action === 'SET_TAB_STATUS') {
    (async () => {
      const { status, result, error, url } = message;
      let badge = CONFIG.BADGES.CHECKING;

      if (status === 'completed' && result) {
        badge = getBadgeForVerdict(result.verdict);
      } else if (status === 'error') {
        badge = CONFIG.BADGES.ERROR;
      } else if (status === 'unsupported') {
        badge = CONFIG.BADGES.UNSUPPORTED;
      }

      await setTabBadge(tabId, badge);
      await saveTabState(tabId, {
        tabId,
        url,
        status,
        result: result || null,
        error: error || null,
        timestamp: Date.now()
      });
      sendResponse({ success: true });
    })();
    return true;
  }

  if (message.action === 'GET_TAB_STATUS') {
    (async () => {
      const state = await getTabState(tabId);
      sendResponse(state);
    })();
    return true;
  }

  return false;
});
