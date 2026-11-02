/** Render untrusted scan evidence as text only, never live HTML. */
export function renderEvidence(container, data) {
  container.replaceChildren();
  const add = (parent, tag, text, className = '') => {
    const el = document.createElement(tag);
    el.textContent = text;
    el.className = className;
    parent.appendChild(el);
    return el;
  };
  const section = (title) => {
    const details = document.createElement('details');
    add(details, 'summary', title);
    container.appendChild(details);
    return details;
  };
  const context = section('URL and transport');
  add(context, 'p', `Submitted: ${data.url}\nInspected address: ${data.effective_url || data.url}`);
  add(context, 'p', data.url_context?.note || 'Live evidence may differ between URL variants.');
  if (data.url_context?.transport === 'http') add(context, 'p', 'Unencrypted HTTP: avoid entering sensitive information.', 'bad');
  if (data.url_context?.fallback_used) {
    add(context, 'p', 'The submitted address could not connect. An HTTPS alternative was inspected; this was recovery, not an observed redirect.');
    for (const attempt of data.url_context.fetch_attempts || []) add(context, 'p', `${attempt.url}: ${attempt.status} ${attempt.reason || attempt.http_status || ''}`);
  }
  if (data.url_context?.journey?.length) {
    const path = section('URL inspection path');
    path.open = true;
    const list = document.createElement('ol');
    path.appendChild(list);
    for (const step of data.url_context.journey) add(list, 'li', `${step.detail}
${step.from ? step.from + ' → ' : ''}${step.url}`);
  }
  if (data.osint?.threat_intel?.length) {
    const feeds = section('Threat intelligence');
    for (const provider of data.osint.threat_intel) {
      add(feeds, 'h4', `${provider.source}: ${provider.status}`);
      add(feeds, 'p', provider.detail);
      for (const check of provider.checks || []) add(feeds, 'p', `${check.url}: ${check.status} — ${check.detail}`);
    }
  }
  const breakdown = data.score_breakdown;
  if (breakdown) {
    const maths = section('How the score adds up');
    add(maths, 'p', 'Rule changes below are sequential percentage points (pp). Model what-if checks are independent and must not be added.');
    breakdown.steps.forEach((s, i) => add(maths, 'p', `${s.label}: ${(s.score * 100).toFixed(2)}%${i && i < breakdown.steps.length - 1 ? ` (${s.change_pp >= 0 ? '+' : ''}${s.change_pp.toFixed(2)} pp)` : ''}`));
  }
  const tls = data.osint?.tls;
  const cert = section('TLS certificate');
  if (tls?.status === 'ok') {
    add(cert, 'p', tls.valid ? 'Certificate verification passed' : `Verification failed: ${tls.error || 'Untrusted certificate'}`, tls.valid ? 'good' : 'bad');
    for (const [label, value] of Object.entries({Host: tls.host, Subject: tls.subject, Issuer: tls.issuer_dn || tls.issuer, 'Valid from': tls.not_before, 'Valid until': tls.not_after, 'Days until expiry': tls.expires_in_days, 'Covered hostnames': tls.san?.join(', '), 'Serial number': tls.serial_number, 'SHA-256': tls.sha256, 'TLS version': tls.tls_version})) {
      add(cert, 'p', `${label}: ${value ?? 'Unavailable'}`);
    }
    add(cert, 'p', 'A valid certificate secures the connection; it does not prove the website is trustworthy.');
    if (tls.pem) add(cert, 'pre', tls.pem);
  } else add(cert, 'p', `${tls?.status || 'Not checked'}: ${tls?.detail || 'Enable live checks to inspect certificates.'}`);
  const page = data.page;
  const dom = section(page?.dom_kind || 'Page HTML / rendered DOM');
  add(dom, 'p', `${page?.inspection_method || 'No inspection'}: ${page?.reason || page?.inspection_status || 'No page content captured.'}`);
  if (page) {
    add(dom, 'p', `Final URL: ${page.final_url || data.effective_url}
HTTP redirects: ${page.redirects ?? 0}; non-cosmetic: ${page.model_redirects ?? page.redirects ?? 0}`);
    for (const hop of page.redirect_chain || []) add(dom, 'p', `${hop.from} → ${hop.to}`);
  }
  if (page?.rendering_error) add(dom, 'p', `Browser rendering unavailable: ${page.rendering_error}. Static content is shown when available.`);
  if (page?.render_readiness?.state === 'time_limit') add(dom, 'p', 'Rendering time limit reached; content may still be loading.');
  if (page?.render_readiness?.assets_ready === false) add(dom, 'p', 'Some visual assets did not finish loading before capture.');
  if (page?.previews) {
    add(dom, 'p', page.previews.note);
    for (const [key, label] of [['static_html', 'Static HTML visual preview'], ['rendered_dom', 'Rendered DOM visual preview']]) {
      const value = page.previews[key];
      if (value && /^[A-Za-z0-9+/=]+$/.test(value)) {
        add(dom, 'h4', label);
        if (key === 'static_html') add(dom, 'p', 'HTML before JavaScript. JavaScript-only sites may appear blank here; see the rendered DOM preview.');
        const img = document.createElement('img');
        img.alt = label;
        img.src = 'data:image/jpeg;base64,' + value;
        img.style.width = '100%';
        dom.appendChild(img);
      }
    }
  }
  if (page?.dom !== undefined) {
    add(dom, 'p', `${page.dom_characters} characters${page.dom_truncated ? ' (preview limited to 100,000)' : ''}. Captured source is displayed as inert text.`);
    add(dom, 'pre', page.dom);
  }
  const features = section('Extracted features and guidance');
  add(features, 'p', 'Green: favourable · Red: review · Grey: context dependent. A single feature is not a verdict.');
  for (const [group, values] of Object.entries({host: data.host_features, content: page?.content_features})) {
    if (!values) continue;
    add(features, 'h4', `${group} features`);
    for (const [name, value] of Object.entries(values)) {
      const a = data.feature_assessments?.[group]?.[name];
      add(features, 'p', `${name}: ${Math.round(value * 1000) / 1000} — ${a?.detail || 'Context dependent'}`, a?.status || 'neutral');
    }
  }
}
