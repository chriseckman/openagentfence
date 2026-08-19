/**
 * The firewall-owned, serialisable in-page probe (OAF-CORE-014). It collects
 * *signals only*; classification happens out-of-page. Placeholders
 * `__MAX_NODES__`, `__MAX_TEXT_LENGTH__`, `__MAX_TEXT_BYTES__`,
 * `__MAX_COMMENTS__`, `__MAX_METADATA__`, `__MAX_LINKS__`, `__TIME_BUDGET__`,
 * and `__PROBE_VERSION__` are substituted by `buildProbe` with numeric literals.
 *
 * The probe must run in Chromium/Firefox/WebKit content contexts without
 * framework globals, must not modify the page, and must self-limit on node
 * count, per-field and total text length, and time (INV-16). It contains no
 * `eval` and no `new Function`.
 */
export const PROBE_SCRIPT_TEMPLATE = `(function () {
  var maxNodes = __MAX_NODES__;
  var maxTextLength = __MAX_TEXT_LENGTH__;
  var maxTextBytes = __MAX_TEXT_BYTES__;
  var maxComments = __MAX_COMMENTS__;
  var maxMetadata = __MAX_METADATA__;
  var maxLinks = __MAX_LINKS__;
  var timeBudgetMs = __TIME_BUDGET__;
  var start = Date.now();
  var nodes = [];
  var comments = [];
  var totalTextBytes = 0;
  var truncation = { nodes: false, textBytes: false, comments: false, metadata: false, links: false, time: false };

  var vw = (window.innerWidth || document.documentElement.clientWidth || 0);
  var vh = (window.innerHeight || document.documentElement.clientHeight || 0);

  function budgetText(len) {
    if (len === 0) { return ''; }
    if (totalTextBytes + len > maxTextBytes) {
      truncation.textBytes = true;
      return '';
    }
    totalTextBytes += len;
    return '';
  }

  var roots = document.querySelectorAll('body, body *');
  for (var i = 0; i < roots.length; i++) {
    if (Date.now() - start > timeBudgetMs) { truncation.time = true; break; }
    if (nodes.length >= maxNodes) { truncation.nodes = true; break; }
    var el = roots[i];
    try {
      var cs = window.getComputedStyle(el);
      var rect = el.getBoundingClientRect();
      var attrs = {};
      var attrNames = ['title', 'alt', 'placeholder', 'role', 'aria-label', 'aria-description'];
      for (var a = 0; a < attrNames.length; a++) {
        var v = el.getAttribute(attrNames[a]);
        if (v !== null && v !== '') {
          budgetText(v.length);
          attrs[attrNames[a]] = v.slice(0, maxTextLength);
        }
      }
      if (el.attributes) {
        for (var d = 0; d < el.attributes.length && Object.keys(attrs).length < 20; d++) {
          var at = el.attributes[d];
          if (at && at.name && at.name.indexOf('data-') === 0) {
            budgetText((at.value || '').length);
            attrs[at.name] = (at.value || '').slice(0, maxTextLength);
          }
        }
      }
      var rawText = directText(el);
      budgetText(rawText.length);
      var pseudoBefore = pseudoText(el, '::before');
      var pseudoAfter = pseudoText(el, '::after');
      nodes.push({
        selector: selectorFor(el),
        tagName: el.tagName ? el.tagName.toLowerCase() : '',
        text: rawText.slice(0, maxTextLength),
        display: cs.display || '',
        visibility: cs.visibility || '',
        opacity: parseFloat(cs.opacity || '1'),
        ariaHidden: el.getAttribute('aria-hidden') === 'true',
        hidden: !!el.hidden,
        role: el.getAttribute('role'),
        ariaLabel: el.getAttribute('aria-label'),
        ariaDescription: el.getAttribute('aria-description'),
        attributes: attrs,
        dimensions: rect.width > 0 && rect.height > 0
          ? { x: rect.x, y: rect.y, width: rect.width, height: rect.height }
          : null,
        boundingBox: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
        frameOrigin: (window.location && window.location.origin) || '',
        fontSize: cs.fontSize || null,
        color: cs.color || null,
        backgroundColor: cs.backgroundColor || null,
        position: cs.position || null,
        transform: cs.transform || null,
        clipPath: cs.clipPath || null,
        overflow: cs.overflow || null,
        inViewport: rect.right > 0 && rect.bottom > 0 && rect.left < vw && rect.top < vh,
        pseudoBefore: pseudoBefore,
        pseudoAfter: pseudoAfter
      });
    } catch (e) {
      // Skip unreadable nodes; never throw out of the probe.
    }
  }

  var meta = { title: '', meta: {}, jsonLd: [], noscript: [] };
  meta.title = (document.title || '').slice(0, maxTextLength);
  var metas = document.querySelectorAll('meta');
  for (var m = 0; m < metas.length; m++) {
    if (m >= maxMetadata) { truncation.metadata = true; break; }
    var mt = metas[m];
    var key = mt.getAttribute('name') || mt.getAttribute('property') || mt.getAttribute('http-equiv');
    var content = mt.getAttribute('content');
    if (key && content && !meta.meta[key]) {
      budgetText(content.length);
      meta.meta[key] = content.slice(0, maxTextLength);
    }
  }
  var scripts = document.querySelectorAll('script[type="application/ld+json"]');
  for (var s = 0; s < scripts.length; s++) {
    if (s >= maxMetadata) { truncation.metadata = true; break; }
    budgetText((scripts[s].textContent || '').length);
    meta.jsonLd.push((scripts[s].textContent || '').slice(0, maxTextLength));
  }
  var noscripts = document.querySelectorAll('noscript');
  for (var n = 0; n < noscripts.length; n++) {
    if (n >= maxMetadata) { truncation.metadata = true; break; }
    budgetText((noscripts[n].textContent || '').length);
    meta.noscript.push((noscripts[n].textContent || '').trim().slice(0, maxTextLength));
  }

  var links = [];
  var anchors = document.querySelectorAll('a[href]');
  for (var l = 0; l < anchors.length; l++) {
    if (Date.now() - start > timeBudgetMs) { truncation.time = true; break; }
    if (l >= maxLinks) { truncation.links = true; break; }
    var href = anchors[l].getAttribute('href') || '';
    if (href) {
      budgetText((anchors[l].textContent || '').length);
      links.push({
        text: (anchors[l].textContent || '').trim().slice(0, maxTextLength),
        href: href.slice(0, maxTextLength)
      });
    }
  }

  if (document.createTreeWalker) {
    var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_COMMENT);
    var cnode;
    while ((cnode = walker.nextNode())) {
      if (Date.now() - start > timeBudgetMs) { truncation.time = true; break; }
      if (comments.length >= maxComments) { truncation.comments = true; break; }
      var t = (cnode.nodeValue || '').trim();
      if (t) {
        budgetText(t.length);
        comments.push(t.slice(0, maxTextLength));
      }
    }
  }

  function selectorFor(el) {
    if (el.id) { return '#' + el.id; }
    var tag = el.tagName ? el.tagName.toLowerCase() : '';
    return tag || '*';
  }
  function directText(el) {
    var text = '';
    for (var i = 0; i < el.childNodes.length; i++) {
      var child = el.childNodes[i];
      if (child && child.nodeType === 3) { text += child.nodeValue; }
    }
    return text;
  }
  function pseudoText(el, pseudo) {
    try {
      var content = window.getComputedStyle(el, pseudo).content;
      if (!content || content === 'none' || content === 'normal') { return null; }
      if ((content.charAt(0) === '"' && content.charAt(content.length - 1) === '"') ||
          (content.charAt(0) === "'" && content.charAt(content.length - 1) === "'")) {
        return content.slice(1, -1).slice(0, maxTextLength);
      }
      return content.slice(0, maxTextLength);
    } catch (e) {
      return null;
    }
  }
  return {
    probeVersion: __PROBE_VERSION__,
    truncated: truncation.nodes || truncation.textBytes || truncation.comments || truncation.metadata || truncation.links || truncation.time,
    truncation: truncation,
    nodes: nodes,
    comments: comments,
    metadata: meta,
    links: links
  };
})()`;
