// keys.js — single-candidate forward-sweep eval UI.

let LAST_CANDIDATE_START = null;
let AWAITING_AI = false;

function setStatus(text) {
  document.getElementById('status').textContent = text;
}

function renderHeader(s) {
  const el = document.getElementById('header-content');
  if (s.all_caught_up) {
    el.innerHTML = `<span class="caught-up">All verified subsegs are caught up. Add a manual anchor in yaml to continue forward-sweep.</span>`;
    return;
  }
  const c = s.candidate;
  const p = s.previous;
  const flagsHtml = (c.yellow_flags && c.yellow_flags.length)
    ? `<span class="flags">${c.yellow_flags.map(f => `<span class="flag">${escapeHtml(f)}</span>`).join('')}</span>`
    : '';
  el.innerHTML = `
    <span class="fn-name">${c.name}</span>
    <span class="addr">0x${c.start_hex} → 0x${c.end_hex}</span>
    <span class="size">${c.size} bytes</span>
    <span class="verdict-tag verdict-${c.verdict}">${c.verdict}</span>
    ${p ? `<span class="prev">after ${p.name}</span>` : ''}
    ${flagsHtml}
  `;
}

// Cache of branches to draw — refreshed each render.
let CURRENT_BRANCHES = [];

function renderListing(lines) {
  const el = document.getElementById('listing');
  if (!lines || !lines.length) { el.textContent = ''; CURRENT_BRANCHES = []; return; }
  CURRENT_BRANCHES = [];
  const html = lines.map(line => {
    const cls = (line.classes || []).join(' ');
    if (line.kind === 'section') {
      return `<span class="line ${cls}">${escapeHtml(line.label || '')}</span>`;
    }
    const indent = (line.indent || 0);
    const indentSpan = indent > 0
      ? `<span class="indent" style="width:${indent * 1.4}em"></span>`
      : '';
    if (line.kind === 'label') {
      return `<span class="line ${cls}" data-addr="${line.addr || ''}"><span class="margin"> </span>${indentSpan}<span class="lbl">${escapeHtml(line.label)}</span></span>`;
    }
    const margin = line.margin || ' ';
    const labelPart = line.label
      ? `<span class="lbl">${escapeHtml(line.label)}</span> `
      : '';
    const tagPart = line.tag
      ? `<span class="tag">${escapeHtml(line.tag)}</span>`
      : '';
    if (line.branch) {
      CURRENT_BRANCHES.push({
        src: line.addr,
        target: line.branch.target,
        type: line.branch.type,
        direction: line.branch.direction,
      });
    }
    return `<span class="line ${cls}" data-addr="${line.addr || ''}" data-indent="${indent}"><span class="margin">${escapeHtml(margin)}</span><span class="a">${escapeHtml(line.addr_str || '')}</span><span class="b">${escapeHtml(line.bytes || '')}</span>${indentSpan}${labelPart}<span class="m">${escapeHtml(line.mnem || '')}</span>${tagPart}</span>`;
  }).join('\n');
  el.innerHTML = html;
  // Defer arc drawing until layout settles
  requestAnimationFrame(drawArcs);
}

// Arc state — keeps interaction state across renders
let ARC_LIST = [];          // [{id, src, target, type, direction, srcLineEl, tgtLineEl}]
let STICKY_ARC_ID = null;

function arcsAtAddr(addr) {
  return ARC_LIST.filter(a => a.src === addr || a.target === addr);
}

function setArcClass(arcId, cls, on) {
  document.querySelectorAll(`[data-arc-id="${arcId}"]`).forEach(el => {
    if (on) el.classList.add(cls);
    else el.classList.remove(cls);
  });
}

function hoverArc(arcId, on) {
  setArcClass(arcId, 'hovered', on);
}

function clickArc(arcId) {
  if (STICKY_ARC_ID === arcId) {
    // Toggle off
    setArcClass(arcId, 'sticky', false);
    STICKY_ARC_ID = null;
  } else {
    if (STICKY_ARC_ID !== null) setArcClass(STICKY_ARC_ID, 'sticky', false);
    setArcClass(arcId, 'sticky', true);
    STICKY_ARC_ID = arcId;
  }
}

function drawArcs() {
  const svg = document.getElementById('arcs');
  if (!svg) return;
  const listing = document.getElementById('listing');
  const wrap = document.getElementById('listing-wrap');
  if (!listing || !wrap) return;

  // Two maps:
  //   srcMap: prefer the INSTRUCTION line (has bytes, is the branch source)
  //   tgtMap: prefer the LABEL line (.lbl-only; the target marker)
  const srcMap = new Map();
  const tgtMap = new Map();
  const allLines = listing.querySelectorAll('.line[data-addr]');
  allLines.forEach(el => {
    const addr = parseInt(el.dataset.addr, 10);
    if (Number.isNaN(addr) || addr <= 0) return;
    const hasBytes = !!el.querySelector('.b')?.textContent?.trim();
    const isLabelOnly = !!el.querySelector('.lbl') && !hasBytes;
    if (hasBytes && !srcMap.has(addr)) srcMap.set(addr, el);
    if (isLabelOnly && !tgtMap.has(addr)) tgtMap.set(addr, el);
  });

  const listingRect = listing.getBoundingClientRect();

  // Tick X = left edge of the mnemonic span (.m) or label span (.lbl) — i.e.,
  // the position that respects per-line indentation.
  function tickXOf(lineEl) {
    const txt = lineEl.querySelector('.m') || lineEl.querySelector('.lbl');
    if (!txt) return lineEl.getBoundingClientRect().left - listingRect.left;
    return txt.getBoundingClientRect().left - listingRect.left;
  }

  function midYOf(lineEl) {
    const r = lineEl.getBoundingClientRect();
    return r.top - listingRect.top + r.height / 2;
  }

  // Compute geometry for each branch
  const arcs = [];
  CURRENT_BRANCHES.forEach((br, idx) => {
    const srcEl = srcMap.get(br.src);
    const tgtEl = tgtMap.get(br.target) || srcMap.get(br.target);
    if (!srcEl || !tgtEl) return;
    arcs.push({
      id: idx,
      src: br.src,
      target: br.target,
      type: br.type,
      direction: br.direction,
      srcY: midYOf(srcEl),
      tgtY: midYOf(tgtEl),
      srcTickX: tickXOf(srcEl),
      tgtTickX: tickXOf(tgtEl),
      srcLineEl: srcEl,
      tgtLineEl: tgtEl,
    });
  });

  // Rail assignment (greedy, by y-span)
  arcs.sort((a, b) => Math.min(a.srcY, a.tgtY) - Math.min(b.srcY, b.tgtY));
  const railEnds = [];
  for (const arc of arcs) {
    const start = Math.min(arc.srcY, arc.tgtY);
    const end = Math.max(arc.srcY, arc.tgtY);
    let rail = railEnds.findIndex(e => e < start);
    if (rail === -1) {
      rail = railEnds.length;
      railEnds.push(end);
    } else {
      railEnds[rail] = end;
    }
    arc.rail = rail;
  }

  ARC_LIST = arcs;
  STICKY_ARC_ID = null;

  // SVG covers the listing area; we use real per-line tick X coords.
  const svgW = wrap.clientWidth;
  const svgH = listing.scrollHeight;
  svg.setAttribute('width', svgW);
  svg.setAttribute('height', svgH);
  svg.style.width = '100%';
  svg.style.height = svgH + 'px';

  const RAIL_STEP = 10;
  const MIN_LEFT_MARGIN = 6;   // never let apex go off the visible left edge
  const TICK_INSET = 8;         // pull tick back into the whitespace gap before the text

  const parts = [];
  for (const arc of arcs) {
    const sX = arc.srcTickX - TICK_INSET;
    const tX = arc.tgtTickX - TICK_INSET;
    const sY = arc.srcY;
    const tY = arc.tgtY;
    // Apex sits to the LEFT of both ticks. Multiple rails bow out further.
    const baseApex = Math.min(sX, tX) - 30;
    const apexX = Math.max(MIN_LEFT_MARGIN, baseApex - arc.rail * RAIL_STEP);
    // Cubic bezier curving LEFT through (apexX, sY) and (apexX, tY)
    const d = `M ${sX} ${sY} C ${apexX} ${sY}, ${apexX} ${tY}, ${tX} ${tY}`;
    const cls = `arc arc-${arc.type} arc-${arc.direction}`;
    parts.push(`<path class="${cls}" data-arc-id="${arc.id}" d="${d}" />`);
    // Source dot
    parts.push(`<circle class="arc-dot arc-${arc.type}" data-arc-id="${arc.id}" cx="${sX}" cy="${sY}" r="3" />`);
    // Arrowhead at target — triangle pointing RIGHT into the target line
    parts.push(`<polygon class="arc-head arc-${arc.type}" data-arc-id="${arc.id}" points="${tX},${tY} ${tX-6},${tY-4} ${tX-6},${tY+4}" />`);
  }
  svg.innerHTML = parts.join('');
}

// Event delegation for arc hover/click
function wireArcEvents() {
  const svg = document.getElementById('arcs');
  const listing = document.getElementById('listing');
  if (!svg || !listing) return;

  svg.addEventListener('mouseover', (e) => {
    const id = e.target.dataset && e.target.dataset.arcId;
    if (id != null) hoverArc(parseInt(id, 10), true);
  });
  svg.addEventListener('mouseout', (e) => {
    const id = e.target.dataset && e.target.dataset.arcId;
    if (id != null) hoverArc(parseInt(id, 10), false);
  });
  svg.addEventListener('click', (e) => {
    const id = e.target.dataset && e.target.dataset.arcId;
    if (id != null) clickArc(parseInt(id, 10));
  });

  // Hover/click on listing lines → highlight associated arc(s)
  listing.addEventListener('mouseover', (e) => {
    const lineEl = e.target.closest('.line[data-addr]');
    if (!lineEl) return;
    const addr = parseInt(lineEl.dataset.addr, 10);
    if (Number.isNaN(addr)) return;
    arcsAtAddr(addr).forEach(a => hoverArc(a.id, true));
  });
  listing.addEventListener('mouseout', (e) => {
    const lineEl = e.target.closest('.line[data-addr]');
    if (!lineEl) return;
    const addr = parseInt(lineEl.dataset.addr, 10);
    if (Number.isNaN(addr)) return;
    arcsAtAddr(addr).forEach(a => hoverArc(a.id, false));
  });
  listing.addEventListener('click', (e) => {
    const lineEl = e.target.closest('.line[data-addr]');
    if (!lineEl) return;
    const addr = parseInt(lineEl.dataset.addr, 10);
    if (Number.isNaN(addr)) return;
    const matched = arcsAtAddr(addr);
    if (matched.length > 0) clickArc(matched[0].id);
  });
}

// Redraw arcs on window resize (font size or container changes layout)
let RESIZE_TIMER = null;
window.addEventListener('resize', () => {
  clearTimeout(RESIZE_TIMER);
  RESIZE_TIMER = setTimeout(drawArcs, 80);
});

function showAwaitingBanner(show) {
  const b = document.getElementById('awaiting-banner');
  if (show) b.classList.remove('hidden');
  else b.classList.add('hidden');
}

function getFeedback() {
  return document.getElementById('feedback-text').value.trim();
}

function clearFeedback() {
  document.getElementById('feedback-text').value = '';
}

async function fetchState() {
  try {
    const r = await fetch('/state');
    const s = await r.json();

    renderHeader(s);

    if (s.all_caught_up) {
      document.getElementById('listing').innerHTML = '';
      setStatus(`history: ${s.history_count}`);
      AWAITING_AI = false;
      showAwaitingBanner(false);
      LAST_CANDIDATE_START = null;
      return;
    }

    // If the candidate changed, scroll to the "PROPOSED" header.
    const newStart = s.candidate.start;
    const changed = (newStart !== LAST_CANDIDATE_START);
    if (changed) {
      renderListing(s.lines);
      LAST_CANDIDATE_START = newStart;
      // After listing rerenders, jump to the proposed-section header.
      requestAnimationFrame(() => {
        const target = document.querySelector('.section-current-header');
        if (target) target.scrollIntoView({block: 'start', behavior: 'instant'});
      });
    }

    AWAITING_AI = !!s.awaiting_ai;
    showAwaitingBanner(AWAITING_AI);
    setStatus(`history: ${s.history_count}`);
  } catch (e) {
    setStatus('connection lost — is the server running?');
  }
}

async function submitVerdict(verdict) {
  const feedback = getFeedback();
  const r = await fetch('/verdict', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({verdict, feedback}),
  });
  const data = await r.json();
  if (!data.ok) {
    setStatus('verdict rejected: ' + (data.error || 'unknown'));
    return;
  }
  clearFeedback();
  fetchState();
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('btn-approve').addEventListener('click', () => {
    if (AWAITING_AI) return;
    submitVerdict('approved');
  });
  document.getElementById('btn-reject').addEventListener('click', () => {
    if (AWAITING_AI) return;
    submitVerdict('rejected');
  });
  document.getElementById('btn-unsure').addEventListener('click', () => {
    if (AWAITING_AI) return;
    submitVerdict('unsure');
  });

  document.addEventListener('keydown', (e) => {
    if (e.target.tagName === 'TEXTAREA' || e.target.tagName === 'INPUT') {
      // Inside feedback box — keyboard shortcuts disabled (the user is typing).
      return;
    }
    if (AWAITING_AI) return;
    if (e.key === '1') { e.preventDefault(); document.getElementById('btn-approve').click(); }
    else if (e.key === '2') { e.preventDefault(); document.getElementById('btn-reject').click(); }
    else if (e.key === '3') { e.preventDefault(); document.getElementById('btn-unsure').click(); }
  });

  // Wire arc hover/click delegation once
  wireArcEvents();

  // Initial fetch + poll every 1s.
  fetchState();
  setInterval(fetchState, 1000);
});

function escapeHtml(s) {
  if (s == null) return '';
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}
