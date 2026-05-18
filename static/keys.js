// keys.js — single-candidate forward-sweep eval UI.

let LAST_CANDIDATE_START = null;
let LAST_NATURAL_START = null;
let LAST_ATTN_KEY = '';

function setStatus(text) {
  document.getElementById('status').textContent = text;
}

function progressHtml(p) {
  if (!p) return '';
  const pct = p.pct.toFixed(2);
  const v = p.verified_bytes.toLocaleString();
  const t = p.total_bytes.toLocaleString();
  // Tiny inline bar — width = pct, RPG-style fill
  return `
    <span class="progress" title="${v} / ${t} bytes of race.bin verified">
      <span class="progress-bar"><span class="progress-fill" style="width:${pct}%"></span></span>
      <span class="progress-pct">${pct}%</span>
      <span class="progress-bytes">${v} / ${t} bytes</span>
    </span>
  `;
}

function referenceHtml(a) {
  if (!a) return '';
  const tip = escapeHtml(a.tooltip || '');
  let label;
  if (a.verdict === 'agrees') {
    const delta = a.end_delta;
    label = delta == null ? 'reference: agrees' : `reference: agrees (${delta >= 0 ? '+' : ''}${delta}b)`;
  } else if (a.verdict === 'disagrees') {
    label = `reference: disagrees (${a.end_delta >= 0 ? '+' : ''}${a.end_delta}b)`;
  } else {
    label = 'reference: silent';
  }
  return `<span class="reference reference-${a.verdict}" title="${tip}">${escapeHtml(label)}</span>`;
}

function evidenceHtml(e) {
  if (!e) return '';
  const parts = [];

  const scCls = e.static_callers > 0 ? 'has' : 'none';
  const rhCls = e.runtime_hits   > 0 ? 'has' : 'none';
  parts.push(
    `<span class="evidence-pill ${scCls}" title="static call references found in reference .s files">`
    + `${e.static_callers} static caller${e.static_callers === 1 ? '' : 's'}</span>`
  );
  parts.push(
    `<span class="evidence-pill ${rhCls}" title="breakpoint hits across all probe runs">`
    + `${e.runtime_hits} runtime hit${e.runtime_hits === 1 ? '' : 's'}</span>`
  );

  for (const mp of e.midpoints || []) {
    const mpSc = mp.static_callers;
    const mpRh = mp.runtime_hits;
    // Loud if reference claims a midpoint but evidence is weak.  Quiet
    // (informational) if both signals back the split.
    const supported = (mpSc > 0 || mpRh > 0);
    parts.push(
      `<span class="midpoint-warning ${supported ? 'supported' : 'suspect'}" `
      + `title="reference proposes FUN_${mp.addr_hex} as a separate function inside our proposed range">`
      + `reference midpoint @ FUN_${mp.addr_hex} `
      + `(${mpSc} static, ${mpRh} runtime)</span>`
    );
  }
  return parts.join('');
}

function renderGapAlert(gaps) {
  const el = document.getElementById('gap-alert');
  if (!el) return;
  if (!gaps || gaps.length === 0) {
    el.classList.add('hidden');
    el.innerHTML = '';
    return;
  }
  const totalBytes = gaps.reduce((n, g) => n + g.size, 0);
  const items = gaps.map(g => `
    <li>
      <code>0x${g.start_hex} -> 0x${g.end_hex}</code>
      <span class="gap-size">(${g.size} bytes)</span>
      after <code>${g.preceding_name}</code>
      <button class="gap-fix-btn" data-start="${g.preceding_start}"
              title="Unstamp ${g.preceding_name} so you can re-review and extend its boundary to swallow the gap">
        review ${g.preceding_name}
      </button>
    </li>
  `).join('');
  el.classList.remove('hidden');
  el.innerHTML = `
    <div class="gap-alert-title">
      &#x26A0; INTERNAL GAP${gaps.length === 1 ? '' : 'S'} DETECTED
      &mdash; ${gaps.length} gap${gaps.length === 1 ? '' : 's'},
      ${totalBytes} byte${totalBytes === 1 ? '' : 's'} uncovered between verified subsegs
    </div>
    <ul class="gap-alert-list">${items}</ul>
  `;
}

// Global header: project-level info only (progress + caught-up message).
// Per-candidate metadata moved to .pane-banner inside each listing pane.
function renderProgress(s) {
  const el = document.getElementById('progress-content');
  if (s.all_caught_up) {
    el.innerHTML = `
      <span class="caught-up">All verified subsegs are caught up. Add a manual anchor in yaml to continue forward-sweep.</span>
      ${progressHtml(s.progress)}
    `;
  } else {
    el.innerHTML = progressHtml(s.progress);
  }
}

// Per-pane banner: full candidate metadata for one side of the diff.
// `paneLabel` is "AI OVERRIDE" or "ORACLE NATURAL" (or empty when no
// override is active and only the primary pane is shown).
function renderCandidateBanner(target, candidate, prev, paneLabel) {
  if (!candidate) {
    target.innerHTML = '';
    return;
  }
  const c = candidate;
  const flagsHtml = (c.yellow_flags && c.yellow_flags.length)
    ? `<span class="flags">${c.yellow_flags.map(f => `<span class="flag">${escapeHtml(f)}</span>`).join('')}</span>`
    : '';
  const label = paneLabel ? `<span class="pane-label">${escapeHtml(paneLabel)}</span>` : '';
  target.innerHTML = `
    ${label}
    <span class="fn-name">${c.name}</span>
    <span class="addr">0x${c.start_hex} → 0x${c.end_hex}</span>
    <span class="size">${c.size} bytes</span>
    <span class="verdict-tag verdict-${c.verdict}">${c.verdict}</span>
    ${referenceHtml(c.reference)}
    ${evidenceHtml(c.evidence)}
    ${prev ? `<span class="prev">after ${prev.name}</span>` : ''}
    ${flagsHtml}
  `;
}

// Cache of branches to draw — refreshed each render.
let CURRENT_BRANCHES = [];

// Diff-style alignment: take two arrays of line objects and return two
// equal-length arrays where rows for the same VRAM anchor address sit at
// the same index.  When one side has a line at an address the other
// doesn't, a `{kind:'blank'}` placeholder gets inserted on the missing
// side.  At the same address, the conventional ordering is
// section-header → label → instruction/pool/raw, so a side missing the
// section-header still aligns its instruction with the other side's
// instruction at the same address.
function alignLines(leftLines, rightLines) {
  const L = leftLines || [];
  const R = rightLines || [];
  const BLANK = { kind: 'blank' };

  function anchor(line) {
    if (!line) return null;
    if (line.kind === 'section') return line.anchor_addr != null ? line.anchor_addr : null;
    if (line.addr != null && line.addr !== 0) return line.addr;
    return null;
  }
  function kindRank(line) {
    if (line.kind === 'section') return 0;
    if (line.kind === 'label')   return 1;
    return 2;  // instr / pool / raw
  }

  const outL = [], outR = [];
  let li = 0, ri = 0;
  while (li < L.length || ri < R.length) {
    const l = li < L.length ? L[li] : null;
    const r = ri < R.length ? R[ri] : null;
    if (l === null) { outL.push(BLANK); outR.push(r); ri++; continue; }
    if (r === null) { outL.push(l); outR.push(BLANK); li++; continue; }
    const la = anchor(l), ra = anchor(r);
    // Lines without anchor addresses (rare — shouldn't happen now that
    // section headers carry anchor_addr) just pass through unaligned.
    if (la == null && ra == null) {
      outL.push(l); outR.push(r); li++; ri++; continue;
    }
    if (la == null) { outL.push(l); outR.push(BLANK); li++; continue; }
    if (ra == null) { outL.push(BLANK); outR.push(r); ri++; continue; }
    if (la === ra) {
      const lk = kindRank(l), rk = kindRank(r);
      if (lk === rk)      { outL.push(l); outR.push(r); li++; ri++; }
      else if (lk < rk)   { outL.push(l); outR.push(BLANK); li++; }
      else                { outL.push(BLANK); outR.push(r); ri++; }
    } else if (la < ra)   { outL.push(l); outR.push(BLANK); li++; }
    else                  { outL.push(BLANK); outR.push(r); ri++; }
  }
  return { left: outL, right: outR };
}

// Render a disassembly listing into the given target element.
// When `isPrimary` is true, also collects branch info into CURRENT_BRANCHES
// for SVG arc drawing.  Natural-pane renders pass isPrimary=false so the
// arcs only ever attach to the primary listing.
// `attnSet` is a Set of addresses the AI wants to draw the human's eye to
// — those rows get an attn highlight (orange box around addr + bold-orange
// last-4-hex tail).
function renderListing(lines, target, isPrimary, attnSet) {
  if (!lines || !lines.length) {
    target.textContent = '';
    if (isPrimary) CURRENT_BRANCHES = [];
    return;
  }
  if (isPrimary) CURRENT_BRANCHES = [];
  const html = lines.map(line => {
    if (line.kind === 'blank') {
      // Diff-alignment placeholder — same row height as a real line,
      // no visible content (color is transparent via CSS).
      return `<span class="line blank">&nbsp;</span>`;
    }
    const isAttn = !!(attnSet && line.addr != null && attnSet.has(line.addr));
    let cls = (line.classes || []).join(' ');
    if (isAttn) cls += ' attn';
    if (line.kind === 'section') {
      return `<span class="line ${cls}">${escapeHtml(line.label || '')}</span>`;
    }
    const indent = (line.indent || 0);
    const indentSpan = indent > 0
      ? `<span class="indent" style="width:${indent * 1.4}em"></span>`
      : '';
    // Address column: when the row is attn-flagged, split the addr_str
    // so the last 4 hex chars get their own span (.attn-tail) for the
    // bold-orange treatment.
    const addrStr = line.addr_str || '';
    let addrHtml;
    if (isAttn && addrStr.length >= 4) {
      const head = addrStr.slice(0, -4);
      const tail = addrStr.slice(-4);
      addrHtml = escapeHtml(head) + `<span class="attn-tail">${escapeHtml(tail)}</span>`;
    } else {
      addrHtml = escapeHtml(addrStr);
    }
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
    if (isPrimary && line.branch) {
      CURRENT_BRANCHES.push({
        src: line.addr,
        target: line.branch.target,
        type: line.branch.type,
        direction: line.branch.direction,
      });
    }
    return `<span class="line ${cls}" data-addr="${line.addr || ''}" data-indent="${indent}"><span class="margin">${escapeHtml(margin)}</span><span class="a">${addrHtml}</span><span class="b">${escapeHtml(line.bytes || '')}</span>${indentSpan}${labelPart}<span class="m">${escapeHtml(line.mnem || '')}</span>${tagPart}</span>`;
  }).join('\n');
  target.innerHTML = html;
  if (isPrimary) {
    // Defer arc drawing until layout settles
    requestAnimationFrame(drawArcs);
  }
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

  // SVG covers the listing area within the primary pane only.
  // (Previously used `wrap.clientWidth` which after the split-pane
  // refactor spans BOTH panes — that would make the SVG's internal
  // coordinate system twice as wide as its display, halving every X
  // coord visually.  Use the SVG's actual parent `.listing-area` width.)
  const area = listing.parentElement;
  const svgW = area.clientWidth;
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

async function fetchState() {
  try {
    const r = await fetch('/state');
    const s = await r.json();

    renderProgress(s);
    renderGapAlert(s.internal_gaps);

    const primaryListing = document.getElementById('listing');
    const primaryBanner  = document.getElementById('banner-primary');
    const naturalPane    = document.getElementById('pane-natural');
    const naturalListing = document.getElementById('listing-natural');
    const naturalBanner  = document.getElementById('banner-natural');

    if (s.all_caught_up) {
      primaryListing.innerHTML = '';
      primaryBanner.innerHTML = '';
      naturalPane.classList.add('hidden');
      setStatus(`history: ${s.history_count}`);
      LAST_CANDIDATE_START = null;
      LAST_NATURAL_START = null;
      return;
    }

    const overrideActive = !!s.override_active && !!s.natural_view;
    const primStart = s.candidate.start;
    const natStart  = overrideActive ? s.natural_view.candidate.start : null;
    const primChanged = (primStart !== LAST_CANDIDATE_START);
    const natChanged  = (natStart  !== LAST_NATURAL_START);

    // Banners are cheap to rebuild — refresh every poll so banner pills
    // stay current even when listings haven't been re-rendered.
    renderCandidateBanner(primaryBanner, s.candidate, s.previous,
                          overrideActive ? 'AI OVERRIDE' : '');
    if (overrideActive) {
      renderCandidateBanner(naturalBanner, s.natural_view.candidate,
                            s.natural_view.previous, 'ORACLE NATURAL');
    }

    // Listings: only re-render when primary or natural candidate changed,
    // OR when the attn list changed (re-rendering destroys + redraws
    // SVG arcs so we avoid it on every poll).
    const attnSet = new Set(s.attn || []);
    const attnKey = Array.from(attnSet).sort().join(',');
    const attnChanged = (attnKey !== LAST_ATTN_KEY);
    LAST_ATTN_KEY = attnKey;
    if (primChanged || natChanged || attnChanged) {
      if (overrideActive) {
        // Diff-align so rows for the same VRAM anchor address sit at the
        // same Y position across panes.  When a side has a header /
        // label / instruction the other lacks at that address, a blank
        // row goes on the missing side.  Works whether the override
        // tightens OR expands scope.
        const aligned = alignLines(s.lines, s.natural_view.lines);
        renderListing(aligned.left,  primaryListing, true,  attnSet);
        renderListing(aligned.right, naturalListing, false, attnSet);
      } else {
        renderListing(s.lines, primaryListing, true, attnSet);
      }
      requestAnimationFrame(() => {
        const target = primaryListing.querySelector('.section-current-header');
        if (target) target.scrollIntoView({block: 'start', behavior: 'instant'});
      });
    }

    if (overrideActive) {
      naturalPane.classList.remove('hidden');
    } else {
      naturalPane.classList.add('hidden');
      naturalBanner.innerHTML = '';
      naturalListing.innerHTML = '';
    }

    LAST_CANDIDATE_START = primStart;
    LAST_NATURAL_START   = natStart;
    setStatus(`history: ${s.history_count}`);
  } catch (e) {
    setStatus('connection lost — is the server running?');
  }
}

async function submitVerdict(verdict) {
  // Feedback is no longer collected in the UI — the human verbally
  // explains reject/unsure reasoning to the AI, which records it
  // verbatim into the session.json history entry's `feedback` list.
  const r = await fetch('/verdict', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({verdict, feedback: ''}),
  });
  const data = await r.json();
  if (!data.ok) {
    setStatus('verdict rejected: ' + (data.error || 'unknown'));
    return;
  }
  fetchState();
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('btn-approve').addEventListener('click', () => submitVerdict('approved'));
  document.getElementById('btn-reject').addEventListener('click',  () => submitVerdict('rejected'));
  document.getElementById('btn-unsure').addEventListener('click',  () => submitVerdict('unsure'));

  // "review FUN_X" button inside the gap alert → POST /unstamp for the
  // preceding subseg so the human can re-review it with current oracle
  // logic and extend the boundary to swallow the gap.
  document.getElementById('gap-alert').addEventListener('click', async (e) => {
    const btn = e.target.closest('.gap-fix-btn');
    if (!btn) return;
    const start = parseInt(btn.dataset.start, 10);
    if (Number.isNaN(start)) return;
    btn.disabled = true;
    btn.textContent = 'unstamping…';
    const r = await fetch('/unstamp', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({start: `0x${start.toString(16).toUpperCase().padStart(8, '0')}`}),
    });
    const data = await r.json();
    if (!data.ok) {
      btn.disabled = false;
      btn.textContent = 'failed — retry';
      setStatus('unstamp failed: ' + (data.error || 'unknown'));
      return;
    }
    // Next /state poll will re-propose the unstamped function as the
    // current candidate.
    fetchState();
  });

  document.addEventListener('keydown', (e) => {
    if (e.target.tagName === 'TEXTAREA' || e.target.tagName === 'INPUT') return;
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
