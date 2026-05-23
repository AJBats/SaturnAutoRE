// keys.js — single-candidate forward-sweep eval UI.

let LAST_CANDIDATE_START = null;
let LAST_CANDIDATE_END = null;
let LAST_NATURAL_START = null;
let LAST_NATURAL_END = null;
let LAST_ATTN_KEY = '';
// Identity key of the candidate's entries + pending_entries.  Changes
// when the user queues / unqueues an alt entry (boundaries stay the
// same, so primChanged wouldn't trip — without this guard the listing
// keeps rendering against stale row data until F5).
let LAST_ENTRIES_KEY = '';

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
    `<span class="evidence-pill ${scCls}" title="static call references found in this binary's reference (physically-possible callers)">`
    + `${e.static_callers} static caller${e.static_callers === 1 ? '' : 's'}</span>`
  );
  // Cross-module callers: same-name bsr/jsr/etc. from sibling modules
  // that share this binary's load address (hot-swap slots).  They're
  // physically impossible at runtime — surfaced but greyed out so the
  // eye sees them without weighting the boundary call.
  if (e.cross_module_callers > 0) {
    parts.push(
      `<span class="evidence-pill cross-module" `
      + `title="same-name references in sibling hot-swap modules — cannot resolve to this binary at runtime">`
      + `${e.cross_module_callers} cross-module</span>`
    );
  }
  parts.push(
    `<span class="evidence-pill ${rhCls}" title="breakpoint hits across all probe runs">`
    + `${e.runtime_hits} runtime hit${e.runtime_hits === 1 ? '' : 's'}</span>`
  );
  return parts.join('');
}

// Midpoint chips are emitted separately so the banner can place them
// LAST — they grow into noise on big absorbed candidates, and putting
// them after yellow_flags + partners lets the banner's scrollbar
// swallow the noise without hiding the higher-signal items.
function midpointsHtml(e) {
  if (!e || !e.midpoints || !e.midpoints.length) return '';
  return e.midpoints.map(mp => {
    const mpSc = mp.static_callers;
    const mpRh = mp.runtime_hits;
    const mpCm = mp.cross_module_callers || 0;
    const supported = (mpSc > 0 || mpRh > 0);
    const cmTail = mpCm > 0 ? `, ${mpCm} cross-module` : '';
    return `<span class="midpoint-warning ${supported ? 'supported' : 'suspect'}" `
      + `title="reference proposes FUN_${mp.addr_hex} as a separate function inside our proposed range">`
      + `reference midpoint @ FUN_${mp.addr_hex} `
      + `(${mpSc} static, ${mpRh} runtime${cmTail})</span>`;
  }).join('');
}

// ANALYZE MODE banner — reuses the .gap-alert DOM slot but with orange
// styling (.analyze-mode class).  Driven by /state.analyze_mode payload.
function renderAnalyzeBanner(am) {
  const el = document.getElementById('gap-alert');
  if (!el) return;
  if (!am) return;  // caller handles non-analyze-mode case
  el.classList.remove('hidden');
  el.classList.add('analyze-mode');
  const blocks = am.blocks_summary || [];
  const active = am.active_block || 0;
  const items = blocks.map((b, i) => `
    <li class="${i === active ? 'active' : ''}">
      Block ${i + 1} of ${blocks.length}:
      <code>0x${b.start_hex} - 0x${b.end_hex}</code>
      <span class="gap-size">(${b.size} bytes)</span>
      ${i === active ? ' &larr; viewing' : ''}
    </li>
  `).join('');
  const label = am.label ? ` &mdash; ${escapeHtml(am.label)}` : '';
  el.innerHTML = `
    <div class="gap-alert-title">
      ANALYZE MODE${label}
    </div>
    <ul class="analyze-block-list">${items}</ul>
  `;
}

function renderGapAlert(gaps) {
  const el = document.getElementById('gap-alert');
  if (!el) return;
  // Clear analyze-mode styling whenever we touch this element via the
  // gap-alert renderer (analyze_mode is rendered via a sibling helper).
  el.classList.remove('analyze-mode');
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
  const btn = document.getElementById('btn-frontier');
  if (btn) {
    const on = !!s.frontier_simulation;
    btn.textContent = on ? 'FRONTIER: ON' : 'FRONTIER: OFF';
    btn.classList.toggle('active', on);
  }
}

// Per-pane banner: full candidate metadata for one side of the diff.
// `paneLabel` is "AI OVERRIDE" or "ORACLE NATURAL" (or empty when no
// override is active and only the primary pane is shown).
function renderPartnerButtons(candidate) {
  const el = document.getElementById('partner-buttons');
  if (!el) return;
  if (!candidate) {
    el.innerHTML = '';
    return;
  }
  const suggestions = candidate.suggested_partners || [];
  // Already-confirmed partners shouldn't re-render as suggestion buttons.
  const confirmed = new Set((candidate.partners || []).map(p => p.addr));
  // Queued partners get a "pressed" visual state — second click cancels.
  const queued = new Set((candidate.pending_partners || []).map(p => p.addr));
  const buttons = suggestions
    .filter(s => !confirmed.has(s.addr))
    .map(s => {
      const isQueued = queued.has(s.addr);
      const klass = isQueued ? 'partner-btn pressed' : 'partner-btn';
      const tip = s.reason ? ` title="${escapeHtml(s.reason)}"` : '';
      return `<button class="${klass}" data-partner="${s.addr}"${tip}>+ Partner FUN_${s.addr_hex}</button>`;
    })
    .join('');
  el.innerHTML = buttons;
}

function partnersHtml(candidate) {
  const parts = [];
  if (candidate.partners && candidate.partners.length) {
    const names = candidate.partners.map(p => `FUN_${p.addr_hex}`).join(', ');
    const balanced = candidate.partner_balanced;
    const klass = balanced ? 'partners balanced' : 'partners';
    const tick = balanced ? '✓ ' : '';
    const suffix = balanced ? ' (frame balanced)' : '';
    parts.push(`<span class="${klass}">${tick}Partner of ${escapeHtml(names)}${suffix}</span>`);
  }
  if (candidate.pending_partners && candidate.pending_partners.length) {
    const names = candidate.pending_partners.map(p => `FUN_${p.addr_hex}`).join(', ');
    parts.push(`<span class="partners pending">Queued partner: ${escapeHtml(names)}</span>`);
  }
  return parts.join('');
}

function entriesHtml(candidate) {
  const parts = [];
  if (candidate.entries && candidate.entries.length) {
    const names = candidate.entries.map(e => `FUN_${e.addr_hex}`).join(', ');
    parts.push(`<span class="entries">Alt entries: ${escapeHtml(names)}</span>`);
  }
  if (candidate.pending_entries && candidate.pending_entries.length) {
    const names = candidate.pending_entries.map(e => `FUN_${e.addr_hex}`).join(', ');
    parts.push(`<span class="entries pending">Queued entry: ${escapeHtml(names)}</span>`);
  }
  return parts.join('');
}

function renderCandidateBanner(target, candidate, prev, paneLabel) {
  if (!candidate) {
    target.innerHTML = '';
    return;
  }
  const c = candidate;
  const flagTooltips = c.flag_tooltips || {};
  const flagSpan = (f, extraClass) => {
    const tip = flagTooltips[f];
    const titleAttr = tip ? ` title="${escapeHtml(tip)}"` : '';
    return `<span class="flag${extraClass ? ' ' + extraClass : ''}"${titleAttr}>${escapeHtml(f)}</span>`;
  };
  const greenFlagsHtml = (c.green_flags && c.green_flags.length)
    ? `<span class="flags">${c.green_flags.map(f => flagSpan(f, 'flag-green')).join('')}</span>`
    : '';
  const flagsHtml = (c.yellow_flags && c.yellow_flags.length)
    ? `<span class="flags">${c.yellow_flags.map(f => flagSpan(f)).join('')}</span>`
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
    ${partnersHtml(c)}
    ${entriesHtml(c)}
    ${greenFlagsHtml}
    ${flagsHtml}
    ${midpointsHtml(c.evidence)}
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
// `midpointSet` is a Set of addresses where reference declares a function
// start INSIDE this pane's candidate range — those rows get a violet
// highlight so the human can spot at a glance where reference would
// have split the function.  AI attn takes priority when both fire on
// the same row.
// `refEndSet` is a Set of addresses where reference would have ENDED
// the function (in practice we store reference's NEXT-function start,
// which is row-aligned).  Red highlight + "ref: next FUN" tag — same
// red palette as the `reference: disagrees` banner pill so the two
// cues are visually linked.
function renderListing(lines, target, isPrimary, attnSet, midpointSet, refEndSet, showUnpinAll, showUnpinEnd) {
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
    const isAttn   = !!(attnSet && line.addr != null && attnSet.has(line.addr));
    const isMid    = !isAttn && !!(midpointSet && line.addr != null && midpointSet.has(line.addr));
    const isRefEnd = !isAttn && !isMid && !!(refEndSet && line.addr != null && refEndSet.has(line.addr));
    let cls = (line.classes || []).join(' ');
    if (isAttn)   cls += ' attn';
    if (isMid)    cls += ' midpoint';
    if (isRefEnd) cls += ' ref-end';
    if (line.kind === 'section') {
      // On the primary pane, surface [ unpin ] buttons on the PROPOSED
      // (section-current) and TRAILING headers when an ai_override is
      // active — with DIFFERENT semantics:
      //   - PROPOSED header [unpin]: clears the whole override
      //     (start, end, attn — start over from scratch).
      //   - TRAILING header [unpin]: clears only candidate_end (keeps
      //     any pinned start; falls back to oracle's natural end).
      // Use a data attribute so the click handler knows which to call.
      const isTrailing = cls.indexOf('section-trailing-header') !== -1;
      const isCurrent  = cls.indexOf('section-current-header')  !== -1;
      let unpinBtn = '';
      // Each button only renders when it has something to clear.
      // showUnpinAll = "any pin exists" (start OR end).
      // showUnpinEnd = "an end pin specifically exists".
      // Without this gating, both buttons would show whenever override
      // is active, even when one of them would be a no-op.
      if (showUnpinAll && isCurrent) {
        unpinBtn = `<button class="unpin-btn" data-unpin-scope="all" title="clear the entire ai_override (start, end, attn) — start over from scratch">[ unpin ]</button>`;
      } else if (showUnpinEnd && isTrailing) {
        unpinBtn = `<button class="unpin-btn" data-unpin-scope="end" title="clear only the pinned end — falls back to oracle's natural end">[ unpin ]</button>`;
      }
      return `<span class="line ${cls}">${unpinBtn}${escapeHtml(line.label || '')}</span>`;
    }
    const indent = (line.indent || 0);
    const indentSpan = indent > 0
      ? `<span class="indent" style="width:${indent * 1.4}em"></span>`
      : '';
    // Address column: when the row is attn/midpoint-flagged, split the
    // addr_str so the last 4 hex chars get their own span (.attn-tail
    // / .midpoint-tail) for the bold-colored treatment.
    const addrStr = line.addr_str || '';
    let addrHtml;
    if (isAttn && addrStr.length >= 4) {
      const head = addrStr.slice(0, -4);
      const tail = addrStr.slice(-4);
      addrHtml = escapeHtml(head) + `<span class="attn-tail">${escapeHtml(tail)}</span>`;
    } else if (isMid && addrStr.length >= 4) {
      const head = addrStr.slice(0, -4);
      const tail = addrStr.slice(-4);
      addrHtml = escapeHtml(head) + `<span class="midpoint-tail">${escapeHtml(tail)}</span>`;
    } else if (isRefEnd && addrStr.length >= 4) {
      const head = addrStr.slice(0, -4);
      const tail = addrStr.slice(-4);
      addrHtml = escapeHtml(head) + `<span class="ref-end-tail">${escapeHtml(tail)}</span>`;
    } else {
      addrHtml = escapeHtml(addrStr);
    }
    if (line.kind === 'label') {
      // Label rows have zero bytes themselves — they're anchor markers
      // above an instruction at the same address.  Clicking `+` on a
      // label still means "this address is where the next function
      // starts," which is exclusive (data-bytes-len=0 → next_start =
      // addr → end at addr - 1).  Distinct from clicking `+` on an
      // instruction row, which is inclusive (includes through that
      // row's last byte).
      const labelPinPart = line.addr
        ? `<span class="pin-zone" title="treat this label's address as the next function's start; pin end at addr - 1">+</span>`
        : `<span class="pin-zone"></span>`;
      // "Called from" label rows ship a structured `callers` list so we
      // can color each FUN_<addr> span by kind (stamped / partner /
      // analyze block).  Fall back to plain text for any other label.
      const lblHtml = line.callers && line.callers.length
        ? calledFromHtml(line.callers)
        : escapeHtml(line.label);
      return `<span class="line ${cls}" data-addr="${line.addr || ''}" data-bytes-len="0">${labelPinPart}<span class="margin"> </span>${indentSpan}<span class="lbl">${lblHtml}</span></span>`;
    }
    const margin = line.margin || ' ';
    const labelPart = line.label
      ? `<span class="lbl">${escapeHtml(line.label)}</span> `
      : '';
    // Compose tag column: existing line.tag (from server) + optional
    // "ref: next FUN" suffix when this row is where reference would
    // have started the next function (= where our function would have
    // ended in reference's view).
    let tagText = line.tag || '';
    if (isRefEnd) tagText = tagText ? `${tagText}  ref: next FUN` : 'ref: next FUN';
    const tagClasses = ['tag'];
    if (isRefEnd) tagClasses.push('tag-ref-end');
    if (line.stop_confidence) tagClasses.push(`tag-stop-${line.stop_confidence.toLowerCase()}`);
    const tooltipAttr = line.tag_tooltip
      ? ` title="${escapeHtml(line.tag_tooltip)}"`
      : '';
    const tagPart = tagText
      ? `<span class="${tagClasses.join(' ')}"${tooltipAttr}>${escapeHtml(tagText)}</span>`
      : '';
    if (isPrimary && line.branch) {
      CURRENT_BRANCHES.push({
        src: line.addr,
        target: line.branch.target,
        type: line.branch.type,
        direction: line.branch.direction,
      });
    }
    // Pin-zone: small `+` in the leftmost margin on row hover.
    //
    // Inclusive semantics: clicking `+` on a row means "include THIS
    // row in the function" — so the candidate end pins at the LAST
    // BYTE of this row (= addr + bytes_len - 1).  Reads naturally
    // top-to-bottom: the user reaches a line they want included,
    // clicks `+`, function extends through that line.
    //
    // Byte length comes from the line's `bytes` field ("00 09" → 2,
    // "01 02 03 04" → 4).  Stashed in data-bytes-len for the click
    // handler.
    const bytesLen = (line.bytes || '').trim().split(/\s+/).filter(Boolean).length;
    const pinPart = line.addr
      ? `<span class="pin-zone" title="include this row in the function; pin end at the last byte of this row">+</span>`
      : `<span class="pin-zone"></span>`;
    // Stack push (@-r15) / pop (@r15+) get a soft highlight so the eye
    // can scan stack manipulations vertically.  Substring replace on the
    // already-escaped mnem is safe — neither `@-r15` nor `@r15+` contain
    // chars that escapeHtml mangles.
    const mnemHtml = escapeHtml(line.mnem || '')
      .replaceAll('@-r15', '<span class="stack-op">@-r15</span>')
      .replaceAll('@r15+', '<span class="stack-op">@r15+</span>');
    return `<span class="line ${cls}" data-addr="${line.addr || ''}" data-bytes-len="${bytesLen}" data-indent="${indent}">${pinPart}<span class="margin">${escapeHtml(margin)}</span><span class="a">${addrHtml}</span><span class="b">${escapeHtml(line.bytes || '')}</span>${indentSpan}${labelPart}<span class="m">${mnemHtml}</span>${tagPart}</span>`;
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
    if (s.analyze_mode) {
      renderAnalyzeBanner(s.analyze_mode);
    } else {
      renderGapAlert(s.internal_gaps);
    }
    // Swap footer button rows based on mode.
    document.getElementById('verdict-row').classList.toggle('hidden', !!s.analyze_mode);
    document.getElementById('analyze-row').classList.toggle('hidden', !s.analyze_mode);
    if (s.analyze_mode) {
      const am = s.analyze_mode;
      const cur = am.blocks_summary[am.active_block];
      document.getElementById('analyze-status').textContent =
        `block ${am.active_block + 1} of ${am.block_count} — 0x${cur.start_hex} → 0x${cur.end_hex}`;
    }
    // Render "+ Partner FUN_X" buttons in the verdict row, one per
    // suggestion.  Pressed state reflects whether the addr is already
    // queued (so a second click acts as toggle/cancel).
    renderPartnerButtons(s.candidate);

    const primaryListing = document.getElementById('listing');
    const primaryBanner  = document.getElementById('banner-primary');
    const naturalPane    = document.getElementById('pane-natural');
    const naturalListing = document.getElementById('listing-natural');
    const naturalBanner  = document.getElementById('banner-natural');

    if (s.all_caught_up) {
      primaryListing.innerHTML = '';
      primaryBanner.innerHTML = '';
      naturalPane.classList.add('hidden');
      naturalBanner.classList.add('hidden');
      document.getElementById('btn-reject').classList.remove('pressed');
      document.getElementById('btn-unsure').classList.remove('pressed');
      setStatus(`history: ${s.history_count}`);
      LAST_CANDIDATE_START = null;
      LAST_CANDIDATE_END = null;
      LAST_NATURAL_START = null;
      LAST_NATURAL_END = null;
      LAST_ENTRIES_KEY = '';
      return;
    }

    const overrideActive = !!s.override_active && !!s.natural_view;
    const primStart = s.candidate.start;
    const primEnd   = s.candidate.end;
    const natStart  = overrideActive ? s.natural_view.candidate.start : null;
    const natEnd    = overrideActive ? s.natural_view.candidate.end   : null;
    // Re-render whenever EITHER boundary changes on either pane.  An
    // end-only pin update (start stays the same) would otherwise not
    // trigger a re-render — banner refreshes unconditionally but the
    // listing rows would render against the stale boundary.
    const primChanged = (primStart !== LAST_CANDIDATE_START) || (primEnd !== LAST_CANDIDATE_END);
    const natChanged  = (natStart  !== LAST_NATURAL_START)   || (natEnd  !== LAST_NATURAL_END);

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
    // Detect entries-set churn (confirmed OR queued).  Boundary-only
    // change detection misses /queue-entry and /remove-entry because
    // they keep start/end identical, so we'd serve stale listing rows.
    const confirmedAddrs = (s.candidate.entries || []).map(e => e.addr);
    const pendingAddrs   = (s.candidate.pending_entries || []).map(e => e.addr);
    const entriesKey = [...confirmedAddrs, '|', ...pendingAddrs].sort().join(',');
    const entriesChanged = (entriesKey !== LAST_ENTRIES_KEY);
    LAST_ENTRIES_KEY = entriesKey;
    // Per-pane midpoint sets — reference's view of where function starts
    // fall INSIDE each pane's candidate range.  Each pane uses its own
    // range so the natural pane (often wider) can highlight midpoints
    // the override pane doesn't surface.
    const primMidSet = new Set(((s.candidate.evidence && s.candidate.evidence.midpoints) || []).map(m => m.addr));
    const natMidSet  = overrideActive
      ? new Set(((s.natural_view.candidate.evidence && s.natural_view.candidate.evidence.midpoints) || []).map(m => m.addr))
      : primMidSet;
    // Per-pane reference-boundary marker — address where reference's
    // NEXT function begins.  Using reference_next (not implied_end)
    // because reference_next is always row-aligned (it's a real
    // `FUN_<addr>:` label start).  The highlighted row visually
    // answers "where would reference have ended my function?" — the
    // row is where reference's NEXT function starts, so everything
    // immediately above is what reference considers part of our
    // function.
    function refEndSet(c) {
      const ref = c && c.reference;
      const a = ref && ref.reference_next;
      return new Set(a != null ? [a] : []);
    }
    const primRefEndSet = refEndSet(s.candidate);
    const natRefEndSet  = overrideActive ? refEndSet(s.natural_view.candidate) : primRefEndSet;
    if (primChanged || natChanged || attnChanged || entriesChanged) {
      if (overrideActive) {
        // Diff-align so rows for the same VRAM anchor address sit at the
        // same Y position across panes.  When a side has a header /
        // label / instruction the other lacks at that address, a blank
        // row goes on the missing side.  Works whether the override
        // tightens OR expands scope.
        const aligned = alignLines(s.lines, s.natural_view.lines);
        // showUnpinAll = any pin exists on the override (so the
        // PROPOSED [unpin] button has something to clear).
        // showUnpinEnd = an end pin specifically exists (so the
        // TRAILING [unpin] button has something to clear).
        renderListing(aligned.left,  primaryListing, true,  attnSet, primMidSet, primRefEndSet, overrideActive, !!s.end_pinned);
        renderListing(aligned.right, naturalListing, false, attnSet, natMidSet,  natRefEndSet, false, false);
      } else {
        renderListing(s.lines, primaryListing, true, attnSet, primMidSet, primRefEndSet, overrideActive, !!s.end_pinned);
      }
      requestAnimationFrame(() => {
        // Scroll the current candidate's section header into view, but
        // offset by the sticky-top wrapper's height so the function's
        // first instruction isn't hidden underneath it after an approve
        // advances to a new candidate.  Sticky-top height varies with
        // gap-alert visibility and banner content, so query it live.
        const target = primaryListing.querySelector('.section-current-header');
        if (!target) return;
        const stickyTop = document.getElementById('sticky-top');
        const stickyHeight = stickyTop ? stickyTop.offsetHeight : 0;
        const targetRect = target.getBoundingClientRect();
        window.scrollBy({ top: targetRect.top - stickyHeight, behavior: 'instant' });
      });
    }

    if (overrideActive) {
      naturalPane.classList.remove('hidden');
      naturalBanner.classList.remove('hidden');
    } else {
      naturalPane.classList.add('hidden');
      naturalBanner.classList.add('hidden');
      naturalBanner.innerHTML = '';
      naturalListing.innerHTML = '';
    }

    LAST_CANDIDATE_START = primStart;
    LAST_CANDIDATE_END   = primEnd;
    LAST_NATURAL_START   = natStart;
    LAST_NATURAL_END     = natEnd;
    setStatus(`history: ${s.history_count}`);

    // Reflect "what verdict did I last press on this candidate" so the
    // human can see at a glance what state they left it in before
    // talking to the AI (no textbox UI — the verdict click IS the
    // record).  Cleared on candidate advance because the new candidate
    // has no prior verdict yet.
    const btnReject = document.getElementById('btn-reject');
    const btnUnsure = document.getElementById('btn-unsure');
    btnReject.classList.toggle('pressed', s.current_verdict === 'rejected');
    btnUnsure.classList.toggle('pressed', s.current_verdict === 'unsure');
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

  // Partner buttons (delegated — re-rendered on every state poll).
  document.getElementById('partner-buttons').addEventListener('click', async (e) => {
    const btn = e.target.closest('.partner-btn');
    if (!btn) return;
    const addr = parseInt(btn.dataset.partner, 10);
    const r = await fetch('/queue-partner', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({partner: '0x' + addr.toString(16).toUpperCase().padStart(8, '0')}),
    });
    const data = await r.json();
    if (!data.ok) {
      setStatus('queue-partner rejected: ' + (data.error || 'unknown'));
      return;
    }
    fetchState();
  });

  // Pin-zone clicks: + button in any line's leftmost margin → POST
  // /pin-end with that row's addr.  Server sets the current
  // candidate's `candidate_end` to addr-1 (= "the next function
  // starts here, so we end at the byte before").
  // Unpin clicks: [ unpin ] button in the primary pane's trailing-zone
  // header → POST /unpin-end to clear the active ai_override entirely.
  // Both handlers delegate from the same listing-wrap listener.
  document.getElementById('listing-wrap').addEventListener('click', async (e) => {
    const unpin = e.target.closest('.unpin-btn');
    if (unpin) {
      // Scope tells us which endpoint to call: "all" clears the whole
      // override (proposed header), "end" clears only candidate_end
      // (trailing header).  Default to "end" for safety if attribute
      // is missing.
      const scope = unpin.dataset.unpinScope || 'end';
      const url = scope === 'all' ? '/unpin-all' : '/unpin-end';
      const r = await fetch(url, {method: 'POST'});
      const data = await r.json();
      if (!data.ok) {
        setStatus(`${url.slice(1)} failed: ` + (data.error || 'unknown'));
        return;
      }
      fetchState();
      return;
    }
    const btn = e.target.closest('.pin-zone');
    if (!btn) return;
    const line = btn.closest('.line[data-addr]');
    if (!line) return;
    const addr = parseInt(line.dataset.addr, 10);
    if (Number.isNaN(addr) || addr <= 0) return;
    const bytesLen = parseInt(line.dataset.bytesLen || '0', 10);
    // Route based on modifier + click position relative to the
    // current candidate:
    //  - Shift held → /queue-entry: toggle this addr as an alt entry
    //    of the current candidate (gold "+ Entry" hover signals this).
    //    Server validates the addr is inside the candidate's range;
    //    out-of-range shift+clicks get rejected with a status message.
    //  - No modifier, above current start → /pin-start.
    //  - No modifier, at or below current start → /pin-end with
    //    INCLUSIVE semantics (next_start = addr + bytes_len).  Label
    //    rows have bytes_len=0 → exclusive (label marks next start).
    let url, body;
    if (e.shiftKey) {
      url = '/queue-entry';
      body = {entry: '0x' + addr.toString(16).toUpperCase().padStart(8, '0')};
    } else if (LAST_CANDIDATE_START != null && addr < LAST_CANDIDATE_START) {
      url = '/pin-start';
      body = {addr: '0x' + addr.toString(16).toUpperCase().padStart(8, '0')};
    } else {
      const nextStart = addr + bytesLen;
      url = '/pin-end';
      body = {next_start: '0x' + nextStart.toString(16).toUpperCase().padStart(8, '0')};
    }
    const r = await fetch(url, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body),
    });
    const data = await r.json();
    if (!data.ok) {
      setStatus(`${url.slice(1)} failed: ` + (data.error || 'unknown'));
      return;
    }
    fetchState();
  });

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
    if (e.key === 'Shift') document.body.classList.add('shift-held');
    if (e.target.tagName === 'TEXTAREA' || e.target.tagName === 'INPUT') return;
    const analyzeRowVisible = !document.getElementById('analyze-row').classList.contains('hidden');
    if (analyzeRowVisible) {
      if (e.key === 'ArrowLeft')  { e.preventDefault(); document.getElementById('btn-analyze-prev').click(); }
      else if (e.key === 'ArrowRight') { e.preventDefault(); document.getElementById('btn-analyze-next').click(); }
      // 1/2/3 stay disabled in analyze mode — server returns 409 anyway.
      return;
    }
    if (e.key === '1') { e.preventDefault(); document.getElementById('btn-approve').click(); }
    else if (e.key === '2') { e.preventDefault(); document.getElementById('btn-reject').click(); }
    else if (e.key === '3') { e.preventDefault(); document.getElementById('btn-unsure').click(); }
  });
  // Shift-held state lets CSS recolor pin-zone hover gold (= queue alt
  // entry semantics) inside the candidate.  Drop on keyup AND window
  // blur — without the blur handler, alt-tabbing away while holding
  // shift leaves the body class stuck on.
  document.addEventListener('keyup', (e) => {
    if (e.key === 'Shift') document.body.classList.remove('shift-held');
  });
  window.addEventListener('blur', () => {
    document.body.classList.remove('shift-held');
  });

  // Analyze-mode button wiring.
  async function analyzeCycle(direction) {
    const r = await fetch('/analyze-mode/cycle', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({direction}),
    });
    const data = await r.json();
    if (!data.ok) {
      setStatus('analyze cycle rejected: ' + (data.error || 'unknown'));
      return;
    }
    fetchState();
  }
  async function analyzeExit() {
    const r = await fetch('/analyze-mode/clear', {method: 'POST'});
    await r.json();
    fetchState();
  }
  document.getElementById('btn-analyze-prev').addEventListener('click', () => analyzeCycle('prev'));
  document.getElementById('btn-analyze-next').addEventListener('click', () => analyzeCycle('next'));
  document.getElementById('btn-analyze-exit').addEventListener('click', analyzeExit);

  document.getElementById('btn-frontier').addEventListener('click', async () => {
    await fetch('/frontier/toggle', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    fetchState();
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

// Render a "Called from" label row from a structured callers list.
// Each caller's FUN_<addr> span gets a kind-specific class so it can be
// colored independently of the "Called from" / ":" / suffix text.
function calledFromHtml(callers) {
  const parts = callers.map(c => {
    const kindClass = `caller-${c.kind || 'stamped'}`;
    const kindTag = c.kind === 'partner' ? ', partner'
                  : c.kind === 'analyze' ? ', analyze block'
                  : '';
    const countStr = c.count > 1 ? `×${c.count}` : '';
    const inside = [countStr, kindTag.replace(/^, /, '')].filter(Boolean).join(', ');
    const suffix = inside ? ` (${inside})` : '';
    return `<span class="caller-name ${kindClass}">FUN_${escapeHtml(c.addr_hex)}</span>${escapeHtml(suffix)}`;
  });
  return `Called from ${parts.join(', ')}:`;
}
