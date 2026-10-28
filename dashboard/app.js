/**
 * WatchTower dashboard: renders the backend's SSE stream (/api/stream) into index.html.
 * Field names follow backend/watchtower/app.py (State.snapshot, normalize, publish).
 */

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────
const API_BASE = '';
// ?demo: a recording layout (agents, events, details only); the director panel stays on D.
const DEMO = new URLSearchParams(location.search).has('demo');
if (DEMO) document.documentElement.classList.add('demo');
const WINDOW_EVENTS = 80;           // same window the backend detectors look at
const MAX_FEED_LINES = 200;
const MAX_GRAPH_RESOURCES = 16;
// Mirrors ai-engine/tools/coordination_score.py so the graph agrees with the detectors.
const WRITE_ACTIONS = new Set(['data_write', 'tool_call']);

const LEVELS = {
  CRITICAL: { cls: 'critical', icon: '✖' },
  HIGH:     { cls: 'serious',  icon: '▲' },
  MEDIUM:   { cls: 'warning',  icon: '▲' },
  LOW:      { cls: 'good',     icon: '●' },
};
const VERDICTS = {
  COORDINATED_THREAT: { cls: 'critical', icon: '✖', label: 'Coordinated threat' },
  SUSPICIOUS:         { cls: 'warning',  icon: '▲', label: 'Suspicious' },
  BENIGN:             { cls: 'good',     icon: '✓', label: 'Benign' },
};
const AGENT_STATUS = {
  active:                  { cls: 'good',     label: 'Active' },
  warning:                 { cls: 'warning',  label: 'Warning' },
  contained:               { cls: 'serious',  label: 'Contained' },
  severed:                 { cls: 'critical', label: 'Severed' },
  quarantined_review_done: { cls: 'warning',  label: 'Reviewed' },
};
// A warned agent is still working; only contained and severed agents have stopped.
const running = (a) => !!a && (a.status === 'active' || a.status === 'warning');
const ALERT_LABELS = { watch: 'Agent warning', revoke: 'Key revoked' };

const GUARD = {
  PASS:  { cls: 'good',     icon: '✓', label: 'PASS' },
  BLOCK: { cls: 'critical', icon: '✖', label: 'BLOCK' },
};
const SIGNAL_NAMES = {
  resource_fan_in: 'Resource fan-in',
  shared_scratchpad: 'Shared scratchpad',
  privilege_escalation: 'Privilege ladder',
};

// ─────────────────────────────────────────────────────────────────────────────
// State (client copy of State.snapshot)
// ─────────────────────────────────────────────────────────────────────────────
const S = {
  agents: new Map(),
  events: [],
  riskHistory: [],
  risk: 0,
  signals: [],
  hotspots: [],
  vcs: [],
  analysis: null,
  analyzing: false,
  incident: null,
  mode: 'live',
  threshold: 80,
  scenarioRunning: false,
  findings: new Map(),  // id -> event summary from the backend
  activity: [],         // plain-language summaries of routine traffic, built here
  selected: null,       // finding id shown in Event details
};
let pendingActivity = [];  // events since the last activity summary
let pickedAt = 0;
let bannerHiddenAt = null;  // when the viewer closed the incident banner; it returns when something newer needs them          // when the viewer last clicked an event; auto-selection waits a while after
let evtSource = null;
let renderedAnalysis;
let seenActions = 0;   // incident.actions already written to the WatchTower feed  // undefined = AI panel body must be redrawn

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
const el = (id) => document.getElementById(id);
// The UI scales with the root font size (see styles.css); SVGs are drawn in unscaled units and stretched by viewBox.
const uiScale = () => parseFloat(getComputedStyle(document.documentElement).fontSize) / 16;

function esc(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function fmtTime(ts) {
  if (!ts) return '--:--:--';
  return new Date(ts).toLocaleTimeString('en-GB', { hour12: false });
}

function riskLevel(score) {
  if (score >= 80) return 'CRITICAL';
  if (score >= 65) return 'HIGH';
  if (score >= 35) return 'MEDIUM';
  return 'LOW';
}

function levelBadge(level, text) {
  const l = LEVELS[level] || LEVELS.LOW;
  return `<span class="badge ${l.cls}">${l.icon} ${esc(text || level)}</span>`;
}

function statusTag(cls, label) {
  return `<span class="status"><span class="dot ${cls}"></span>${esc(label)}</span>`;
}

function sensitiveHotspot(resource) {
  return S.hotspots.some(h => h.resource === resource && h.sensitive && h.writers.length >= 2);
}

async function post(path, body) {
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
    if (!res.ok) {
      // Show the server's own explanation (e.g. "NOTIFY_EMAIL_TO is not set") rather than a bare status.
      const why = await res.json().then(b => b.error).catch(() => null);
      throw new Error(why || `HTTP ${res.status}`);
    }
    return await res.json();
  } catch (err) {
    console.error('[WatchTower]', path, err);
    alert(err.message);
    return null;
  }
}

// Batch renders into one animation frame; events can arrive several per second.
const dirty = new Set();
function schedule(...fns) {
  const first = dirty.size === 0;
  fns.forEach(f => dirty.add(f));
  if (first) requestAnimationFrame(() => {
    const fns = [...dirty];
    dirty.clear();
    fns.forEach(f => f());
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// SSE connection
// ─────────────────────────────────────────────────────────────────────────────
function connect() {
  if (evtSource) evtSource.close();
  setLive('connecting');
  evtSource = new EventSource(`${API_BASE}/api/stream`);
  evtSource.onopen = () => setLive('connected');
  evtSource.onmessage = (e) => {
    try {
      handle(JSON.parse(e.data));
    } catch (err) {
      console.error('[WatchTower] bad message', err);
    }
  };
  // EventSource retries on its own; just reflect the state.
  evtSource.onerror = () => setLive(evtSource.readyState === EventSource.CLOSED ? 'closed' : 'connecting');
}

function setLive(status) {
  const map = {
    connected:  ['live', 'Live'],
    connecting: ['warning', 'Reconnecting'],
    closed:     ['critical', 'Disconnected'],
  };
  const [cls, label] = map[status];
  el('live-dot').className = `dot ${cls}`;
  el('live-label').textContent = label;
  if (status === 'closed') setTimeout(connect, 3000);
}

// ─────────────────────────────────────────────────────────────────────────────
// Message handlers
// ─────────────────────────────────────────────────────────────────────────────
function handle(msg) {
  const d = msg.data;
  switch (msg.type) {
    case 'snapshot':
    case 'reset':
      applySnapshot(d);
      break;
    case 'event':
      S.events.push(d);
      if (S.events.length > 400) S.events.splice(0, S.events.length - 400);
      addGuardLine(d, true);
      pendingActivity.push(d);
      if (d.guardrail_verdict === 'BLOCK') wt(d.ts, 'Guardrail block', `${d.agent_id}: ${d.tool || d.action}`);
      schedule(renderGraph);
      mapPulse(d.agent_id);
      break;
    case 'risk':
      onRisk(d, msg.ts);
      break;
    case 'analyzing':
      S.analyzing = d;
      if (d) wt(msg.ts, 'AI Engine', `Analyzing the last ${Math.min(S.events.length, WINDOW_EVENTS)} events across ${S.agents.size} agents`);
      schedule(renderAnalysis, renderDetail);
      break;
    case 'analysis':
      S.analysis = d;
      S.analyzing = false;
      wt(msg.ts, 'AI Engine verdict', `${(VERDICTS[d.verdict] || {}).label || d.verdict} · ${d.risk_level} · ${d.summary || ''}`);
      schedule(renderAnalysis, renderRoster, renderGraph, renderMap);
      break;
    case 'incident':
      onIncident(d, msg.ts);
      break;
    case 'agents':
      S.agents = new Map(d.map(a => [a.agent_id, a]));
      schedule(renderRoster, renderGraph, renderMap, renderDetail);
      break;
    case 'agent':
      S.agents.set(d.agent_id, d);
      schedule(renderRoster, renderGraph, renderMap, renderDetail);
      break;
    case 'vcs': {
      const was = new Map(S.vcs.map(v => [v.vc_id, v.state]));
      for (const v of d) if (was.get(v.vc_id) === 'DOWN' && v.state === 'UP') wt(msg.ts, 'Fabric VC restored', v.vc_id);
      S.vcs = d;
      schedule(renderTopbar, renderRoster, renderGraph, renderMap, renderDetail);
      break;
    }
    case 'scenario':
      S.scenarioRunning = d.running;
      if (d.running) wt(msg.ts, 'Scenario', `${d.name} started at ${d.speed}x`);
      schedule(renderDirector);
      break;
    case 'finding': {
      const prev = S.findings.get(d.id);
      S.findings.set(d.id, d);
      maybeToast(d, prev);
      const sel = S.findings.get(S.selected);
      // Follow the newest event unless the viewer just picked one, or the picked one outranks it.
      if (!sel || (Date.now() - pickedAt > 20000 && TIERS[d.tier].rank >= TIERS[sel.tier].rank)) S.selected = d.id;
      schedule(renderEvents, renderDetail, renderIncident);
      break;
    }
    case 'alert':
      wt(msg.ts, ALERT_LABELS[d.tier] || 'Agent alert', `${d.title} · ${d.response}`);
      break;
    case 'bridge':
      S.bridgeOnline = d.online;
      schedule(renderDetail);
      wt(msg.ts, 'AI Engine bridge', d.online ? 'Bridge connected; analyses go to Equinix AI Engine' : 'Bridge disconnected; analyses fall back to the last recording');
      schedule(renderTopbar);
      break;
  }
}

function applySnapshot(d) {
  S.agents = new Map((d.agents || []).map(a => [a.agent_id, a]));
  S.events = d.events || [];
  S.riskHistory = d.risk_history || [];
  S.risk = d.risk_score || 0;
  S.signals = d.signals || [];
  S.hotspots = d.hotspots || [];
  S.vcs = d.vcs || [];
  S.analysis = d.analysis || null;
  S.analyzing = !!d.analyzing;
  S.incident = d.incident || null;
  S.mode = d.ai_engine_mode || 'live';
  S.bridgeOnline = !!d.bridge_online;
  S.threshold = d.analyze_threshold ?? 80;
  S.scenarioRunning = !!d.scenario_running;
  S.findings = new Map((d.findings || []).map(f => [f.id, f]));
  S.activity = [];
  pendingActivity = [];
  S.selected = topFinding()?.id || null;
  renderedAnalysis = undefined;

  el('feed-guard').innerHTML = '';
  el('feed-wt').innerHTML = '';
  S.events.forEach(e => addGuardLine(e, false));
  S.signals.forEach(s => wt(null, SIGNAL_NAMES[s.type] || s.type, s.detail));
  for (const al of d.alerts || []) wt(null, ALERT_LABELS[al.tier] || 'Agent alert', `${al.title} · ${al.response}`);
  if (S.analysis) wt(null, 'AI Engine verdict', `${S.analysis.verdict} · ${S.analysis.risk_level}`);
  seenActions = 0;
  if (S.incident) logActions(S.incident, false);

  schedule(renderTopbar, renderIncident, renderRisk, renderRoster, renderGraph, renderMap, renderAnalysis, renderDirector, renderEvents, renderDetail);
}

function onRisk(d, ts) {
  const prev = new Map(S.signals.map(s => [s.type, s.score]));
  const before = S.risk;
  S.risk = d.risk;
  S.signals = d.signals || [];
  S.hotspots = d.hotspots || [];
  S.riskHistory.push({ ts, risk: d.risk });
  if (S.riskHistory.length > 300) S.riskHistory.shift();

  // The WatchTower feed only speaks when the cross-agent picture changes.
  for (const s of S.signals) {
    const was = prev.get(s.type);
    if (was == null) wt(ts, SIGNAL_NAMES[s.type] || s.type, s.detail);
    else if (s.score - was >= 0.25) wt(ts, SIGNAL_NAMES[s.type] || s.type, `escalating: ${s.detail}`);
  }
  if (before < S.threshold && S.risk >= S.threshold) wt(ts, 'Threshold crossed', `Collective risk ${S.risk} ≥ ${S.threshold}; requesting AI Engine analysis`);

  schedule(renderRisk, renderGraph);
}

function onIncident(d, ts) {
  const was = S.incident;
  if (!was || was.opened_at !== d.opened_at) seenActions = 0;
  S.incident = d;
  logActions(d, true);
  if (d.status === 'resolved' && was?.status !== 'resolved') wt(ts, 'Human review', 'Restore approved');
  schedule(renderIncident, renderTopbar, renderRoster, renderMap);
}

function logActions(inc, live) {
  for (const act of inc.actions.slice(seenActions)) {
    const by = act.by === 'auto' ? 'auto' : 'operator';
    if (act.type === 'cut_vc') {
      wt(live ? act.ts : null, 'Fabric VC cut', `${act.target} (${by}) · DELETE → ${act.fabric.response.state}${act.fabric.simulated ? ' (simulated)' : ''}`);
    } else {
      wt(live ? act.ts : null, 'Agent isolated', `${act.target} revoked at AI Gateway (${by})${act.reason ? `: ${act.reason}` : ''}`);
    }
  }
  seenActions = inc.actions.length;
}

// ─────────────────────────────────────────────────────────────────────────────
// Feeds
// ─────────────────────────────────────────────────────────────────────────────
function prependLine(feed, html, cls, animate) {
  const div = document.createElement('div');
  div.className = `line ${cls}${animate ? ' new' : ''}`;
  div.innerHTML = html;
  feed.prepend(div);
  while (feed.childElementCount > MAX_FEED_LINES) feed.lastElementChild.remove();
}

function addGuardLine(e, animate) {
  const g = GUARD[e.guardrail_verdict] || GUARD.PASS;
  const what = [e.status === 'error' ? 'failed' : '', e.tool || e.action, e.resource, e.detail].filter(Boolean).join(' · ');
  prependLine(el('feed-guard'), `
    <span class="ts">${fmtTime(e.ts)}</span>
    <span class="agent">${esc(e.agent_id)}</span>
    <span class="verdict-tag" style="color:var(--${g.cls})">${g.icon} ${g.label}</span>
    <span class="txt" title="${esc(what)}">${esc(what)}</span>`, '', animate);
}

function wt(ts, label, text) {
  prependLine(el('feed-wt'), `
    <span class="ts">${ts ? fmtTime(ts) : ''}</span>
    <span class="verdict-tag">${esc(label)}</span>
    <span class="txt" title="${esc(text)}">${esc(text)}</span>`, 'wt', !!ts);
}

// ─────────────────────────────────────────────────────────────────────────────
// Top bar + incident banner
// ─────────────────────────────────────────────────────────────────────────────
function renderTopbar() {
  const up = S.vcs.filter(v => v.state === 'UP').length, total = S.vcs.length;
  el('vc-dot').className = `dot ${up === total ? 'good' : up === 0 ? 'critical' : 'warning'}`;
  el('vc-state').textContent = total ? `${up} of ${total} UP` : '-';
  // Bridge mode: the VM reaches AI Engine only through a relay on a ZPA-connected laptop.
  // Demo mode shows what the audience needs (connected or not), not how the connection is made.
  el('ai-mode').textContent = DEMO
    ? (S.mode === 'bridge' ? (S.bridgeOnline ? 'connected' : 'offline') : 'connected')
    : S.mode === 'bridge' ? `bridge · ${S.bridgeOnline ? 'online' : 'offline'}` : S.mode;
  el('btn-kill').disabled = up === 0;
}

function renderIncident() {
  const box = el('incident');
  const inc = S.incident;
  // Closing the banner only hides it. A new event at revoke level or above, or a new action waiting for a
  // confirmation, brings it back (ones already there when it was closed do not).
  const newer = bannerHiddenAt && [...S.findings.values()].some(f =>
    (f.pending && (f.pending.ts || f.ts) > bannerHiddenAt) || (TIERS[f.tier].rank >= TIERS.revoke.rank && f.ts > bannerHiddenAt));
  if (newer) bannerHiddenAt = null;
  const hidden = !!bannerHiddenAt;
  box.className = 'incident' + (inc && !hidden ? ' show' : '') + (inc?.status === 'resolved' ? ' resolved' : '');
  if (!inc) return;

  const cut = inc.actions.filter(x => x.type === 'cut_vc').map(x => x.target);
  const isolated = inc.actions.filter(x => x.type === 'isolate_agent').map(x => x.target);
  const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
  const scope = [cut.length && `${plural(cut.length, 'Fabric VC')} cut`, isolated.length && `${plural(isolated.length, 'agent')} isolated`].filter(Boolean).join(', ');

  if (inc.status === 'resolved') {
    el('incident-title').textContent = '✓ Incident resolved after human review';
    el('incident-meta').textContent = `Opened ${fmtTime(inc.opened_at)} · resolved ${fmtTime(inc.resolved_at)} · all VCs restored, affected agents quarantined pending follow-up`;
  } else {
    const titles = {
      KILL_ALL: `▲ Global kill switch: all ${plural(S.vcs.length, 'Fabric VC')} cut`,
      KILL_SWITCH: `▲ Targeted kill switch: ${scope}`,
      CONTAIN_AGENTS: `▲ Agents contained: ${scope}`,
      REVOKE_KEY: `▲ Gateway key revoked: ${isolated.join(', ')}`,
    };
    // Lead with what happened; what WatchTower did goes on the line below.
    const top = topFinding(false);
    const icon = '▲';  // not ✖: on the banner it looked like a close button
    el('incident-title').textContent = top && TIERS[top.tier].rank >= TIERS.revoke.rank
      ? `${icon} ${headline(top)}` : (titles[inc.trigger] || `▲ Operator containment: ${scope}`);
    const active = [...S.agents.values()].filter(running).map(a => a.agent_id);
    const led = top && TIERS[top.tier].rank >= TIERS.revoke.rank;
    const parts = [led && top.response ? `WatchTower: ${top.response}` : `WatchTower: ${scope}`, `Opened ${fmtTime(inc.opened_at)}`];
    if (!led && cut.length) parts.push(`Cut: ${cut.join(', ')}`);
    if (!led && isolated.length) parts.push(`Isolated at gateway: ${isolated.join(', ')}`);
    parts.push(!active.length ? 'No agents running' : active.length > 4 ? `${active.length} agents still working` : `Still working: ${active.join(', ')}`);
    parts.push(inc.notified ? 'Slack notified' : 'Notification logged');
    el('incident-meta').textContent = parts.join(' · ');
  }
  // Restore only makes sense once something was actually blocked.
  // Restore only once something was blocked, and never next to a pending Confirm: the two were easy to mix up.
  const anyPending = [...S.findings.values()].some(f => f.pending);
  el('btn-approve').style.display = inc.status === 'pending_review' && inc.actions.length && !anyPending ? '' : 'none';
  // A proposed action waits for a person: offer the confirmation right on the banner (oldest first).
  const waiting = [...S.findings.values()].filter(f => f.pending).sort((a, b) => a.ts.localeCompare(b.ts))[0];
  const cutBtn = el('btn-approve-cut');
  cutBtn.hidden = !waiting;
  if (waiting) {
    cutBtn.dataset.action = waiting.pending.id;
    cutBtn.textContent = `Confirm: ${waiting.pending.label}`;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Collective risk
// ─────────────────────────────────────────────────────────────────────────────
function renderRisk() {
  const level = riskLevel(S.risk);
  const l = LEVELS[level];
  el('risk-num').textContent = Math.round(S.risk);
  el('risk-num').style.color = S.risk >= 35 ? `var(--${l.cls})` : '';
  el('risk-level').innerHTML = `<span class="dot ${l.cls}"></span>${level}`;
  el('risk-level').style.color = `var(--${l.cls})`;
  renderRiskChart();

  el('signals').innerHTML = S.signals.length
    ? S.signals.map(s => `
      <div class="signal">
        <div class="row"><span>${esc(SIGNAL_NAMES[s.type] || s.type)}</span><span>${Math.round(s.score * 100)}</span></div>
        <div class="track"><div class="fill" style="width:${s.score * 100}%;${s.score >= 0.7 ? 'background:var(--critical)' : ''}"></div></div>
        <div class="detail">${esc(s.detail)}</div>
      </div>`).join('')
    : '<div class="empty">No cross-agent signals yet</div>';
}

function renderRiskChart() {
  const svg = el('risk-chart');
  const W = (svg.clientWidth || 300) / uiScale(), H = 140, pad = 6;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  const pts = S.riskHistory;
  const y = (v) => H - pad - (v / 100) * (H - 2 * pad);
  const x = (i) => pts.length < 2 ? W : (i / (pts.length - 1)) * W;
  const ty = y(S.threshold);

  let html = `
    <line x1="0" x2="${W}" y1="${ty}" y2="${ty}" style="stroke:var(--critical)" stroke-dasharray="4 4" stroke-width="1" opacity="0.7"/>
    <text x="${W - 4}" y="${ty - 4}" text-anchor="end" class="node-label">analysis threshold ${S.threshold}</text>`;
  if (pts.length) {
    const line = pts.map((p, i) => `${x(i).toFixed(1)},${y(p.risk).toFixed(1)}`).join(' ');
    const color = `var(--${LEVELS[riskLevel(S.risk)].cls})`;
    html += `
      <polygon points="0,${H} ${line} ${W},${H}" style="fill:${color}" opacity="0.12"/>
      <polyline points="${line}" fill="none" style="stroke:${color}" stroke-width="2" stroke-linejoin="round"/>
      <circle cx="${x(pts.length - 1)}" cy="${y(pts.at(-1).risk)}" r="3.5" style="fill:${color}"/>`;
  }
  svg.innerHTML = html;
}

function initRiskTooltip() {
  const svg = el('risk-chart'), tip = el('risk-tip');
  svg.addEventListener('mousemove', (e) => {
    const pts = S.riskHistory;
    if (!pts.length) return;
    const rect = svg.getBoundingClientRect();
    const i = Math.round(((e.clientX - rect.left) / rect.width) * (pts.length - 1));
    const p = pts[Math.max(0, Math.min(pts.length - 1, i))];
    tip.innerHTML = `${fmtTime(p.ts)} · risk <b>${p.risk}</b>`;
    tip.style.left = `${e.clientX - rect.left}px`;  // tooltip is HTML, so real pixels
    tip.style.top = `${e.clientY - rect.top}px`;
    tip.style.display = 'block';
  });
  svg.addEventListener('mouseleave', () => { tip.style.display = 'none'; });
}

// ─────────────────────────────────────────────────────────────────────────────
// Events: what WatchTower noticed and did, in plain words (findings come from the backend)
// ─────────────────────────────────────────────────────────────────────────────
const TIERS = {
  info:   { rank: 0, cls: 'neutral',  label: 'Info' },
  watch:  { rank: 1, cls: 'warning',  label: 'Watch' },
  revoke: { rank: 2, cls: 'serious',  label: 'Revoke key' },
  cut:    { rank: 3, cls: 'critical', label: 'Cut VC' },
};
const ACTIVITY_EVERY_MS = 8000;
const VERBS = { data_read: 'read', data_write: 'wrote', tool_call: 'ran', llm_call: 'called the model', agent_message: 'messaged' };

const findingTime = (f) => f.updated || f.ts;

// The event that most needs attention: highest tier among unresolved ones.
// newest=false picks the first event to reach that tier, i.e. the one that started the incident.
function topFinding(newest = true) {
  const dir = newest ? -1 : 1;
  return [...S.findings.values()]
    .filter(f => f.status !== 'resolved')
    .sort((a, b) => TIERS[b.tier].rank - TIERS[a.tier].rank || dir * a.ts.localeCompare(b.ts))[0];
}

// One headline for the incident banner: what happened, in words.
function headline(f) {
  if (!f.key.startsWith('analysis:')) return f.what;
  const verdict = (VERDICTS[S.analysis?.verdict] || {}).label || 'AI Engine finding';
  const text = S.analysis?.collective_intent || f.detail || f.what;
  return `${verdict}: ${text.length > 150 ? text.slice(0, 147) + '…' : text}`;
}

// Routine traffic since the last summary, as one sentence: "agent-01 read README.md and wrote README.md; ..."
function summarizeActivity() {
  if (!pendingActivity.length) return;
  const batch = pendingActivity;
  pendingActivity = [];
  const byAgent = new Map();
  for (const e of batch) {
    if (!byAgent.has(e.agent_id)) byAgent.set(e.agent_id, []);
    const target = (e.resource || '').replace(/^app\//, '');
    const verb = e.status === 'error' ? `failed ${e.tool || e.action} on` : e.action === 'tool_call' ? `ran ${e.tool}${target ? ' on' : ''}` : (VERBS[e.action] || e.action);
    const phrase = `${verb} ${target}`.trim();
    const list = byAgent.get(e.agent_id);
    const same = list.find(x => x.phrase === phrase);
    same ? same.n++ : list.push({ phrase, n: 1 });
  }
  const parts = [...byAgent].slice(0, 4).map(([agent, list]) =>
    `${agent} ${list.slice(0, 3).map(x => x.n > 1 ? `${x.phrase} (${x.n}×)` : x.phrase).join(', ')}${list.length > 3 ? ', …' : ''}`);
  const more = byAgent.size > 4 ? `; ${byAgent.size - 4} more agents active` : '';
  S.activity.push({ ts: batch[batch.length - 1].ts, text: `${batch.length} tool call${batch.length === 1 ? '' : 's'}: ${parts.join('; ')}${more}.` });
  if (S.activity.length > 40) S.activity.shift();
  schedule(renderEvents);
}

function renderEvents() {
  const list = el('events-list');
  const items = [
    ...[...S.findings.values()].map(f => ({ ts: findingTime(f), f })),
    ...S.activity.map(a => ({ ts: a.ts, a })),
  ].sort((x, y) => y.ts.localeCompare(x.ts));
  if (!items.length) {
    list.innerHTML = `<div class="empty">No events yet. Routine agent activity is summarized here every few seconds, and anything WatchTower flags shows up as its own event. Press D to run a scenario.</div>`;
    return;
  }
  list.innerHTML = items.slice(0, 80).map(({ f, a, ts }) => {
    if (a) return `
      <div class="ev activity">
        <span class="ev-time">${fmtTime(ts)}</span>
        <span class="ev-tier">Activity</span>
        <div class="ev-body"><div class="ev-detail">${esc(a.text)}</div></div>
      </div>`;
    const t = TIERS[f.tier] || TIERS.info;
    return `
      <button class="ev tier-${t.cls}${f.id === S.selected ? ' selected' : ''}${f.status === 'resolved' ? ' resolved' : ''}" data-finding="${esc(f.id)}">
        <span class="ev-time">${fmtTime(ts)}</span>
        <span class="ev-tier"><span class="dot ${t.cls}"></span>${t.label}</span>
        <div class="ev-body">
          <div class="ev-what">${esc(f.what)}${f.source === 'ai_engine' ? ' <span class="ev-src">AI Engine</span>' : ''}</div>
          ${f.detail ? `<div class="ev-detail">${esc(f.detail)}</div>` : ''}
          ${f.response ? `<div class="ev-resp">WatchTower: ${esc(f.response)}</div>` : ''}
          ${f.pending ? `<div class="ev-await">Waiting for your confirmation: ${esc(f.pending.label)}</div>` : ''}
        </div>
      </button>`;
  }).join('');
}

function renderDetail() {
  const box = el('event-detail');
  const f = S.findings.get(S.selected);
  if (!f) {
    box.innerHTML = `<div class="empty">Select an event to see who is involved, what WatchTower did, and what you can do next.</div>`;
    return;
  }
  const t = TIERS[f.tier] || TIERS.info;
  const agents = f.agents.map(id => S.agents.get(id)).filter(Boolean);
  const vcs = [...new Set(agents.map(a => a.vc_id))].map(id => S.vcs.find(v => v.vc_id === id)).filter(Boolean);
  const isolatable = agents.filter(running);
  const proposal = f.pending;
  const buttons = [
    ...(proposal ? [
      `<button class="danger" data-confirm-action="${esc(proposal.id)}" title="WatchTower acts only when a person confirms">Confirm: ${esc(proposal.label)}</button>`,
      `<button data-decline-action="${esc(proposal.id)}" title="Do not take this action">Decline</button>`,
    ] : []),
    ...(proposal ? [] : isolatable).slice(0, 4).map(a => `<button data-isolate="${esc(a.agent_id)}" title="Revoke this agent's AI Gateway key">Revoke ${esc(a.agent_id)}</button>`),
    ...(proposal ? [] : vcs).filter(v => v.state === 'UP').map(v => `<button class="${f.tier === 'cut' ? 'danger' : ''}" data-cut="${esc(v.vc_id)}" title="Delete this Fabric VC; every agent behind it loses the model">Cut ${esc(v.vc_id)}</button>`),
    `<button data-analyze="1" ${S.analyzing ? 'disabled' : ''} title="Send the current window to Equinix AI Engine">${S.analyzing ? 'AI Engine is analyzing…' : 'Ask AI Engine'}</button>`,
    emailButton(f),
    f.status === 'open' ? `<button data-ack="${esc(f.id)}" title="Mark as seen; keeps it in the feed">Acknowledge</button>` : '',
  ].filter(Boolean);
  const mail = f.email;
  const mailLine = !mail ? '' : mail.status === 'sending' ? `Emailing ${esc(mail.to)}…`
    : mail.status === 'sent' ? `AI Engine emailed ${esc(mail.to)} at ${fmtTime(mail.ts)}.`
    : mail.status === 'approval' ? `Waiting for approval in AI Engine before it is sent to ${esc(mail.to)}. ${esc(mail.error || '')}`
    : `Email to ${esc(mail.to)} was not sent: ${esc(mail.error || 'unknown error')}.`;
  const statusLabel = { open: 'Open', acknowledged: 'Acknowledged', resolved: 'Resolved' }[f.status] || f.status;
  box.innerHTML = `
    <div class="detail-head">
      <span class="badge ${t.cls}">${t.label}</span>
      <span class="hint">${fmtTime(f.ts)}${f.count > 1 ? ` · updated ${f.count - 1}×` : ''} · ${esc(statusLabel)}${f.source === 'ai_engine' ? ' · from AI Engine' : f.source === 'operator' ? ' · operator action' : ''}</span>
    </div>
    <div class="detail-what">${esc(f.what)}</div>
    ${f.detail ? `<p class="detail-text">${esc(f.detail)}</p>` : ''}
    <div class="ai-section"><h3>What WatchTower did</h3><p>${esc(f.response || 'Nothing yet.')}</p>${mailLine ? `<p class="mail-line ${mail.status}">${mailLine}</p>` : ''}</div>
    ${agents.length ? `<div class="ai-section"><h3>Agents involved</h3><div class="detail-agents">${agents.map(a => {
      const st = AGENT_STATUS[a.status] || { cls: '', label: a.status };
      return `<span class="chip" title="${esc(a.declared_task)}">${esc(a.agent_id)} <span class="dot ${st.cls}"></span>${esc(st.label)}</span>`;
    }).join('')}</div></div>` : ''}
    <div class="ai-section"><h3>Actions</h3><div class="detail-actions">${buttons.join('')}</div></div>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Notifications: a card on the right when something needs a look; Review jumps to it
// ─────────────────────────────────────────────────────────────────────────────
const MAX_TOASTS = 3;
const TOAST_MS = 12000;
let showView = () => {};  // set by initViewTabs

function maybeToast(f, prev) {
  const rank = TIERS[f.tier].rank;
  const analysisDone = f.key.startsWith('analysis:') && !prev;
  const escalated = rank >= TIERS.revoke.rank && (!prev || TIERS[prev.tier].rank < rank);
  const approvalNeeded = f.pending && !prev?.pending;
  // Confirmed or declined anywhere (banner, event details, Auto-run): its notification has nothing left to ask.
  if (prev?.pending && !f.pending) el('toasts').querySelector(`[data-finding-toast="${CSS.escape(f.id)}"]`)?.remove();
  if (analysisDone || escalated || approvalNeeded) toast(f);
}

function toast(f) {
  const t = TIERS[f.tier] || TIERS.info;
  const box = el('toasts');
  // One notification at a time: the newest replaces the others, except a card still waiting for a Confirm,
  // which stays until someone answers it.
  const waiting = [...box.children].some(c => c.dataset.pending && c.dataset.findingToast !== f.id);
  if (waiting && !f.pending) return;
  box.replaceChildren();
  const card = document.createElement('div');
  card.dataset.findingToast = f.id;
  if (f.pending) card.dataset.pending = '1';
  card.className = `toast tier-${t.cls}`;
  card.setAttribute('role', 'status');
  card.innerHTML = `
    <div class="toast-head">
      <span class="ev-tier"><span class="dot ${t.cls}"></span>${t.label}</span>
      <span class="ev-time">${fmtTime(f.updated || f.ts)}</span>
      <button class="toast-close" aria-label="Close notification" title="Close">×</button>
    </div>
    <div class="toast-what">${esc(f.what)}</div>
    ${f.pending ? `<div class="toast-resp"><b>Confirmation needed:</b> ${esc(f.pending.label)}.</div>` : ''}
    ${f.response ? `<div class="toast-resp">WatchTower: ${esc(f.response)}</div>` : ''}
    <div class="toast-actions">${f.pending ? `<button class="danger toast-confirm">Confirm</button>` : ''}<button class="toast-review">Review</button></div>`;
  card.querySelector('.toast-close').addEventListener('click', () => card.remove());
  card.querySelector('.toast-confirm')?.addEventListener('click', () => {
    post(`/api/actions/${encodeURIComponent(f.pending.id)}/confirm`);
    card.remove();
  });
  card.querySelector('.toast-review').addEventListener('click', () => {
    S.selected = f.id;
    pickedAt = Date.now();
    showView('events');
    schedule(renderEvents, renderDetail);
    el('ai').scrollIntoView({ behavior: 'smooth', block: 'start' });
    card.remove();
  });
  // Watch and revoke notices close on their own (they can cover the action buttons); a cut or an approval
  // request stays until closed. Nothing closes while the tab is in the background, so it is there on return.
  const sticky = f.tier === 'cut' || f.pending;
  let timer;
  const close = () => { if (document.hidden) timer = setTimeout(close, 2000); else card.remove(); };
  if (!sticky) {
    timer = setTimeout(close, TOAST_MS);
    card.addEventListener('mouseenter', () => clearTimeout(timer));
    card.addEventListener('mouseleave', () => { timer = setTimeout(close, TOAST_MS / 2); });
  }
  box.prepend(card);
  while (box.childElementCount > MAX_TOASTS) box.lastElementChild.remove();
}

// Email goes out through AI Engine (Microsoft 365), which only a bridge laptop on ZPA can reach.
function emailButton(f) {
  const sending = f.email?.status === 'sending';
  const ready = S.mode === 'bridge' && S.bridgeOnline;
  const label = sending ? 'Sending email…' : f.email?.status === 'sent' ? 'Email again' : 'Email me';
  const why = ready ? 'Email this event through Equinix AI Engine (Microsoft 365)' : 'Start the bridge on a laptop on Zscaler ZPA to send email';
  return `<button data-email="${esc(f.id)}" ${sending || !ready ? 'disabled' : ''} title="${why}">${label}</button>`;
}

function initEvents() {
  el('events-list').addEventListener('click', (e) => {
    const b = e.target.closest('[data-finding]');
    if (!b) return;
    S.selected = b.dataset.finding;
    pickedAt = Date.now();
    schedule(renderEvents, renderDetail);
  });
  el('event-detail').addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (!b || b.disabled) return;
    if (b.dataset.isolate) post(`/api/agents/${encodeURIComponent(b.dataset.isolate)}/isolate`);
    if (b.dataset.cut && confirm(`Cut Fabric VC ${b.dataset.cut}? Every agent behind it loses the model.`)) post(`/api/vcs/${encodeURIComponent(b.dataset.cut)}/cut`);
    if (b.dataset.analyze) post('/api/analyze');
    if (b.dataset.ack) post(`/api/findings/${encodeURIComponent(b.dataset.ack)}/ack`);
    if (b.dataset.confirmAction) post(`/api/actions/${encodeURIComponent(b.dataset.confirmAction)}/confirm`);
    if (b.dataset.declineAction) post(`/api/actions/${encodeURIComponent(b.dataset.declineAction)}/decline`);
    if (b.dataset.email) post(`/api/findings/${encodeURIComponent(b.dataset.email)}/email`);
  });
  setInterval(summarizeActivity, ACTIVITY_EVERY_MS);
}

// ─────────────────────────────────────────────────────────────────────────────
// Agent roster
// ─────────────────────────────────────────────────────────────────────────────
function renderRoster() {
  const flagged = new Set(S.analysis?.involved_agents || []);
  const agents = [...S.agents.values()];
  const active = agents.filter(running).length;
  el('roster-sub').textContent = agents.length ? `${active} of ${agents.length} agents active` : '';
  if (!agents.length) {
    el('roster-list').innerHTML = '<div class="empty">No agents registered. Press D, then Run scenario.</div>';
    return;
  }

  const agentRow = (a) => {
    const st = AGENT_STATUS[a.status] || { cls: '', label: a.status };
    return `
      <div class="agent-row${flagged.has(a.agent_id) || a.alert ? ' flagged' : ''}" title="${esc(a.alert ? a.alert + ' · ' : '')}${esc(a.owner)} · ${a.llm_calls} LLM calls · last: ${esc(a.last_action || 'none')}">
        <span class="id">${flagged.has(a.agent_id) || a.alert ? '▲ ' : ''}${esc(a.agent_id)}</span>
        <span class="task">${esc(a.declared_task)}</span>
        ${statusTag(st.cls, st.label)}
        <button class="mini" data-isolate="${esc(a.agent_id)}" ${running(a) ? '' : 'disabled'} title="Revoke this agent's AI Gateway token">Isolate</button>
      </div>`;
  };
  el('roster-list').innerHTML = S.vcs.map(vc => {
    const down = vc.state === 'DOWN';
    const rows = vc.agents.map(id => S.agents.get(id)).filter(Boolean).sort((x, y) => x.agent_id.localeCompare(y.agent_id));
    return `
      <div class="vc-group">
        <div class="vc-row${down ? ' down' : ''}" title="${esc(vc.owner)} workloads to the AI Hub">
          <span class="dot ${down ? 'critical' : 'good'}"></span>
          <span class="vc-id">${esc(vc.vc_id)}</span>
          ${statusTag(down ? 'critical' : 'good', down ? 'DOWN' : 'UP')}
          <button class="mini" data-cut="${esc(vc.vc_id)}" ${down ? 'disabled' : ''} title="Delete this Fabric VC; every agent behind it loses the model">Cut VC</button>
        </div>
        ${rows.map(agentRow).join('')}
      </div>`;
  }).join('');
}

// ─────────────────────────────────────────────────────────────────────────────
// Correlation graph: agents (left) ↔ resources (right), edges from the detector window
// ─────────────────────────────────────────────────────────────────────────────
function renderGraph() {
  const svg = el('net');
  const u = uiScale();
  const W = (svg.clientWidth || 600) / u, H = Math.max(svg.clientHeight / u, 640);
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

  const recent = S.events.slice(-WINDOW_EVENTS);
  const edges = new Map();   // "agent|resource" -> {agent, resource, write, count}
  const touches = new Map(); // resource -> Set(agent)
  for (const e of recent) {
    if (!e.resource) continue;
    const key = `${e.agent_id}|${e.resource}`;
    const edge = edges.get(key) || { agent: e.agent_id, resource: e.resource, write: false, count: 0 };
    edge.write ||= WRITE_ACTIONS.has(e.action);
    edge.count += 1;
    edges.set(key, edge);
    if (!touches.has(e.resource)) touches.set(e.resource, new Set());
    touches.get(e.resource).add(e.agent_id);
  }

  // Order agents by VC so each team's connection reads as one block.
  const vcOf = (id) => S.agents.get(id)?.vc_id || '';
  const agentIds = [...new Set([...S.agents.keys(), ...recent.map(e => e.agent_id)])]
    .sort((x, y) => vcOf(x).localeCompare(vcOf(y)) || x.localeCompare(y));
  const resources = [...touches.keys()]
    .sort((a, b) => (sensitiveHotspot(b) - sensitiveHotspot(a)) || (touches.get(b).size - touches.get(a).size) || a.localeCompare(b))
    .slice(0, MAX_GRAPH_RESOURCES);

  if (!agentIds.length) {
    svg.innerHTML = `<text x="${W / 2}" y="${H / 2}" text-anchor="middle" class="node-label">Waiting for agent activity</text>`;
    return;
  }

  // Leave room for labels: agent ids on the left, resource paths on the right.
  const longest = Math.max(8, ...agentIds.map(id => id.length + 2));  // + room for the ✖ marker
  const ax = Math.min(W * 0.35, longest * 7.6 + 30), rx = W - Math.min(280, W * 0.4);
  // Rows at most 64 apart and centered, so a few nodes don't stretch into long diagonals.
  const spread = (n, i) => {
    const gap = n === 1 ? 0 : Math.min(64, (H - 72) / (n - 1));
    return (H - gap * (n - 1)) / 2 + i * gap;
  };
  const apos = new Map(agentIds.map((id, i) => [id, spread(agentIds.length, i)]));
  const rpos = new Map(resources.map((r, i) => [r, spread(resources.length, i)]));
  const flagged = new Set(S.analysis?.involved_agents || []);

  let lines = '';
  for (const e of edges.values()) {
    if (!rpos.has(e.resource) || !apos.has(e.agent)) continue;
    const y1 = apos.get(e.agent), y2 = rpos.get(e.resource), mx = (ax + rx) / 2;
    const hot = e.write && sensitiveHotspot(e.resource);
    const color = hot ? 'var(--critical)' : e.write ? 'var(--series-1)' : 'var(--neutral-mark)';
    const width = Math.min(4, 1 + e.count * 0.5) + (hot ? 0.5 : 0);
    lines += `<path d="M${ax},${y1} C${mx},${y1} ${mx},${y2} ${rx},${y2}" fill="none" style="stroke:${color}" stroke-width="${width}" opacity="${hot ? 0.95 : 0.55}"/>`;
  }

  let nodes = '';
  for (const id of agentIds) {
    const a = S.agents.get(id);
    const down = a && !running(a);
    const warned = a?.status === 'warning';
    const y = apos.get(id);
    nodes += `
      <g opacity="${down ? 0.45 : 1}">
        ${flagged.has(id) || warned ? `<circle cx="${ax}" cy="${y}" r="14" fill="none" style="stroke:var(${warned && !flagged.has(id) ? '--warning' : '--critical'})" stroke-width="2"/>` : ''}
        <circle cx="${ax}" cy="${y}" r="9" style="fill:var(--series-1)"/>
        <text x="${ax - 20}" y="${y + 5}" text-anchor="end" class="node-label${flagged.has(id) ? ' strong' : ''}">${esc(id)}${down ? ' ✖' : ''}</text>
      </g>`;
  }
  for (const r of resources) {
    const hot = sensitiveHotspot(r);
    const n = touches.get(r).size;
    const y = rpos.get(r);
    nodes += `
      <circle cx="${rx}" cy="${y}" r="${Math.min(16, 6 + n * 1.4)}" style="fill:var(${hot ? '--critical' : '--neutral-mark'})"/>
      <text x="${rx + 22}" y="${y + 5}" class="node-label${hot ? ' strong' : ''}">${esc(r)} <tspan opacity="0.7">· ${n}</tspan></text>`;
  }
  svg.innerHTML = lines + nodes;
}

// ─────────────────────────────────────────────────────────────────────────────
// Map view: Fabric VCs from each team's site to the AI Gateway (topology.json says where things are)
// ─────────────────────────────────────────────────────────────────────────────
const M = { topo: null, nation: null, states: null, baseKey: '', arcs: new Map(), view: 'graph' };

async function loadMap() {
  try {
    const [topo, us] = await Promise.all([
      fetch('topology.json').then(r => r.json()),
      fetch('vendor/states-10m.json').then(r => r.json()),
    ]);
    M.topo = topo;
    // Lower 48 only: Alaska, Hawaii and the territories would shrink the map to make room for insets.
    const lower48 = us.objects.states.geometries.filter(g => +g.id <= 56 && !['02', '15'].includes(g.id));
    M.states = { type: 'FeatureCollection', features: lower48.map(g => topojson.feature(us, g)) };
    M.nation = topojson.merge(us, lower48);
    M.baseKey = '';
    schedule(renderMap);
  } catch (err) {
    console.error('[WatchTower] map data failed to load', err);
  }
}

function initViewTabs() {
  const titles = {
    events: ['Events', 'what WatchTower noticed, in plain words'],
    graph: ['Agent correlation graph', 'who touches what, live'],
    map: ['Fabric network map', "one VC per team, from the team's site to the AI Gateway"],
  };
  const show = (view) => {
    M.view = view;
    for (const b of document.querySelectorAll('#graph .tab')) {
      b.classList.toggle('active', b.dataset.view === view);
      b.setAttribute('aria-selected', b.dataset.view === view);
    }
    el('view-events').hidden = view !== 'events';
    el('view-graph').hidden = view !== 'graph';
    el('view-map').hidden = view !== 'map';
    [el('graph-title').textContent, el('graph-sub').textContent] = titles[view];
    try { localStorage.setItem('wt-view', view); } catch {}
    M.baseKey = '';
    schedule(view === 'map' ? renderMap : view === 'graph' ? renderGraph : renderEvents);
  };
  for (const b of document.querySelectorAll('#graph .tab')) b.addEventListener('click', () => show(b.dataset.view));
  showView = show;
  let saved = 'events';
  try { saved = localStorage.getItem('wt-view') || 'events'; } catch {}
  show(titles[saved] ? saved : 'events');
}

function siteOf(owner) {
  return M.topo.team_sites[owner] || M.topo.default_site;
}

function renderMap() {
  if (M.view !== 'map' || !M.topo || !M.nation) return;
  const svg = el('map');
  const u = uiScale();
  const W = (svg.clientWidth || 800) / u, H = Math.max(svg.clientHeight / u, 640);
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  const projection = d3.geoAlbers().fitExtent([[24, 24], [W - 24, H - 24]], M.nation);
  const pt = (metro) => {
    const m = M.topo.metros[metro];
    return m ? projection([m.lon, m.lat]) : null;
  };

  // Base layer only when the size changes: state boundaries are heavy.
  const key = `${Math.round(W)}x${Math.round(H)}`;
  if (M.baseKey !== key) {
    const path = d3.geoPath(projection);
    svg.innerHTML = `<g id="map-base">
        ${M.states.features.map(f => `<path class="map-state" d="${path(f) || ''}"/>`).join('')}
        <path class="map-nation" d="${path(M.nation) || ''}"/>
      </g><g id="map-links"></g><g id="map-pulses"></g><g id="map-nodes"></g>`;
    M.baseKey = key;
  }

  const gw = pt(M.topo.gateway.metro);
  if (!gw) return;
  const curve = (a, b, bend) => {
    const mx = (a[0] + b[0]) / 2, my = (a[1] + b[1]) / 2;
    const dx = b[0] - a[0], dy = b[1] - a[1], len = Math.hypot(dx, dy) || 1;
    const cx = mx - (dy / len) * len * bend, cy = my + (dx / len) * len * bend;
    return { d: `M${a[0]},${a[1]} Q${cx},${cy} ${b[0]},${b[1]}`, mid: [(a[0] + 2 * cx + b[0]) / 4, (a[1] + 2 * cy + b[1]) / 4] };
  };

  // VCs: one arc per VC from its team's site to the gateway; VCs sharing a site fan out.
  let links = '';
  const perSite = new Map();
  M.arcs.clear();
  for (const vc of S.vcs) {
    const metro = siteOf(vc.owner);
    const from = pt(metro);
    if (!from) continue;
    const i = perSite.get(metro) || 0;
    perSite.set(metro, i + 1);
    const { d, mid } = curve(from, gw, 0.18 + i * 0.12);
    const down = vc.state === 'DOWN';
    M.arcs.set(vc.vc_id, { d, down });
    links += `<path class="map-vc ${down ? 'down' : 'up'}" d="${d}"/>
      <path class="map-vc-hit" data-vc="${esc(vc.vc_id)}" d="${d}"/>`;
    if (down) {
      links += `<g transform="translate(${mid[0]},${mid[1]})">
          <circle r="11" style="fill:var(--critical)"/>
          <text y="5" text-anchor="middle" style="fill:#fff;font-size:14px;font-weight:bold">✖</text>
        </g>
        <text x="${mid[0]}" y="${mid[1] + 28}" text-anchor="middle" class="map-sub" style="fill:var(--critical)">${esc(vc.vc_id)} cut</text>`;
    }
  }
  for (const llm of M.topo.llm_endpoints || []) {
    const to = pt(llm.metro);
    if (to) links += `<path class="map-llm-link" d="${curve(gw, to, -0.12).d}"/>`;
  }
  svg.querySelector('#map-links').innerHTML = links;

  // Nodes: gateway, LLM endpoints, one per team site with its agents' state.
  const metroName = (m) => `${m} · ${M.topo.metros[m]?.name || ''}`;
  // Two-line label on the side topology.json names for the metro ("label": left|right|above|below),
  // flipped or nudged back inside the map when it would run off an edge.
  const label = (p, r, side, title, sub) => {
    const w = Math.max(title.length * 7.6, sub.length * 5.8);
    if (side === 'right' && p[0] + r + 8 + w > W - 8) side = 'left';
    else if (side === 'left' && p[0] - r - 8 - w < 8) side = 'right';
    let x = p[0], y = p[1], anchor = 'middle';
    if (side === 'left') { x -= r + 8; anchor = 'end'; y -= 2; }
    else if (side === 'right') { x += r + 8; anchor = 'start'; y -= 2; }
    else if (side === 'above') y -= r + 22;
    else y += r + 18;
    const left = anchor === 'start' ? x : anchor === 'end' ? x - w : x - w / 2;
    x += Math.max(0, 8 - left) - Math.max(0, left + w - (W - 8));
    return `<text x="${x}" y="${y}" text-anchor="${anchor}" class="map-label">${esc(title)}</text>
      <text x="${x}" y="${y + 16}" text-anchor="${anchor}" class="map-sub">${esc(sub)}</text>`;
  };
  const sideOf = (m, fallback) => M.topo.metros[m]?.label || fallback;
  let nodes = '';
  for (const llm of M.topo.llm_endpoints || []) {
    const p = pt(llm.metro);
    if (!p) continue;
    nodes += `<circle cx="${p[0]}" cy="${p[1]}" r="8" style="fill:var(--neutral-mark);stroke:var(--surface-1)" stroke-width="2"/>
      ${label(p, 8, sideOf(llm.metro, 'below'), llm.label, metroName(llm.metro))}`;
  }
  const sites = new Map();
  for (const a of S.agents.values()) {
    const m = siteOf(a.owner);
    if (!sites.has(m)) sites.set(m, { teams: new Set(), total: 0, active: 0 });
    const s = sites.get(m);
    s.teams.add(a.owner);
    s.total += 1;
    if (running(a)) s.active += 1;
  }
  for (const [m, s] of sites) {
    const p = pt(m);
    if (!p) continue;
    const allDown = s.active === 0;
    const r = 7 + Math.min(10, s.total * 1.5);
    nodes += `${allDown && S.incident?.status === 'pending_review' ? `<circle class="map-ring" cx="${p[0]}" cy="${p[1]}" r="14"/>` : ''}
      <circle cx="${p[0]}" cy="${p[1]}" r="${r}" style="fill:var(${allDown ? '--critical' : '--series-1'});stroke:var(--surface-1)" stroke-width="2"/>
      <text x="${p[0]}" y="${p[1] + 5}" text-anchor="middle" style="fill:#fff;font-size:13px;font-weight:bold">${s.total}</text>
      ${label(p, r, sideOf(m, 'right'), [...s.teams].join(', '), `${metroName(m)} · ${s.active} of ${s.total} agents active`)}`;
  }
  nodes += `<circle cx="${gw[0]}" cy="${gw[1]}" r="15" style="fill:var(--eq-hero-accent);stroke:#fff" stroke-width="3"/>
    ${label(gw, 15, sideOf(M.topo.gateway.metro, 'left'), M.topo.gateway.label, metroName(M.topo.gateway.metro))}`;
  if (!S.vcs.length) {
    nodes += `<text x="${W / 2}" y="${H - 30}" text-anchor="middle" class="map-sub">No Fabric VCs yet. Agents appear when they register or send traffic.</text>`;
  }
  svg.querySelector('#map-nodes').innerHTML = nodes;
}

// One dot per LLM call travelling from the agent's site to the gateway over its VC.
function mapPulse(agentId) {
  if (M.view !== 'map') return;
  const a = S.agents.get(agentId);
  const arc = a && M.arcs.get(a.vc_id);
  const layer = el('map')?.querySelector('#map-pulses');
  if (!arc || arc.down || !layer || layer.childElementCount > 40) return;
  const ns = 'http://www.w3.org/2000/svg';
  const dot = document.createElementNS(ns, 'circle');
  dot.setAttribute('r', '4');
  dot.setAttribute('class', 'map-pulse');
  const move = document.createElementNS(ns, 'animateMotion');
  move.setAttribute('dur', '1.2s');
  move.setAttribute('fill', 'freeze');
  move.setAttribute('path', arc.d);
  dot.appendChild(move);
  layer.appendChild(dot);
  move.beginElement?.();
  setTimeout(() => dot.remove(), 1300);
}

function initMapTooltip() {
  const svg = el('map'), tip = el('map-tip');
  svg.addEventListener('mousemove', (e) => {
    const id = e.target.dataset?.vc;
    const vc = id && S.vcs.find(v => v.vc_id === id);
    if (!vc) { tip.style.display = 'none'; return; }
    const agents = vc.agents.map(aid => {
      const st = AGENT_STATUS[S.agents.get(aid)?.status] || { label: '?' };
      return `${esc(aid)}: ${esc(st.label)}`;
    }).join('<br>');
    const rect = svg.parentElement.getBoundingClientRect();
    tip.innerHTML = `<b>${esc(vc.vc_id)}</b> · ${esc(vc.owner)} · ${vc.state}<br>${agents}`;
    tip.style.left = `${e.clientX - rect.left}px`;
    tip.style.top = `${e.clientY - rect.top}px`;
    tip.style.display = 'block';
  });
  svg.addEventListener('mouseleave', () => { tip.style.display = 'none'; });
}

// ─────────────────────────────────────────────────────────────────────────────
// AI Engine analysis
// ─────────────────────────────────────────────────────────────────────────────
function renderAnalysis() {
  const status = el('ai-status');
  const a = S.analysis;
  if (S.analyzing) {
    status.innerHTML = `<span class="spinner"></span>Equinix AI Engine is analyzing the cross-agent window…`;
  } else if (a) {
    const l = LEVELS[a.risk_level] || LEVELS.LOW;
    const latency = a._latency_s != null ? ` in ${a._latency_s}s` : '';
    status.innerHTML = `<span class="dot ${l.cls}"></span>Analysis complete${latency}`;
  } else {
    status.innerHTML = `<span class="dot"></span>Waiting for risk to cross the analysis threshold (${S.threshold})`;
  }

  if (a === renderedAnalysis) return;
  renderedAnalysis = a;
  const body = el('ai-body');
  if (!a) { body.innerHTML = ''; return; }

  const v = VERDICTS[a.verdict] || { cls: 'warning', icon: '▲', label: a.verdict };
  const section = (title, html) => html ? `<div class="ai-section"><h3>${title}</h3>${html}</div>` : '';
  const chips = (xs) => xs?.length ? `<div class="chips">${xs.map(x => `<span class="chip">${esc(x)}</span>`).join('')}</div>` : '';
  const agentOf = new Map(S.events.map(e => [e.event_id, e.agent_id]));

  body.innerHTML = `
    <div class="verdict">
      <span class="badge ${v.cls}">${v.icon} ${esc(v.label)}</span>
      ${levelBadge(a.risk_level)}
      <span class="hint">${Math.round((a.confidence || 0) * 100)}% confidence${a.attack_stage ? ` · stage: ${esc(a.attack_stage)}` : ''}</span>
    </div>
    ${section('Summary', `<p>${esc(a.summary)}</p>`)}
    ${section('Collective intent', a.collective_intent && `<p>${esc(a.collective_intent)}</p>`)}
    ${section('Patterns', chips(a.patterns))}
    ${section('Involved agents', chips(a.involved_agents))}
    ${section('Target resources', chips(a.target_resources))}
    ${section('Coordination channel', a.coordination_channel && a.coordination_channel !== 'none' && `<p>${esc(a.coordination_channel)}</p>`)}
    ${section('Reasoning', a.reasoning_steps?.length && `<ol class="steps">${a.reasoning_steps.map(s => `<li>${esc(s)}</li>`).join('')}</ol>`)}
    ${section('Evidence', a.evidence?.length && `<div class="evidence">${a.evidence.map(ev => `
      <div><span class="eid">${esc(ev.event_id)}</span><span class="${/inject/i.test(ev.why) ? 'inj' : ''}">${agentOf.has(ev.event_id) ? `${esc(agentOf.get(ev.event_id))}: ` : ''}${esc(ev.why)}</span></div>`).join('')}</div>`)}
    ${section('Why guardrails missed it', a.why_guardrails_missed && `<p>${esc(a.why_guardrails_missed)}</p>`)}
    ${section('Human review', a.human_review_note && `<p>${esc(a.human_review_note)}</p>`)}
    <div class="source">Source: ${esc(a._source || S.mode)}</div>`;

  // Reveal the reasoning one step at a time.
  body.querySelectorAll('ol.steps li').forEach((li, i) => setTimeout(() => li.classList.add('in'), 250 + i * 450));
}

// ─────────────────────────────────────────────────────────────────────────────
// Actions + director controls (press D)
// ─────────────────────────────────────────────────────────────────────────────
function renderDirector() {
  el('btn-run').textContent = S.scenarioRunning ? 'Restart scenario' : 'Run scenario';
}

async function loadScenarios() {
  try {
    const list = await (await fetch(`${API_BASE}/api/scenarios`)).json();
    el('scenario').innerHTML = list.map((x, i) => `<option value="${esc(x.id)}" title="${esc(x.description || '')}">${i + 1}. ${esc(x.tier)} · ${esc(x.name)}</option>`).join('');
  } catch (err) {
    console.error('[WatchTower] could not load scenarios', err);
  }
}

function initControls() {
  el('btn-kill').addEventListener('click', () => {
    const ids = S.vcs.filter(v => v.state === 'UP').map(v => v.vc_id);
    if (confirm(`Global kill switch: delete ${ids.length} Fabric VCs (${ids.join(', ')}) and cut every agent off from the model?`)) post('/api/killswitch');
  });
  el('roster-list').addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (!b || b.disabled) return;
    if (b.dataset.isolate) post(`/api/agents/${encodeURIComponent(b.dataset.isolate)}/isolate`);
    if (b.dataset.cut && confirm(`Cut Fabric VC ${b.dataset.cut}? Every agent behind it loses the model.`)) post(`/api/vcs/${encodeURIComponent(b.dataset.cut)}/cut`);
  });
  el('btn-approve').addEventListener('click', () => post('/api/review/approve'));
  el('btn-incident-close').addEventListener('click', () => {
    bannerHiddenAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    schedule(renderIncident);
  });
  el('btn-approve-cut').addEventListener('click', (e) => {
    const id = e.currentTarget.dataset.action;
    if (id) post(`/api/actions/${encodeURIComponent(id)}/confirm`);
  });
  el('btn-run').addEventListener('click', () => post('/api/scenario/run', { scenario: el('scenario').value, speed: parseFloat(el('speed').value) }));
  loadScenarios();
  el('btn-reset').addEventListener('click', () => post('/api/reset'));

  document.addEventListener('keydown', (e) => {
    if (e.key.toLowerCase() !== 'd' || e.metaKey || e.ctrlKey || e.altKey) return;
    if (['INPUT', 'SELECT', 'TEXTAREA'].includes(document.activeElement?.tagName)) return;
    el('director').classList.toggle('show');
  });

  window.addEventListener('resize', () => schedule(renderRiskChart, renderGraph, renderMap));
}

// ─────────────────────────────────────────────────────────────────────────────
// Init: the stream's first message is a full snapshot, so no separate /api/state fetch.
// ─────────────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initControls();
  initRiskTooltip();
  initViewTabs();
  initEvents();
  initMapTooltip();
  loadMap();
  connect();
});
