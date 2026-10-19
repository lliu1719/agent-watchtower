/**
 * WatchTower dashboard: renders the backend's SSE stream (/api/stream) into index.html.
 * Field names follow backend/watchtower/app.py (State.snapshot, normalize, publish).
 */

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────
const API_BASE = '';
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
  contained:               { cls: 'serious',  label: 'Contained' },
  severed:                 { cls: 'critical', label: 'Severed' },
  quarantined_review_done: { cls: 'warning',  label: 'Reviewed' },
};
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
};
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
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.error('[WatchTower]', path, err);
    alert(`${path} failed: ${err.message}`);
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
      if (d.guardrail_verdict === 'BLOCK') wt(d.ts, 'Guardrail block', `${d.agent_id}: ${d.tool || d.action}`);
      schedule(renderGraph);
      break;
    case 'risk':
      onRisk(d, msg.ts);
      break;
    case 'analyzing':
      S.analyzing = d;
      if (d) wt(msg.ts, 'AI Engine', `Analyzing the last ${Math.min(S.events.length, WINDOW_EVENTS)} events across ${S.agents.size} agents`);
      schedule(renderAnalysis);
      break;
    case 'analysis':
      S.analysis = d;
      S.analyzing = false;
      wt(msg.ts, 'AI Engine verdict', `${(VERDICTS[d.verdict] || {}).label || d.verdict} · ${d.risk_level} · ${d.summary || ''}`);
      schedule(renderAnalysis, renderRoster, renderGraph);
      break;
    case 'incident':
      onIncident(d, msg.ts);
      break;
    case 'agents':
      S.agents = new Map(d.map(a => [a.agent_id, a]));
      schedule(renderRoster, renderGraph);
      break;
    case 'agent':
      S.agents.set(d.agent_id, d);
      schedule(renderRoster, renderGraph);
      break;
    case 'vcs': {
      const was = new Map(S.vcs.map(v => [v.vc_id, v.state]));
      for (const v of d) if (was.get(v.vc_id) === 'DOWN' && v.state === 'UP') wt(msg.ts, 'Fabric VC restored', v.vc_id);
      S.vcs = d;
      schedule(renderTopbar, renderRoster, renderGraph);
      break;
    }
    case 'scenario':
      S.scenarioRunning = d.running;
      if (d.running) wt(msg.ts, 'Scenario', `${d.name} started at ${d.speed}x`);
      schedule(renderDirector);
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
  S.threshold = d.analyze_threshold ?? 80;
  S.scenarioRunning = !!d.scenario_running;
  renderedAnalysis = undefined;

  el('feed-guard').innerHTML = '';
  el('feed-wt').innerHTML = '';
  S.events.forEach(e => addGuardLine(e, false));
  S.signals.forEach(s => wt(null, SIGNAL_NAMES[s.type] || s.type, s.detail));
  if (S.analysis) wt(null, 'AI Engine verdict', `${S.analysis.verdict} · ${S.analysis.risk_level}`);
  seenActions = 0;
  if (S.incident) logActions(S.incident, false);

  schedule(renderTopbar, renderIncident, renderRisk, renderRoster, renderGraph, renderAnalysis, renderDirector);
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
  schedule(renderIncident, renderTopbar, renderRoster);
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
  const what = [e.tool || e.action, e.resource, e.detail].filter(Boolean).join(' · ');
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
  el('ai-mode').textContent = S.mode;
  el('btn-kill').disabled = up === 0;
}

function renderIncident() {
  const box = el('incident');
  const inc = S.incident;
  box.className = 'incident' + (inc ? ' show' : '') + (inc?.status === 'resolved' ? ' resolved' : '');
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
      KILL_ALL: `✖ Global kill switch: all ${plural(S.vcs.length, 'Fabric VC')} cut`,
      KILL_SWITCH: `✖ Targeted kill switch: ${scope}`,
      CONTAIN_AGENTS: `▲ Agents contained: ${scope}`,
    };
    el('incident-title').textContent = titles[inc.trigger] || `▲ Operator containment: ${scope}`;
    const active = [...S.agents.values()].filter(a => a.status === 'active').map(a => a.agent_id);
    const parts = [`Opened ${fmtTime(inc.opened_at)}`];
    if (cut.length) parts.push(`Cut: ${cut.join(', ')}`);
    if (isolated.length) parts.push(`Isolated at gateway: ${isolated.join(', ')}`);
    parts.push(active.length ? `Still working: ${active.join(', ')}` : 'No agents running');
    parts.push(inc.notified ? 'Slack notified' : 'Notification logged');
    el('incident-meta').textContent = parts.join(' · ');
  }
  el('btn-approve').style.display = inc.status === 'pending_review' ? '' : 'none';
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
// Agent roster
// ─────────────────────────────────────────────────────────────────────────────
function renderRoster() {
  const flagged = new Set(S.analysis?.involved_agents || []);
  const agents = [...S.agents.values()];
  const active = agents.filter(a => a.status === 'active').length;
  el('roster-sub').textContent = agents.length ? `${active} of ${agents.length} agents active` : '';
  if (!agents.length) {
    el('roster-list').innerHTML = '<div class="empty">No agents registered. Press D, then Run scenario.</div>';
    return;
  }

  const agentRow = (a) => {
    const st = AGENT_STATUS[a.status] || { cls: '', label: a.status };
    return `
      <div class="agent-row${flagged.has(a.agent_id) ? ' flagged' : ''}" title="${esc(a.owner)} · ${a.llm_calls} LLM calls · last: ${esc(a.last_action || 'none')}">
        <span class="id">${flagged.has(a.agent_id) ? '▲ ' : ''}${esc(a.agent_id)}</span>
        <span class="task">${esc(a.declared_task)}</span>
        ${statusTag(st.cls, st.label)}
        <button class="mini" data-isolate="${esc(a.agent_id)}" ${a.status === 'active' ? '' : 'disabled'} title="Revoke this agent's AI Gateway token">Isolate</button>
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
  const ax = Math.min(130, W * 0.2), rx = W - Math.min(280, W * 0.4);
  const spread = (n, i) => n === 1 ? H / 2 : 36 + (i * (H - 72)) / (n - 1);
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
    const down = a && a.status !== 'active';
    const y = apos.get(id);
    nodes += `
      <g opacity="${down ? 0.45 : 1}">
        ${flagged.has(id) ? `<circle cx="${ax}" cy="${y}" r="14" fill="none" style="stroke:var(--critical)" stroke-width="2"/>` : ''}
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
  el('btn-run').addEventListener('click', () => post('/api/scenario/run', { speed: parseFloat(el('speed').value) }));
  el('btn-reset').addEventListener('click', () => post('/api/reset'));

  document.addEventListener('keydown', (e) => {
    if (e.key.toLowerCase() !== 'd' || e.metaKey || e.ctrlKey || e.altKey) return;
    if (['INPUT', 'SELECT', 'TEXTAREA'].includes(document.activeElement?.tagName)) return;
    el('director').classList.toggle('show');
  });

  window.addEventListener('resize', () => schedule(renderRiskChart, renderGraph));
}

// ─────────────────────────────────────────────────────────────────────────────
// Init: the stream's first message is a full snapshot, so no separate /api/state fetch.
// ─────────────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initControls();
  initRiskTooltip();
  connect();
});
