/* diagram.html: Map tab (Physical, Routing and VLAN views) and Findings tab (#63, #64).
   Our own plain JavaScript, inlined. It reads the JSON data block, draws inline SVG markup
   and never loads anything. Every value from the Topology passes through esc() before it
   becomes markup. Ids are looked up in Maps only, so an id can never reach an object's
   prototype. Nothing here decides a finding: markers and lists show only what topology.json
   records, and data it lacks stays unknown. */
'use strict';
(function () {
  const DATA = JSON.parse(document.getElementById('topology-data').textContent);
  const T = DATA.topology || {};
  const app = document.getElementById('app');

  /* ---------- plain helpers ---------- */
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const arr = v => (Array.isArray(v) ? v : []);
  const isUnk = v => !!v && typeof v === 'object' && !Array.isArray(v) && typeof v.unknown === 'string';
  const str = v => (typeof v === 'string' ? v : null);
  const num = v => (typeof v === 'number' && isFinite(v) ? v : null);
  function txt(v) {
    if (v === null || v === undefined) return '—';
    if (isUnk(v)) return 'unknown (' + v.unknown + ')';
    if (Array.isArray(v)) return v.length ? v.map(txt).join(', ') : 'none';
    if (typeof v === 'boolean') return v ? 'yes' : 'no';
    if (typeof v === 'object') return '—';
    return String(v);
  }
  const h = v => esc(txt(v));
  function ifn(name) {
    if (isUnk(name)) return '?';
    return name && typeof name === 'object' && typeof name.short === 'string' ? name.short : '?';
  }
  function ranges(v) {
    if (v === null || v === undefined) return '—';
    if (isUnk(v)) return 'unknown (' + v.unknown + ')';
    if (!Array.isArray(v)) return '—';
    if (!v.length) return 'none';
    if (v.length === 1 && Array.isArray(v[0]) && v[0][0] === 1 && v[0][1] === 4094) return 'all (1-4094)';
    return v.map(r => (Array.isArray(r) ? (r[0] === r[1] ? String(r[0]) : r[0] + '-' + r[1]) : txt(r))).join(',');
  }
  /* true or false for a list of [first, last] ranges; null when the list is not known */
  function inRanges(v, n) {
    if (!Array.isArray(v)) return null;
    return v.some(r => Array.isArray(r) && num(r[0]) !== null && num(r[1]) !== null && r[0] <= n && n <= r[1]);
  }
  const short = (s, n) => (s.length > n ? s.slice(0, n - 1) + '…' : s);

  /* ---------- the Topology, by id ---------- */
  const DEV = new Map(), UNV = new Map(), SEG = new Map(), LINK = new Map(), BUNDLE = new Map(), FINDING = new Map();
  const ADJ = new Map(), SUBNET = new Map();
  arr(T.devices).forEach(d => DEV.set(d.id, d));
  arr(T.unvisited).forEach(d => UNV.set(d.id, d));
  arr(T.segments).forEach(s => SEG.set(s.id, s));
  arr(T.links).forEach(l => LINK.set(l.id, l));
  arr(T.bundles).forEach(b => BUNDLE.set(b.id, b));
  arr(T.findings).forEach(f => FINDING.set(f.id, f));
  arr(T.adjacencies).forEach(a => ADJ.set(a.id, a));
  arr(T.subnets).forEach(s => SUBNET.set(s.id, s));
  const L3_RECORDED = Array.isArray(T.adjacencies) && Array.isArray(T.subnets);
  const POS = new Map(), SPOS = new Map();
  arr(DATA.layout && DATA.layout.positions).forEach(p => POS.set(p[0], { x: p[1], y: p[2] }));
  arr(DATA.layout && DATA.layout.subnets).forEach(p => SPOS.set(p[0], { x: p[1], y: p[2] }));
  const LABELS = arr(DATA.layout && DATA.layout.labels);
  const posOf = id => POS.get(id) || SPOS.get(id);

  function nameOf(id) {
    const d = DEV.get(id);
    if (d) return str(d.hostname) || str(d.management_ip) || id;
    const u = UNV.get(id);
    if (u) return str(u.label) || str(arr(u.advertised_ips)[0]) || id;
    if (SEG.has(id)) return 'Shared Segment';
    const s = SUBNET.get(id);
    if (s) return 'Subnet ' + txt(s.prefix);
    return id;
  }
  const endsOf = l => arr(l.ends).filter(e => e && typeof e.device === 'string');
  function portChannel(bundle, device) {
    for (const side of arr(bundle.sides)) for (const end of arr(side && side.ends)) {
      if (end && end.device === device) {
        if (end.port_channel === null) return 'no port-channel';
        return isUnk(end.port_channel) ? '?' : txt(end.port_channel);
      }
    }
    return '?';
  }
  const bundleIsVpc = b => arr(b.sides).some(s => s && typeof s.vpc === 'number');
  const STATUS = { confirmed: 'st-confirmed', 'one-sided': 'st-one-sided', inferred: 'st-inferred' };
  const statusClass = s => STATUS[s] || 'st-unknown';
  const isUnvisited = id => UNV.has(id);

  /* ---------- findings and markers (story 150) ---------- */
  const ONE_END = 'VLAN on one end only';
  const CONFLICT = 'conflicting evidence';
  const RED = new Set(['differing native VLAN', 'trunk facing access', 'differing access VLANs']);
  const MARK = {
    conflict: { t: '≠', cls: 'conflict', name: 'conflicting evidence' },
    bad: { t: '!', cls: 'bad', name: 'VLAN Mismatch' },
    noisy: { t: '~', cls: 'noisy', name: 'VLAN on one end only' },
    unknown: { t: '?', cls: 'unknown', name: 'not checked: data unknown' }
  };
  const ORDER = ['conflict', 'bad', 'noisy', 'unknown'];
  function markOf(f) {
    if (f.kind === CONFLICT) return 'conflict';
    if (RED.has(f.kind)) return 'bad';
    if (f.kind === ONE_END) return 'noisy';
    return null;
  }
  const FIND_BY_ITEM = new Map(), SKIP_BY_ITEM = new Map(), BAD_DEV = new Set();
  const addTo = (map, key, value) => { if (!map.has(key)) map.set(key, []); if (!map.get(key).includes(value)) map.get(key).push(value); };
  for (const f of FINDING.values()) {
    arr(f.items).forEach(i => { if (typeof i === 'string') addTo(FIND_BY_ITEM, i, f); });
    const m = markOf(f);
    if (m === 'bad' || m === 'conflict') arr(f.devices).forEach(d => BAD_DEV.add(d));
  }
  for (const group of [LINK, ADJ, SUBNET]) for (const item of group.values()) {
    arr(item.conflicts).forEach(fid => { const f = FINDING.get(fid); if (f) addTo(FIND_BY_ITEM, item.id, f); });
  }
  /* A VLAN check that could not run is a skipped row whose reason ends with the Link or Bundle id (#61). */
  const SKIP_SUBJECT = /\(((?:link|bundle)-[A-Za-z0-9._-]+)\)$/;
  const SKIPPED = arr(T.skipped).filter(r => r && typeof r.device === 'string');
  SKIPPED.forEach(r => {
    if (r.data !== 'vlan_mismatch') return;
    const m = SKIP_SUBJECT.exec(txt(r.reason));
    if (m && (LINK.has(m[1]) || BUNDLE.has(m[1]))) addTo(SKIP_BY_ITEM, m[1], r);
  });
  function markerFor(items) {
    const found = new Set();
    for (const i of items) {
      arr(FIND_BY_ITEM.get(i)).forEach(f => { const m = markOf(f); if (m) found.add(m); });
      if (SKIP_BY_ITEM.has(i)) found.add('unknown');
    }
    const best = ORDER.find(m => found.has(m));
    return best ? MARK[best] : null;
  }
  const skipText = r => txt(r.reason).replace(SKIP_SUBJECT, '').replace(/^VLAN check skipped: /, '').trim();

  /* ---------- the Physical view's lines ---------- */
  function physicalEdges() {
    const out = [], groups = new Map();
    for (const l of LINK.values()) {
      const ends = endsOf(l);
      if (ends.length !== 2) continue;
      const a = ends[0].device, b = ends[1].device;
      const bundle = typeof l.bundle === 'string' ? BUNDLE.get(l.bundle) : undefined;
      if (bundle) {
        const key = l.bundle + '|' + [a, b].sort().join('|');
        if (!groups.has(key)) groups.set(key, { bundle, a, b, links: [] });
        groups.get(key).links.push(l);
        continue;
      }
      const cls = [statusClass(l.status)];
      let mid = '';
      if (l.role === 'vPC peer-keepalive') { cls.push('keepalive'); mid = 'vPC keepalive'; }
      if (l.role === 'vPC peer-link') mid = 'vPC peer-link';
      const ai = ifn(ends[0].interface), bi = ifn(ends[1].interface);
      out.push({ id: l.id, a, b, ai, bi, pa: ai, pb: bi, cls, mid, items: [l.id], ref: { type: 'link', link: l } });
    }
    let n = 0;
    for (const g of groups.values()) {
      const b = g.bundle, na = portChannel(b, g.a), nb = portChannel(b, g.b);
      const statuses = new Set(g.links.map(l => l.status));
      const status = statuses.size === 1 ? [...statuses][0] : (statuses.has('one-sided') ? 'one-sided' : 'mixed');
      let mid = (na === nb ? na : na + ' / ' + nb) + ' ×' + g.links.length;
      if (bundleIsVpc(b)) mid += ' vPC';
      if (b.role === 'vPC peer-link') mid += ' peer-link';
      out.push({ id: 'bundle~' + (n++), a: g.a, b: g.b, ai: na, bi: nb, pa: na, pb: nb, cls: ['bundle', statusClass(status)], mid,
        items: [b.id, ...g.links.map(l => l.id)], ref: { type: 'bundle', bundle: b, a: g.a, b: g.b, links: g.links } });
    }
    for (const s of SEG.values()) {
      arr(s.ports).forEach((p, i) => {
        if (!p || typeof p.device !== 'string') return;
        const bi = ifn(p.interface);
        out.push({ id: s.id + '~' + i, a: s.id, b: p.device, ai: '', bi, pa: null, pb: bi, cls: ['segment'], mid: '', items: [s.id], ref: { type: 'segment', segment: s } });
      });
    }
    out.forEach(e => { e.mark = markerFor(e.items); });
    return out;
  }
  const EDGES = physicalEdges();
  const edgesOfItem = id => EDGES.filter(e => e.items.includes(id));

  /* ---------- the Routing view (story 147) ---------- */
  const L3_MEMBERS = new Set();
  for (const a of ADJ.values()) endsOf(a).forEach(e => L3_MEMBERS.add(e.device));
  for (const s of SUBNET.values()) arr(s.attachments).forEach(x => { if (x && typeof x.device === 'string') L3_MEMBERS.add(x.device); });
  function hasL3(d) {
    if (!Array.isArray(d.interfaces)) return true; /* unknown: never faded for it */
    return d.interfaces.some(i => i && i.ip && typeof i.ip === 'object' && (isUnk(i.ip) || arr(i.ip.addresses).length > 0 || i.ip.unnumbered === true));
  }
  function routingEdges() {
    const out = [];
    for (const s of SUBNET.values()) {
      const seen = new Set();
      arr(s.attachments).forEach(x => {
        if (!x || typeof x.device !== 'string' || seen.has(x.device)) return;
        seen.add(x.device);
        out.push({ id: s.id + '>' + x.device, a: s.id, b: x.device, ai: '', bi: ifn(x.interface), cls: ['l3m'], mid: '', items: [s.id],
          mark: markerFor([s.id]), ref: { type: 'subnet', subnet: s } });
      });
    }
    for (const a of ADJ.values()) {
      const ends = endsOf(a);
      if (ends.length !== 2) continue;
      const shared = a.kind === 'shared subnet';
      const names = e => arr(e.interfaces).map(ifn).join(', ');
      out.push({ id: a.id, a: ends[0].device, b: ends[1].device, ai: names(ends[0]), bi: names(ends[1]), cls: ['l3', shared ? 'shared' : 'proto'],
        mid: shared ? txt(a.prefix) : txt(a.kind), items: [a.id], mark: markerFor([a.id]), ref: { type: 'adjacency', adjacency: a } });
    }
    return out;
  }
  const L3_EDGES = routingEdges();

  /* ---------- the VLAN view (story 148) ---------- */
  function interfaceOf(device, port) {
    const d = DEV.get(device);
    if (!d) return null;
    return arr(d.interfaces).find(i => i && ifn(i.name) === port) || null;
  }
  /* Does this end carry VLAN v? true, false, or null when it cannot be told. Effective VLANs
     on a trunk are the allowed ones also in the VLAN database, as #61 reads them. */
  function carries(device, port, v) {
    const d = DEV.get(device);
    if (!d || !port || port === '?') return null;
    const i = interfaceOf(device, port);
    if (!i) return null;
    if (i.mode === 'access') return num(i.access_vlan) === null ? null : i.access_vlan === v;
    if (i.mode === 'trunk') {
      const allowed = inRanges(i.allowed_vlans, v);
      if (allowed !== true) return allowed;
      return inRanges(d.vlan_database, v);
    }
    if (i.mode === 'routed' || i.mode === 'other') return false;
    return null;
  }
  function effective(device, port) {
    const i = interfaceOf(device, port), d = DEV.get(device);
    if (!d || !i) return null;
    if (i.mode === 'access') return num(i.access_vlan) === null ? null : [[i.access_vlan, i.access_vlan]];
    if (i.mode !== 'trunk') return [];
    if (!Array.isArray(i.allowed_vlans) || !Array.isArray(d.vlan_database)) return null;
    const out = [];
    for (const r of i.allowed_vlans) for (const q of d.vlan_database) {
      if (!Array.isArray(r) || !Array.isArray(q)) continue;
      const lo = Math.max(r[0], q[0]), hi = Math.min(r[1], q[1]);
      if (lo <= hi) out.push([lo, hi]);
    }
    return out.sort((x, y) => x[0] - y[0]);
  }
  function vlanState(e, v) {
    const ca = e.pa === null ? null : carries(e.a, e.pa, v), cb = carries(e.b, e.pb, v);
    if (ca === true && cb === true) return 'vlan-on';
    if ((ca === true && cb === false) || (ca === false && cb === true)) return 'vlan-break';
    if (ca === true || cb === true) return 'vlan-unk';
    return 'vlan-off';
  }
  const VLANS = (function () {
    const found = new Set();
    for (const d of DEV.values()) {
      arr(d.vlan_database).forEach(r => { if (Array.isArray(r) && r[1] - r[0] < 4094) for (let n = r[0]; n <= r[1]; n++) found.add(n); });
      arr(d.interfaces).forEach(i => { if (!i) return; [i.access_vlan, i.native_vlan].forEach(n => { if (num(n) !== null) found.add(n); }); });
    }
    return [...found].filter(n => n >= 1 && n <= 4094).sort((x, y) => x - y);
  })();

  /* ---------- what is on screen ---------- */
  const S = { tab: 'map', view: 'physical', vlan: VLANS.find(n => n !== 1) || VLANS[0] || null, pick: null, sel: null, filter: '' };
  const REG = new Map();

  function deviceNodes(ids, extra) {
    const nodes = [];
    for (const id of ids) {
      const d = DEV.get(id), u = UNV.get(id);
      const add = extra ? ' ' + extra(id) : '';
      if (d) {
        const plat = str(d.platform) || '';
        const cls = (plat === 'NX-OS' ? 'nx' : 'xe') + (d.outcome === 'partial' ? ' partial' : '') + (BAD_DEV.has(id) ? ' has-bad' : '');
        nodes.push({ id, shape: 'dev', cls: cls + add, t: nameOf(id), s: str(d.model) || '', plat, ref: { type: 'device', id } });
      } else if (u) {
        nodes.push({ id, shape: 'dev', cls: 'unv' + add, t: nameOf(id), s: str(u.reason) || 'reason not recorded', plat: '', ref: { type: 'device', id } });
      } else if (SEG.has(id)) {
        nodes.push({ id, shape: 'seg', cls: add.trim(), ref: { type: 'device', id } });
      } else if (SUBNET.has(id)) {
        const s = SUBNET.get(id);
        nodes.push({ id, shape: 'subnet', cls: add.trim(), t: txt(s.prefix) + ' · ' + txt(s.vrf), ref: { type: 'subnet', subnet: s } });
      }
    }
    return nodes;
  }
  const ALL_NODES = () => [...DEV.keys(), ...UNV.keys(), ...SEG.keys()];
  const picked = id => !!S.pick && S.pick.id === id;

  function physicalScene() {
    const edges = EDGES.filter(e => (!isUnvisited(e.a) && !isUnvisited(e.b)) || picked(e.a) || picked(e.b) || picked(e.id));
    return { nodes: deviceNodes(ALL_NODES()), edges: edges.map(e => Object.assign({}, e, { badge: e.mark })), labels: LABELS };
  }
  function routingScene() {
    const ids = [...DEV.keys(), ...[...UNV.keys(), ...SEG.keys()].filter(id => L3_MEMBERS.has(id)), ...[...SUBNET.keys()].filter(id => SPOS.has(id))];
    const faded = id => (L3_RECORDED && DEV.has(id) && !L3_MEMBERS.has(id) && !hasL3(DEV.get(id)) ? 'faded' : '');
    return { nodes: deviceNodes(ids, faded), edges: L3_EDGES.map(e => Object.assign({}, e, { badge: e.mark })), labels: [] };
  }
  function vlanScene() {
    const v = S.vlan;
    const states = new Map(EDGES.map(e => [e.id, v === null ? 'vlan-off' : vlanState(e, v)]));
    const edges = EDGES.filter(e => (!isUnvisited(e.a) && !isUnvisited(e.b)) || states.get(e.id) !== 'vlan-off' || picked(e.a) || picked(e.b) || picked(e.id))
      .map(e => Object.assign({}, e, { cls: e.cls.concat(states.get(e.id)), badge: null }));
    const faded = id => {
      const d = DEV.get(id);
      if (!d || v === null) return 'faded';
      return inRanges(d.vlan_database, v) === false ? 'faded' : '';
    };
    const count = s => edges.filter(e => e.cls.includes(s)).length;
    return { nodes: deviceNodes(ALL_NODES(), faded), edges, labels: LABELS, counts: { on: count('vlan-on'), br: count('vlan-break'), un: count('vlan-unk') } };
  }
  /* The Findings tab draws only the selection's neighbourhood, each device where the Map puts it. */
  function neighbourhoodScene() {
    const sel = S.sel;
    if (!sel) return { nodes: [], edges: [], labels: [] };
    const centres = new Set(sel.centres.filter(id => posOf(id)));
    const edges = EDGES.filter(e => centres.has(e.a) || centres.has(e.b));
    const ids = new Set(centres);
    edges.forEach(e => { ids.add(e.a); ids.add(e.b); });
    const focus = new Set(sel.focus || []);
    return {
      nodes: deviceNodes([...ids], id => (centres.has(id) ? 'centre' : '')),
      edges: edges.map(e => Object.assign({}, e, { badge: e.mark, cls: focus.has(e.id) ? e.cls.concat('focus') : e.cls })),
      labels: []
    };
  }
  function scene() {
    if (S.tab === 'findings') return neighbourhoodScene();
    if (S.view === 'routing') return routingScene();
    if (S.view === 'vlan') return vlanScene();
    return physicalScene();
  }

  /* ---------- drawing ---------- */
  function curve(p1, p2, off) {
    const dx = p2.x - p1.x, dy = p2.y - p1.y, len = Math.hypot(dx, dy) || 1, nx = -dy / len, ny = dx / len;
    const cx = (p1.x + p2.x) / 2 + nx * off * 2, cy = (p1.y + p2.y) / 2 + ny * off * 2;
    const at = t => ({ x: (1 - t) * (1 - t) * p1.x + 2 * (1 - t) * t * cx + t * t * p2.x, y: (1 - t) * (1 - t) * p1.y + 2 * (1 - t) * t * cy + t * t * p2.y });
    const slope = t => ({ x: 2 * (1 - t) * (cx - p1.x) + 2 * t * (p2.x - cx), y: 2 * (1 - t) * (cy - p1.y) + 2 * t * (p2.y - cy) });
    const f = n => n.toFixed(1);
    return { d: 'M' + f(p1.x) + ',' + f(p1.y) + ' Q' + f(cx) + ',' + f(cy) + ' ' + f(p2.x) + ',' + f(p2.y), at, slope, len, dx, dy };
  }

  function endLabel(c, text, fromA) {
    /* the name starts at its device's box edge and runs along the line */
    const ux = Math.abs(c.dx) / c.len, uy = Math.abs(c.dy) / c.len;
    const edge = Math.min(ux > 0.01 ? 66 / ux : 1e9, uy > 0.01 ? 22 / uy : 1e9) + 6;
    const t0 = Math.min(0.45, (edge + text.length * 3.1) / c.len), t = fromA ? t0 : 1 - t0;
    const q = c.at(t), s = c.slope(t);
    let ang = Math.atan2(s.y, s.x) * 180 / Math.PI;
    if (ang > 90) ang -= 180; else if (ang <= -90) ang += 180;
    const x = q.x.toFixed(1), y = q.y.toFixed(1);
    return '<text class="lbl" x="' + x + '" y="' + y + '" dy="-2.5" text-anchor="middle" transform="rotate(' + ang.toFixed(1) + ' ' + x + ' ' + y + ')">' + esc(text) + '</text>';
  }
  const boxless = id => SEG.has(id) || SUBNET.has(id);

  function render(g, sc) {
    let out = '';
    const count = new Map(), index = new Map();
    const pairKey = e => (e.a < e.b ? e.a + '|' + e.b : e.b + '|' + e.a);
    sc.edges.forEach(e => count.set(pairKey(e), (count.get(pairKey(e)) || 0) + 1));
    REG.clear();
    for (const e of sc.edges) {
      const p1 = posOf(e.a), p2 = posOf(e.b);
      if (!p1 || !p2) continue;
      REG.set(e.id, e.ref);
      const k = pairKey(e), n = count.get(k), i = index.get(k) || 0;
      index.set(k, i + 1);
      let off = (i - (n - 1) / 2) * 16;
      if (e.a > e.b) off = -off;
      const c = curve(p1, p2, off);
      const cls = e.cls.slice();
      if (isUnvisited(e.a) || isUnvisited(e.b)) cls.push('to-unv');
      if (e.badge) cls.push('mk-' + e.badge.cls);
      if (picked(e.id)) cls.push('sel');
      out += '<g class="edge ' + cls.join(' ') + '" data-id="' + esc(e.id) + '"><title>' + esc(nameOf(e.a) + ' ' + e.ai + ' ⇄ ' + nameOf(e.b) + ' ' + e.bi) + '</title>' +
        '<path class="hit" d="' + c.d + '"/><path class="ln" d="' + c.d + '"/>' + (cls.includes('bundle') ? '<path class="ln2" d="' + c.d + '"/>' : '');
      const m = c.at(0.5);
      if (e.mid) out += '<text class="lbl mid" x="' + m.x.toFixed(1) + '" y="' + (m.y - (e.badge ? 12 : 5)).toFixed(1) + '" text-anchor="middle">' + esc(e.mid) + '</text>';
      if (e.ai && !boxless(e.a)) out += endLabel(c, e.ai, true);
      if (e.bi && !boxless(e.b)) out += endLabel(c, e.bi, false);
      if (e.badge) out += '<g class="badge ' + e.badge.cls + '" transform="translate(' + m.x.toFixed(1) + ',' + m.y.toFixed(1) + ')"><title>' + esc(e.badge.name) + '</title><circle r="8"/><text y="4" text-anchor="middle">' + esc(e.badge.t) + '</text></g>';
      out += '</g>';
    }
    for (const l of sc.labels) {
      out += '<text class="lane' + (l.heading ? ' h' : '') + '" x="' + Number(l.x).toFixed(1) + '" y="' + Number(l.y).toFixed(1) + '">' + esc(txt(l.text)) + '</text>';
    }
    for (const n of sc.nodes) {
      const p = posOf(n.id);
      if (!p) continue;
      REG.set(n.id, n.ref);
      const sel = picked(n.id) ? ' sel' : '';
      const tr = ' transform="translate(' + p.x.toFixed(1) + ',' + p.y.toFixed(1) + ')"';
      if (n.shape === 'seg') {
        out += '<g class="node seg ' + n.cls + sel + '" data-id="' + esc(n.id) + '"' + tr + '><title>Shared Segment: something the tool cannot see, such as an unmanaged switch</title>' +
          '<circle r="15"/><text class="t" y="4" text-anchor="middle">?</text><text class="s" y="29" text-anchor="middle">Shared Segment</text></g>';
        continue;
      }
      if (n.shape === 'subnet') {
        const w = Math.max(96, n.t.length * 6.4 + 18);
        out += '<g class="node subnet ' + n.cls + sel + '" data-id="' + esc(n.id) + '"' + tr + '><title>Subnet shared by three or more devices</title>' +
          '<rect x="' + (-w / 2).toFixed(1) + '" y="-11" width="' + w.toFixed(1) + '" height="22" rx="11"/><text class="t" y="4" text-anchor="middle">' + esc(n.t) + '</text></g>';
        continue;
      }
      out += '<g class="node ' + n.cls + sel + '" data-id="' + esc(n.id) + '"' + tr + '><title>' + esc(n.t) + '</title><rect x="-64" y="-20" width="128" height="40" rx="6"/>' +
        '<text class="t" y="-3" text-anchor="middle">' + esc(short(n.t, 20)) + '</text><text class="s" y="12" text-anchor="middle">' +
        (n.plat ? '<tspan class="plat">' + esc(n.plat) + '</tspan> ' : '') + esc(short(n.s, n.plat ? 14 : 26)) + '</text></g>';
    }
    g.innerHTML = out;
  }

  function boundsOf(sc) {
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    sc.nodes.forEach(n => { const p = posOf(n.id); if (!p) return; x0 = Math.min(x0, p.x - 70); x1 = Math.max(x1, p.x + 70); y0 = Math.min(y0, p.y - 30); y1 = Math.max(y1, p.y + 40); });
    sc.labels.forEach(l => { x0 = Math.min(x0, l.x); y0 = Math.min(y0, l.y - 16); x1 = Math.max(x1, l.x + 340); });
    return isFinite(x0) ? { x0, y0, x1, y1 } : { x0: -100, y0: -100, x1: 100, y1: 100 };
  }

  function attachCanvas(svg, onPick) {
    const g = svg.querySelector('.vp'), s = { x: 0, y: 0, k: 1 };
    const apply = () => {
      g.setAttribute('transform', 'translate(' + s.x.toFixed(1) + ' ' + s.y.toFixed(1) + ') scale(' + s.k.toFixed(4) + ')');
      svg.classList.toggle('far', s.k < 0.45);
    };
    let drag = null, moved = false;
    svg.addEventListener('pointerdown', e => { drag = { x: e.clientX, y: e.clientY, sx: s.x, sy: s.y, id: e.pointerId }; moved = false; });
    svg.addEventListener('pointermove', e => {
      if (!drag) return;
      const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
      if (!moved && Math.abs(dx) + Math.abs(dy) > 4) { moved = true; try { svg.setPointerCapture(drag.id); } catch (_) { /* not captured */ } }
      if (moved) { s.x = drag.sx + dx; s.y = drag.sy + dy; apply(); }
    });
    const end = () => { drag = null; };
    svg.addEventListener('pointerup', end);
    svg.addEventListener('pointercancel', end);
    svg.addEventListener('click', e => {
      if (moved) { moved = false; return; }
      const t = e.target.closest('[data-id]');
      onPick(t ? t.getAttribute('data-id') : null);
    });
    const zoomAt = (f, mx, my) => {
      const nk = Math.min(4, Math.max(0.05, s.k * f));
      s.x = mx - (mx - s.x) * (nk / s.k); s.y = my - (my - s.y) * (nk / s.k); s.k = nk; apply();
    };
    svg.addEventListener('wheel', e => {
      e.preventDefault();
      const r = svg.getBoundingClientRect();
      zoomAt(Math.exp(-e.deltaY * 0.0015), e.clientX - r.left, e.clientY - r.top);
    }, { passive: false });
    return {
      fit(b) {
        const r = svg.getBoundingClientRect();
        if (!r.width || !r.height) return;
        const bw = b.x1 - b.x0, bh = b.y1 - b.y0, k = Math.min((r.width - 40) / bw, (r.height - 40) / bh, 1.25);
        s.k = k; s.x = r.width / 2 - k * (b.x0 + bw / 2); s.y = r.height / 2 - k * (b.y0 + bh / 2); apply();
      },
      zoom(f) { const r = svg.getBoundingClientRect(); zoomAt(f, r.width / 2, r.height / 2); },
      centerOn(p) { const r = svg.getBoundingClientRect(); s.k = Math.max(s.k, 0.9); s.x = r.width / 2 - s.k * p.x; s.y = r.height / 2 - s.k * p.y; apply(); }
    };
  }

  /* ---------- details, docked below the drawing ---------- */
  const row = (k, v) => '<dt>' + esc(k) + '</dt><dd>' + v + '</dd>';
  const table = (heads, rows) => '<div class="tblwrap"><table><tr>' + heads.map(x => '<th>' + esc(x) + '</th>').join('') + '</tr>' +
    (rows.length ? rows.join('') : '<tr><td colspan="' + heads.length + '">none</td></tr>') + '</table></div>';
  const td = (v, mono) => '<td' + (mono ? ' class="mono"' : '') + '>' + v + '</td>';
  function evidenceList(items) {
    const lines = arr(items).map(e => '<li>' + esc(nameOf(txt(e.device))) + ': ' + h(e.source) + ', <span class="mono">' + h(e.command) + '</span></li>');
    return lines.length ? '<ul>' + lines.join('') + '</ul>' : '<p class="note">none recorded</p>';
  }
  function findingBox(f) {
    const m = markOf(f);
    return '<div class="find ' + (m || 'other') + '">' + (m ? '<b class="mk">' + esc(MARK[m].t) + '</b> ' : '') + '<b>' + h(f.kind) + '.</b> ' + h(f.summary) + '</div>';
  }
  function itemBoxes(items) {
    const seen = new Set(), boxes = [];
    items.forEach(i => arr(FIND_BY_ITEM.get(i)).forEach(f => { if (!seen.has(f.id)) { seen.add(f.id); boxes.push(findingBox(f)); } }));
    const skips = items.flatMap(i => arr(SKIP_BY_ITEM.get(i)));
    if (skips.length) {
      boxes.push('<div class="find unknown"><b class="mk">?</b> <b>Not checked: data unknown.</b> ' +
        esc([...new Set(skips.map(r => nameOf(r.device) + ': ' + skipText(r)))].join('; ')) + '</div>');
    }
    return boxes.join('');
  }
  function vlanTable(columns) {
    /* columns: [{device, port}] side by side */
    const cells = columns.map(c => ({ c, i: interfaceOf(c.device, c.port) }));
    const line = (label, f) => '<tr><td>' + esc(label) + '</td>' + cells.map(x => td(x.i ? esc(f(x)) : (DEV.has(x.c.device) ? 'not recorded' : 'not a Visited Device'), true)).join('') + '</tr>';
    return '<div class="tblwrap"><table><tr><th></th>' + cells.map(x => '<th>' + esc(nameOf(x.c.device)) + ' <span class="mono">' + esc(x.c.port) + '</span></th>').join('') + '</tr>' +
      line('Mode', x => txt(x.i.mode)) + line('Allowed VLANs', x => ranges(x.i.allowed_vlans)) + line('Native VLAN', x => txt(x.i.native_vlan)) +
      line('Access VLAN', x => txt(x.i.access_vlan)) +
      line('Effective', x => { const e = effective(x.c.device, x.c.port); return e === null ? 'unknown' : ranges(e); }) +
      line('Status', x => (x.i.line_up === true ? 'up' : x.i.line_up === false ? 'down' : txt(x.i.line_up))) +
      '</table></div><p class="note">Effective = allowed and present in that switch\'s VLAN database.</p>';
  }

  function deviceDetail(id) {
    const d = DEV.get(id);
    if (d) return visitedDetail(d);
    const u = UNV.get(id);
    if (u) return unvisitedDetail(u);
    const s = SEG.get(id);
    return s ? segmentDetail(s) : '';
  }
  function visitedDetail(d) {
    const links = [];
    for (const e of EDGES) {
      if (e.ref.type === 'segment') continue;
      const me = e.a === d.id ? 'a' : e.b === d.id ? 'b' : null;
      if (!me) continue;
      const far = me === 'a' ? e.b : e.a;
      const status = e.ref.type === 'link' ? txt(e.ref.link.status) + (e.ref.link.role ? ' · ' + txt(e.ref.link.role) : '') : 'Bundle ' + e.mid;
      links.push('<tr>' + td(esc(me === 'a' ? e.ai : e.bi), true) + td(esc(nameOf(far)) + ' <span class="mono">' + esc(me === 'a' ? e.bi : e.ai) + '</span>') +
        td(esc(status) + (e.mark ? ' <span class="pill ' + e.mark.cls + '">' + esc(e.mark.t + ' ' + e.mark.name) + '</span>' : '')) + '</tr>');
    }
    for (const s of SEG.values()) arr(s.ports).forEach(p => {
      if (p && p.device === d.id) links.push('<tr>' + td(esc(ifn(p.interface)), true) + td('Shared Segment') + td('hears two or more Neighbours') + '</tr>');
    });
    const l3 = arr(d.interfaces).filter(i => i && i.ip && typeof i.ip === 'object' && !isUnk(i.ip) && arr(i.ip.addresses).length)
      .map(i => '<tr>' + td(esc(ifn(i.name)), true) + td(h(i.ip.addresses), true) + td(h(i.ip.vrf)) + '</tr>');
    const adj = [...ADJ.values()].filter(a => endsOf(a).some(e => e.device === d.id)).map(a => {
      const far = endsOf(a).find(e => e.device !== d.id);
      return '<tr>' + td(h(a.kind)) + td(esc(far ? nameOf(far.device) : '?')) + td(h(a.vrf)) + td(a.kind === 'shared subnet' ? h(a.prefix) : '—', true) + '</tr>';
    });
    const subnets = [...SUBNET.values()].filter(s => arr(s.attachments).some(x => x && x.device === d.id))
      .map(s => '<tr>' + td('Subnet') + td(esc(String(arr(s.attachments).length)) + ' attachments') + td(h(s.vrf)) + td(h(s.prefix), true) + '</tr>');
    const skipped = SKIPPED.filter(r => r.device === d.id && r.data !== 'vlan_mismatch').map(r => '<tr>' + td(h(r.data), true) + td(h(r.reason)) + '</tr>');
    const findings = [...FINDING.values()].filter(f => arr(f.devices).includes(d.id)).map(findingBox).join('');
    const stack = arr(d.stack_members).map(m => txt(m.number) + ': ' + txt(m.model) + ' ' + txt(m.serial));
    const vpc = d.vpc && typeof d.vpc === 'object' && !isUnk(d.vpc)
      ? row('vPC domain', h(d.vpc.domain) + ', peer-link <span class="mono">' + esc(ifn(d.vpc.peer_link)) + '</span>') : (isUnk(d.vpc) ? row('vPC', h(d.vpc)) : '');
    return '<div class="det"><div><h3>' + esc(nameOf(d.id)) + '</h3><span class="pill acc">Visited Device</span>' +
      (d.outcome === 'partial' ? '<span class="pill bad">partial: ' + h(d.partial_reason) + '</span>' : '') +
      (BAD_DEV.has(d.id) ? '<span class="pill bad">has a VLAN Mismatch or conflict</span>' : '') + findings + '<dl>' +
      row('Platform', h(d.platform)) + row('Model', h(d.model)) + row('Software', '<span class="mono">' + h(d.software_version) + '</span>') +
      row('Serials', '<span class="mono">' + h(d.serials) + '</span>') + (stack.length ? row('Stack members', esc(stack.join('; '))) : '') +
      row('Logged into at', '<span class="mono">' + h(d.management_ip) + '</span>') + row('Alias IPs', '<span class="mono">' + h(d.alias_ips) + '</span>') + vpc +
      row('VLAN database', '<span class="mono">' + esc(ranges(d.vlan_database)) + '</span>') +
      row('Id', '<span class="mono">' + esc(d.id) + '</span>') + '</dl></div>' +
      '<div><h4>Interfaces with a Link</h4>' + table(['Local', 'Far end', 'Status'], links) + '</div>' +
      (l3.length ? '<div><h4>L3 interfaces</h4>' + table(['Interface', 'Addresses', 'VRF'], l3) + '</div>' : '') +
      (adj.length || subnets.length ? '<div><h4>L3 Adjacencies</h4>' + table(['Kind', 'With', 'VRF', 'Prefix'], adj.concat(subnets)) + '</div>' : '') +
      (skipped.length ? '<div><h4>Not collected, so not checked</h4>' + table(['Data', 'Reason'], skipped) + '</div>' : '') +
      '<p class="note">topology.json also records every other interface on this device, down ones included. This view lists only those with a Link or an IP.</p></div>';
  }
  function unvisitedDetail(u) {
    const reporters = arr(u.reported_by).map(r => esc(nameOf(txt(r.device))) + ' <span class="mono">' + esc(ifn(r.interface)) + '</span> (' + h(r.evidence && r.evidence.source) + ')');
    return '<div class="det"><div><h3>' + esc(nameOf(u.id)) + '</h3><span class="pill unv">Unvisited Device</span><dl>' +
      row('Reason', '<b>' + h(u.reason) + '</b>') + row('Advertised Platform', h(u.advertised_platform)) +
      row('Advertised IPs', '<span class="mono">' + h(u.advertised_ips) + '</span>') +
      (arr(u.advertised_ipv6).length ? row('Advertised IPv6', '<span class="mono">' + h(u.advertised_ipv6) + '</span>') : '') +
      row('LLDP chassis ID', '<span class="mono">' + h(u.chassis_id) + '</span>') +
      row('Reported by', reporters.join('<br>') || 'none') + row('Id', '<span class="mono">' + esc(u.id) + '</span>') + '</dl></div></div>';
  }
  function segmentDetail(s) {
    const ports = arr(s.ports).map(p => '<tr>' + td(esc(nameOf(txt(p.device)))) + td(esc(ifn(p.interface)), true) + '</tr>');
    return '<div class="det"><div><h3>Shared Segment</h3><span class="pill unv">not a device the tool can see</span>' + itemBoxes([s.id]) +
      '<p class="note">A port hears two or more Neighbours, so something unmanaged (a switch, hub or virtual switch) sits between them.</p></div>' +
      '<div><h4>Ports on it</h4>' + table(['Device', 'Port'], ports) + '</div><div><h4>Evidence</h4>' + evidenceList(s.evidence) + '</div></div>';
  }
  function linkDetail(l) {
    const ends = endsOf(l), a = ends[0], b = ends[1];
    const bundle = typeof l.bundle === 'string' ? BUNDLE.get(l.bundle) : undefined;
    return '<div class="det"><div><h3>' + esc(nameOf(a.device) + ' ' + ifn(a.interface) + ' ⇄ ' + nameOf(b.device) + ' ' + ifn(b.interface)) + '</h3>' +
      '<span class="pill ' + (l.status === 'confirmed' ? 'ok' : 'unv') + '">Link · ' + h(l.status) + '</span>' +
      (l.role ? '<span class="pill acc">' + h(l.role) + '</span>' : '') +
      (bundle ? '<span class="pill acc">member of ' + esc(portChannel(bundle, a.device)) + '</span>' : '') +
      (arr(l.conflicts).length ? '<span class="pill conflict">conflicting evidence</span>' : '') + itemBoxes([l.id]) +
      '<dl>' + row('Id', '<span class="mono">' + esc(l.id) + '</span>') + '</dl>' +
      '<h4>Evidence</h4>' + evidenceList(l.evidence) + '</div>' +
      '<div><h4>VLANs</h4>' + vlanTable([{ device: a.device, port: ifn(a.interface) }, { device: b.device, port: ifn(b.interface) }]) + '</div></div>';
  }
  function bundleDetail(ref) {
    const b = ref.bundle, na = portChannel(b, ref.a), nb = portChannel(b, ref.b);
    const flagged = new Set(arr(b.flagged));
    const members = ref.links.map(l => {
      const ends = endsOf(l);
      const mine = ends.find(e => e.device === ref.a) || ends[0], far = ends.find(e => e !== mine) || ends[1];
      return '<tr>' + td(esc(ifn(mine.interface)), true) + td(esc(ifn(far.interface)), true) + td(h(l.status) + (flagged.has(l.id) ? ' <span class="pill bad">flagged</span>' : '')) + '</tr>';
    });
    const sides = arr(b.sides).map(s => arr(s && s.ends).map(e => esc(nameOf(txt(e.device))) + ' <span class="mono">' + esc(portChannel(b, e.device)) + '</span>').join(' + ') +
      (s && typeof s.vpc === 'number' ? ' (vPC ' + esc(String(s.vpc)) + ')' : ''));
    const columns = [];
    arr(b.sides).forEach(s => arr(s && s.ends).forEach(e => { if (e && typeof e.device === 'string') columns.push({ device: e.device, port: portChannel(b, e.device) }); }));
    return '<div class="det"><div><h3>' + esc(nameOf(ref.a) + ' ' + na + ' ⇄ ' + nameOf(ref.b) + ' ' + nb) + '</h3>' +
      '<span class="pill ok">Bundle · ' + esc(String(ref.links.length)) + ' member' + (ref.links.length === 1 ? '' : 's') + ' here</span>' +
      (bundleIsVpc(b) ? '<span class="pill acc">vPC</span>' : '') + (b.role ? '<span class="pill acc">' + h(b.role) + '</span>' : '') +
      itemBoxes([b.id, ...ref.links.map(l => l.id)]) + '<dl>' + row('Sides', sides.join('<br>')) + row('Id', '<span class="mono">' + esc(b.id) + '</span>') + '</dl>' +
      '<h4>Member Links here</h4>' + table([nameOf(ref.a), nameOf(ref.b), 'Status'], members) +
      '<h4>Evidence</h4>' + evidenceList(ref.links.flatMap(l => arr(l.evidence))) + '</div>' +
      '<div><h4>VLANs</h4>' + vlanTable(columns) + '</div></div>';
  }
  function subnetDetail(s) {
    const rows = arr(s.attachments).filter(x => x && typeof x.device === 'string')
      .map(x => '<tr>' + td(esc(nameOf(x.device))) + td(esc(ifn(x.interface)), true) + td(h(x.address), true) + '</tr>');
    return '<div class="det"><div><h3 class="mono">' + h(s.prefix) + '</h3><span class="pill l3">Subnet · VRF ' + h(s.vrf) + '</span>' + itemBoxes([s.id]) +
      '<p class="note">A prefix three or more devices share in one VRF: one node each device attaches to.</p>' +
      '<dl>' + row('Id', '<span class="mono">' + esc(s.id) + '</span>') + '</dl></div>' +
      '<div><h4>Attached interfaces</h4>' + table(['Device', 'Interface', 'Address'], rows) + '</div><div><h4>Evidence</h4>' + evidenceList(s.evidence) + '</div></div>';
  }
  function adjacencyDetail(a) {
    const rows = endsOf(a).map(e => '<tr>' + td(esc(nameOf(e.device))) + td(esc(arr(e.interfaces).map(ifn).join(', ') || 'none named'), true) + '</tr>');
    return '<div class="det"><div><h3>' + esc(endsOf(a).map(e => nameOf(e.device)).join(' ⇄ ')) + '</h3><span class="pill l3">L3 Adjacency · ' + h(a.kind) + '</span>' + itemBoxes([a.id]) +
      '<dl>' + row('VRF', h(a.vrf)) + (a.kind === 'shared subnet' ? row('Prefix', '<span class="mono">' + h(a.prefix) + '</span>') : '') +
      row('Id', '<span class="mono">' + esc(a.id) + '</span>') + '</dl></div>' +
      '<div><h4>Learned on</h4>' + table(['Device', 'Interfaces'], rows) + '</div><div><h4>Evidence</h4>' + evidenceList(a.evidence) + '</div></div>';
  }
  function findingDetail(f) {
    const items = arr(f.items).filter(i => typeof i === 'string');
    const first = items.map(i => edgesOfItem(i)[0]).find(Boolean);
    const named = items.map(i => (LINK.has(i) || BUNDLE.has(i) ? i : nameOf(i)));
    return '<div class="det"><div><h3>' + h(f.kind) + '</h3>' + findingBox(f) + '<dl>' +
      row('Devices', esc(arr(f.devices).map(d => nameOf(d)).join(', ') || 'none named')) +
      row('Concerns', '<span class="mono">' + esc(named.join(', ') || 'none named') + '</span>') +
      row('Id', '<span class="mono">' + esc(f.id) + '</span>') + '</dl><h4>Evidence</h4>' + evidenceList(f.evidence) + '</div></div>' +
      (first ? refDetail(first.ref) : '');
  }
  function refDetail(r) {
    if (r.type === 'device') return deviceDetail(r.id);
    if (r.type === 'link') return linkDetail(r.link);
    if (r.type === 'bundle') return bundleDetail(r);
    if (r.type === 'segment') return segmentDetail(r.segment);
    if (r.type === 'subnet') return subnetDetail(r.subnet);
    if (r.type === 'adjacency') return adjacencyDetail(r.adjacency);
    return '';
  }
  function detail() {
    const hint = '<div class="det"><p class="hint">' + (S.tab === 'findings'
      ? 'Pick an item from the list to draw its neighbourhood and see what the Topology recorded.'
      : 'Select a device, Link, Bundle, Subnet or Shared Segment to see what the Topology recorded about it.') + '</p></div>';
    if (!S.pick) return hint;
    if (S.pick.finding) { const f = FINDING.get(S.pick.finding); return f ? findingDetail(f) : hint; }
    const r = REG.get(S.pick.id);
    return r ? refDetail(r) : hint;
  }

  /* ---------- the Findings tab's list (story 151) ---------- */
  const ITEMS = [];
  function item(o) { o.i = ITEMS.length; ITEMS.push(o); return o; }
  function centresOfItem(id) {
    const l = LINK.get(id);
    if (l) return endsOf(l).map(e => e.device);
    const b = BUNDLE.get(id);
    if (b) return arr(b.sides).flatMap(s => arr(s && s.ends)).map(e => e && e.device).filter(d => typeof d === 'string');
    const s = SEG.get(id);
    if (s) return [id];
    return posOf(id) ? [id] : [];
  }
  const focusOf = ids => ids.flatMap(id => edgesOfItem(id).map(e => e.id));
  function findingItem(f) {
    const items = arr(f.items).filter(i => typeof i === 'string');
    const centres = [...new Set([...arr(f.devices).filter(d => typeof d === 'string'), ...items.flatMap(centresOfItem)])];
    const m = markOf(f);
    return item({ dot: m || 'other', title: centres.slice(0, 2).map(nameOf).join(' ⇄ ') || txt(f.kind), sub: txt(f.summary), finding: f.id,
      sel: { centres, focus: focusOf(items), pick: { finding: f.id } } });
  }
  function edgeTitle(id) {
    const e = edgesOfItem(id)[0];
    return e ? nameOf(e.a) + ' ' + e.ai + ' ⇄ ' + nameOf(e.b) + ' ' + e.bi : id;
  }
  function linkItem(l, dot) {
    const e = edgesOfItem(l.id)[0];
    return item({ dot, title: edgeTitle(l.id), sub: txt(l.status) + (typeof l.bundle === 'string' ? ', Bundle member' : '') + ', from ' + [...new Set(arr(l.evidence).map(x => txt(x.source)))].join(', '),
      sel: { centres: centresOfItem(l.id), focus: focusOf([l.id]), pick: e ? { id: e.id } : null } });
  }
  const deviceItem = (id, dot, sub) => item({ dot, title: nameOf(id), sub, sel: { centres: [id], focus: [], pick: { id } } });
  const byKindOrder = f => (f.kind === CONFLICT ? 1 : RED.has(f.kind) ? 0 : 2);

  const findings = [...FINDING.values()];
  const LIST = {
    attention: findings.filter(f => f.kind !== ONE_END).sort((x, y) => byKindOrder(x) - byKindOrder(y)).map(findingItem),
    notChecked: (function () {
      const groups = new Map();
      for (const [subject, rows] of SKIP_BY_ITEM) {
        const reasons = [...new Set(rows.map(skipText))];
        const key = 'VLAN check: ' + reasons[0];
        const e = edgesOfItem(subject)[0];
        addTo(groups, key, item({ dot: 'unknown', title: edgeTitle(subject), sub: rows.map(r => nameOf(r.device) + ': ' + skipText(r)).join('; '),
          sel: { centres: centresOfItem(subject), focus: focusOf([subject]), pick: e ? { id: e.id } : null } }));
      }
      const perDevice = new Map();
      SKIPPED.filter(r => r.data !== 'vlan_mismatch').forEach(r => addTo(perDevice, r.device, r));
      for (const [device, rows] of perDevice) {
        addTo(groups, 'Data not collected from a Visited Device', deviceItem(device, 'unknown', rows.map(r => txt(r.data) + ' (' + txt(r.reason) + ')').join('; ')));
      }
      return [...groups.entries()].sort((x, y) => (x[0] < y[0] ? -1 : 1));
    })(),
    oneEnd: findings.filter(f => f.kind === ONE_END).map(findingItem),
    oneSided: [...LINK.values()].filter(l => l.status === 'one-sided' && endsOf(l).length === 2 && endsOf(l).every(e => DEV.has(e.device))).map(l => linkItem(l, 'acc')),
    inferred: [...LINK.values()].filter(l => l.status === 'inferred').map(l => linkItem(l, 'acc')),
    unvisited: (function () {
      const groups = new Map();
      for (const u of UNV.values()) {
        const by = [...new Set(arr(u.reported_by).map(r => nameOf(txt(r.device))))];
        addTo(groups, str(u.reason) || 'reason not recorded', deviceItem(u.id, 'unv', by.length ? 'reported by ' + by.join(', ') : 'reported by no Visited Device'));
      }
      return [...groups.entries()].sort((x, y) => (x[0] < y[0] ? -1 : 1));
    })(),
    visited: [...DEV.values()].sort((x, y) => (nameOf(x.id) < nameOf(y.id) ? -1 : 1))
      .map(d => deviceItem(d.id, 'acc', txt(d.platform) + ' · ' + txt(d.model)))
  };
  const FINDING_ITEM = new Map(ITEMS.filter(x => x.finding).map(x => [x.finding, x]));

  const itemButton = x => '<button class="fi" data-i="' + x.i + '"><span class="dot ' + esc(x.dot) + '"></span>' +
    '<span class="ft">' + esc(x.title) + '</span><span class="k">' + esc(x.sub) + '</span></button>';
  const count = list => list.length;
  function section(key, title, items, open, sub) {
    return '<details data-s="' + key + '"' + (open ? ' open' : '') + '><summary>' + esc(title) + '<span class="n">' + count(items) + '</span></summary>' +
      (sub ? '<div class="sub">' + esc(sub) + '</div>' : '') + (items.map(itemButton).join('') || '<div class="sub">none</div>') + '</details>';
  }
  function groupedSection(key, title, groups, open, sub) {
    const total = groups.reduce((n, g) => n + g[1].length, 0);
    return '<details data-s="' + key + '"' + (open ? ' open' : '') + '><summary>' + esc(title) + '<span class="n">' + total + '</span></summary>' +
      (sub ? '<div class="sub">' + esc(sub) + '</div>' : '') +
      (groups.map(g => '<div class="rgh">' + esc(g[0]) + ' (' + g[1].length + ')</div>' + g[1].map(itemButton).join('')).join('') || '<div class="sub">none</div>') + '</details>';
  }
  function sideList() {
    return section('attention', 'Needs attention', LIST.attention, true, 'VLAN Mismatches that break traffic, and conflicting evidence.') +
      groupedSection('unknown', 'Not checked', LIST.notChecked, true, 'Data was not collected, so these are never called a Mismatch.') +
      section('oneend', 'VLAN on one end only', LIST.oneEnd, false, 'Often harmless, such as "allowed all" facing a pruned list. Kept apart so it does not drown the rest.') +
      section('onesided', 'One-sided Links between Visited Devices', LIST.oneSided, false, '') +
      section('inferred', 'Inferred Links (from MAC/ARP)', LIST.inferred, false, '') +
      groupedSection('unvisited', 'Unvisited Devices', LIST.unvisited, false, '') +
      '<details data-s="visited"><summary>All Visited Devices<span class="n">' + LIST.visited.length + '</span></summary>' +
      '<input class="filter" id="filter" type="search" placeholder="Filter by name, Platform or model" aria-label="Filter Visited Devices"><div id="visited-list"></div></details>';
  }

  /* ---------- the page ---------- */
  const sample = (cls, double) => '<svg width="34" height="12" aria-hidden="true"><g class="edge ' + cls + '"><path class="ln" d="M2,6 L32,6"/>' + (double ? '<path class="ln2" d="M2,6 L32,6"/>' : '') + '</g></svg>';
  const stat = (n, one, many) => '<span><b>' + n + '</b> ' + (n === 1 ? one : many) + '</span>';
  const markCount = m => EDGES.filter(e => e.mark && e.mark === MARK[m]).length;
  function keyHtml() {
    if (S.tab === 'findings') {
      return '<span><b class="mk bad">!</b> mismatch</span><span><b class="mk noisy">~</b> one end only</span><span><b class="mk unknown">?</b> not checked</span><span><b class="mk conflict">≠</b> conflict</span>';
    }
    if (S.view === 'routing') {
      if (!L3_RECORDED) return '<span>This topology.json holds no L3 Adjacencies or Subnets (it was written by an older version), so no routing lines are drawn.</span>';
      return '<span>' + sample('l3 shared') + 'shared subnet (prefix)</span><span>' + sample('l3 proto') + 'routing protocol</span>' +
        '<span>Subnet node = prefix shared by 3+ devices</span><span>faded = no L3 interface</span>';
    }
    if (S.view === 'vlan') {
      const sc = vlanScene();
      const pickVlan = VLANS.length
        ? '<label class="field">VLAN <select id="vsel">' + VLANS.map(n => '<option' + (n === S.vlan ? ' selected' : '') + '>' + n + '</option>').join('') + '</select></label>'
        : '<span>No VLAN is recorded in this topology.json.</span>';
      return pickVlan + '<span class="c-on"><b>' + sc.counts.on + '</b> carry it at both ends</span><span class="c-break"><b>' + sc.counts.br + '</b> stop at one end</span>' +
        '<span class="c-unk"><b>' + sc.counts.un + '</b> unknown far end</span>';
    }
    return '<span>' + sample('st-confirmed') + 'confirmed</span><span>' + sample('st-one-sided') + 'one-sided</span>' +
      '<span>' + sample('st-inferred') + 'inferred</span><span>' + sample('bundle st-confirmed', true) + 'Bundle</span>' +
      '<span>' + sample('segment') + 'to a Shared Segment</span>' +
      '<span><b class="mk bad">!</b> ' + markCount('bad') + ' mismatch</span><span><b class="mk noisy">~</b> ' + markCount('noisy') + ' one end only</span>' +
      '<span><b class="mk unknown">?</b> ' + markCount('unknown') + ' not checked</span><span><b class="mk conflict">≠</b> ' + markCount('conflict') + ' conflict</span>';
  }
  app.innerHTML = '<header class="top gut"><h1>Network diagram</h1><div class="stats">' +
    stat(DEV.size, 'Visited Device', 'Visited Devices') + stat(UNV.size, 'Unvisited Device', 'Unvisited Devices') +
    stat(LINK.size, 'Link', 'Links') + stat(BUNDLE.size, 'Bundle', 'Bundles') + stat(SEG.size, 'Shared Segment', 'Shared Segments') +
    stat(SUBNET.size, 'Subnet', 'Subnets') + stat(FINDING.size, 'finding', 'findings') + '</div></header>' +
    '<div class="tabs gut"><div class="pages" role="tablist" aria-label="Tabs">' +
    '<button class="tab" role="tab" data-tab="map" aria-selected="true">Map</button>' +
    '<button class="tab" role="tab" data-tab="findings" aria-selected="false">Findings</button></div>' +
    '<div class="views" role="tablist" aria-label="Views" id="views">' +
    '<button class="tab" role="tab" data-view="physical" aria-selected="true">Physical</button>' +
    '<button class="tab" role="tab" data-view="routing" aria-selected="false">Routing (L3)</button>' +
    '<button class="tab" role="tab" data-view="vlan" aria-selected="false">VLAN</button></div>' +
    '<div class="key" id="key"></div></div>' +
    '<div class="body"><aside class="side" id="side" hidden>' + sideList() + '</aside>' +
    '<section class="main"><div class="stage"><div class="crumb" id="crumb" hidden></div><svg class="canvas" id="map" role="img" aria-label="Diagram of the Topology"><g class="vp"></g></svg>' +
    '<div class="zoom"><button data-z="in" aria-label="Zoom in">+</button><button data-z="out" aria-label="Zoom out">−</button><button data-z="fit" aria-label="Fit to view">⤢</button></div></div>' +
    '<div class="detail gut" id="detail" aria-live="polite"></div></section></div>';

  const svg = document.getElementById('map'), vp = svg.querySelector('.vp'), panel = document.getElementById('detail');
  const side = document.getElementById('side'), keyBox = document.getElementById('key'), crumb = document.getElementById('crumb');
  let current = null;
  function draw(refit) {
    app.querySelectorAll('[data-tab]').forEach(b => b.setAttribute('aria-selected', String(b.getAttribute('data-tab') === S.tab)));
    app.querySelectorAll('[data-view]').forEach(b => b.setAttribute('aria-selected', String(b.getAttribute('data-view') === S.view)));
    document.getElementById('views').hidden = S.tab !== 'map';
    side.hidden = S.tab !== 'findings';
    crumb.hidden = S.tab !== 'findings' || !S.sel;
    crumb.textContent = S.sel ? S.sel.label : '';
    svg.setAttribute('aria-label', S.tab === 'findings' ? 'Neighbourhood of the selected item' : (S.view === 'routing' ? 'Routing (L3) view' : S.view === 'vlan' ? 'VLAN view' : 'Physical view') + ' of the Topology');
    current = scene();
    render(vp, current);
    keyBox.innerHTML = keyHtml();
    const vsel = document.getElementById('vsel');
    if (vsel) vsel.addEventListener('change', () => { S.vlan = parseInt(vsel.value, 10); draw(false); });
    panel.innerHTML = detail();
    side.querySelectorAll('.fi').forEach(b => {
      if (S.sel && S.sel.i === Number(b.getAttribute('data-i'))) b.setAttribute('aria-current', 'true');
      else b.removeAttribute('aria-current');
    });
    if (refit) canvas.fit(boundsOf(current));
  }
  function select(x) {
    S.tab = 'findings';
    S.sel = { i: x.i, centres: x.sel.centres, focus: x.sel.focus, label: x.title };
    S.pick = x.sel.pick;
    draw(true);
  }
  function walkTo(id) {
    S.sel = { i: -1, centres: [id], focus: [], label: nameOf(id) };
    S.pick = { id };
    draw(true);
  }
  const canvas = attachCanvas(svg, id => {
    if (S.tab === 'findings' && id && (DEV.has(id) || UNV.has(id) || SEG.has(id))) { walkTo(id); return; }
    S.pick = id ? { id } : null;
    draw(false);
  });
  app.querySelectorAll('.zoom button').forEach(b => b.addEventListener('click', () => {
    const z = b.getAttribute('data-z');
    if (z === 'in') canvas.zoom(1.3); else if (z === 'out') canvas.zoom(1 / 1.3); else canvas.fit(boundsOf(current));
  }));
  app.querySelectorAll('[data-tab]').forEach(b => b.addEventListener('click', () => {
    const t = b.getAttribute('data-tab');
    if (t === S.tab) return;
    S.tab = t;
    S.pick = null;
    if (t === 'findings' && !S.sel) {
      const first = LIST.attention[0] || LIST.notChecked.map(g => g[1][0])[0] || LIST.visited[0];
      if (first) { select(first); return; }
    }
    draw(true);
  }));
  app.querySelectorAll('[data-view]').forEach(b => b.addEventListener('click', () => {
    S.view = b.getAttribute('data-view');
    S.pick = null;
    draw(true);
  }));
  side.addEventListener('click', e => {
    const b = e.target.closest('.fi');
    if (!b) return;
    const x = ITEMS[Number(b.getAttribute('data-i'))];
    if (x) select(x);
  });
  const visitedList = document.getElementById('visited-list'), filter = document.getElementById('filter');
  function listVisited() {
    const q = filter.value.trim().toLowerCase();
    visitedList.innerHTML = LIST.visited.filter(x => (x.title + ' ' + x.sub).toLowerCase().includes(q)).slice(0, 200).map(itemButton).join('') || '<div class="sub">none</div>';
  }
  filter.addEventListener('input', listVisited);
  listVisited();

  function openFromAddress() {
    /* diagram.html#device=<id> opens that device on the Map tab, and diagram.html#finding=<id>
       opens that finding on the Findings tab; an id the Topology does not hold is ignored */
    const m = /^#(device|finding)=([A-Za-z0-9._%-]+)$/.exec(location.hash);
    if (!m) return;
    let id;
    try { id = decodeURIComponent(m[2]); } catch (_) { return; }
    if (m[1] === 'finding') {
      const x = FINDING_ITEM.get(id);
      if (!x) return;
      const box = side.querySelector('details[data-s="' + (FINDING.get(id).kind === ONE_END ? 'oneend' : 'attention') + '"]');
      if (box) box.open = true;
      select(x);
      return;
    }
    if (!DEV.has(id) && !UNV.has(id) && !SEG.has(id)) return;
    S.tab = 'map';
    if (S.view === 'routing' && !DEV.has(id) && !L3_MEMBERS.has(id)) S.view = 'physical';
    S.pick = { id };
    draw(false);
    const p = POS.get(id);
    if (p) canvas.centerOn(p);
  }
  window.addEventListener('hashchange', openFromAddress);
  S.view = 'physical';
  draw(true);
  openFromAddress();
})();
