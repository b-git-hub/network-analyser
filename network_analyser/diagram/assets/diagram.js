/* diagram.html: Map tab, Physical view (#63). Our own plain JavaScript, inlined.
   It reads the JSON data block, draws inline SVG markup and never loads anything.
   Every value from the Topology passes through esc() before it becomes markup.
   Ids are looked up in Maps only, so an id can never reach an object's prototype. */
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
  const short = (s, n) => (s.length > n ? s.slice(0, n - 1) + '…' : s);

  /* ---------- the Topology, by id ---------- */
  const DEV = new Map(), UNV = new Map(), SEG = new Map(), LINK = new Map(), BUNDLE = new Map(), FINDING = new Map();
  arr(T.devices).forEach(d => DEV.set(d.id, d));
  arr(T.unvisited).forEach(d => UNV.set(d.id, d));
  arr(T.segments).forEach(s => SEG.set(s.id, s));
  arr(T.links).forEach(l => LINK.set(l.id, l));
  arr(T.bundles).forEach(b => BUNDLE.set(b.id, b));
  arr(T.findings).forEach(f => FINDING.set(f.id, f));
  const POS = new Map();
  arr(DATA.layout && DATA.layout.positions).forEach(p => POS.set(p[0], { x: p[1], y: p[2] }));
  const LABELS = arr(DATA.layout && DATA.layout.labels);

  function nameOf(id) {
    const d = DEV.get(id);
    if (d) return str(d.hostname) || str(d.management_ip) || id;
    const u = UNV.get(id);
    if (u) return str(u.label) || str(arr(u.advertised_ips)[0]) || id;
    if (SEG.has(id)) return 'Shared Segment';
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
      out.push({ id: l.id, a, b, ai: ifn(ends[0].interface), bi: ifn(ends[1].interface), cls, mid, ref: { type: 'link', link: l } });
    }
    let n = 0;
    for (const g of groups.values()) {
      const b = g.bundle, na = portChannel(b, g.a), nb = portChannel(b, g.b);
      const statuses = new Set(g.links.map(l => l.status));
      const status = statuses.size === 1 ? [...statuses][0] : (statuses.has('one-sided') ? 'one-sided' : 'mixed');
      let mid = (na === nb ? na : na + ' / ' + nb) + ' ×' + g.links.length;
      if (bundleIsVpc(b)) mid += ' vPC';
      if (b.role === 'vPC peer-link') mid += ' peer-link';
      out.push({ id: 'bundle~' + (n++), a: g.a, b: g.b, ai: na, bi: nb, cls: ['bundle', statusClass(status)], mid,
        ref: { type: 'bundle', bundle: b, a: g.a, b: g.b, links: g.links } });
    }
    for (const s of SEG.values()) {
      arr(s.ports).forEach((p, i) => {
        if (!p || typeof p.device !== 'string') return;
        out.push({ id: s.id + '~' + i, a: s.id, b: p.device, ai: '', bi: ifn(p.interface), cls: ['segment'], mid: '', ref: { type: 'segment', segment: s } });
      });
    }
    return out;
  }
  const EDGES = physicalEdges();

  /* ---------- drawing ---------- */
  const REG = new Map();
  let pick = null;

  function scene() {
    const nodes = [];
    for (const d of DEV.values()) {
      const plat = str(d.platform) || '';
      const cls = (plat === 'NX-OS' ? 'nx' : 'xe') + (d.outcome === 'partial' ? ' partial' : '');
      nodes.push({ id: d.id, shape: 'dev', cls, t: nameOf(d.id), s: str(d.model) || '', plat, ref: { type: 'device', id: d.id } });
    }
    for (const u of UNV.values()) {
      nodes.push({ id: u.id, shape: 'dev', cls: 'unv', t: nameOf(u.id), s: str(u.reason) || 'reason not recorded', plat: '', ref: { type: 'device', id: u.id } });
    }
    for (const s of SEG.values()) nodes.push({ id: s.id, shape: 'seg', cls: '', ref: { type: 'device', id: s.id } });
    const shown = id => !!pick && (pick.id === id);
    const edges = EDGES.filter(e => {
      if (!isUnvisited(e.a) && !isUnvisited(e.b)) return true;
      return shown(e.a) || shown(e.b) || shown(e.id);
    });
    return { nodes, edges };
  }

  function curve(p1, p2, off) {
    const dx = p2.x - p1.x, dy = p2.y - p1.y, len = Math.hypot(dx, dy) || 1, nx = -dy / len, ny = dx / len;
    const cx = (p1.x + p2.x) / 2 + nx * off * 2, cy = (p1.y + p2.y) / 2 + ny * off * 2;
    const at = t => ({ x: (1 - t) * (1 - t) * p1.x + 2 * (1 - t) * t * cx + t * t * p2.x, y: (1 - t) * (1 - t) * p1.y + 2 * (1 - t) * t * cy + t * t * p2.y });
    const slope = t => ({ x: 2 * (1 - t) * (cx - p1.x) + 2 * t * (p2.x - cx), y: 2 * (1 - t) * (cy - p1.y) + 2 * t * (p2.y - cy) });
    const f = n => n.toFixed(1);
    return { d: 'M' + f(p1.x) + ',' + f(p1.y) + ' Q' + f(cx) + ',' + f(cy) + ' ' + f(p2.x) + ',' + f(p2.y), at, slope, len, dx, dy };
  }

  function endLabel(c, text, fromA) {
    // the name starts at its device's box edge and runs along the line
    const ux = Math.abs(c.dx) / c.len, uy = Math.abs(c.dy) / c.len;
    const edge = Math.min(ux > 0.01 ? 66 / ux : 1e9, uy > 0.01 ? 22 / uy : 1e9) + 6;
    const t0 = Math.min(0.45, (edge + text.length * 3.1) / c.len), t = fromA ? t0 : 1 - t0;
    const q = c.at(t), s = c.slope(t);
    let ang = Math.atan2(s.y, s.x) * 180 / Math.PI;
    if (ang > 90) ang -= 180; else if (ang <= -90) ang += 180;
    const x = q.x.toFixed(1), y = q.y.toFixed(1);
    return '<text class="lbl" x="' + x + '" y="' + y + '" dy="-2.5" text-anchor="middle" transform="rotate(' + ang.toFixed(1) + ' ' + x + ' ' + y + ')">' + esc(text) + '</text>';
  }

  function render(g, sc) {
    let out = '';
    const count = new Map(), index = new Map();
    const pairKey = e => (e.a < e.b ? e.a + '|' + e.b : e.b + '|' + e.a);
    sc.edges.forEach(e => count.set(pairKey(e), (count.get(pairKey(e)) || 0) + 1));
    REG.clear();
    for (const e of sc.edges) {
      const p1 = POS.get(e.a), p2 = POS.get(e.b);
      if (!p1 || !p2) continue;
      REG.set(e.id, e.ref);
      const k = pairKey(e), n = count.get(k), i = index.get(k) || 0;
      index.set(k, i + 1);
      let off = (i - (n - 1) / 2) * 16;
      if (e.a > e.b) off = -off;
      const c = curve(p1, p2, off);
      const cls = e.cls.slice();
      if (isUnvisited(e.a) || isUnvisited(e.b)) cls.push('to-unv');
      if (pick && pick.id === e.id) cls.push('sel');
      out += '<g class="edge ' + cls.join(' ') + '" data-id="' + esc(e.id) + '"><title>' + esc(nameOf(e.a) + ' ' + e.ai + ' ⇄ ' + nameOf(e.b) + ' ' + e.bi) + '</title>' +
        '<path class="hit" d="' + c.d + '"/><path class="ln" d="' + c.d + '"/>' + (cls.includes('bundle') ? '<path class="ln2" d="' + c.d + '"/>' : '');
      const m = c.at(0.5);
      if (e.mid) out += '<text class="lbl mid" x="' + m.x.toFixed(1) + '" y="' + (m.y - 5).toFixed(1) + '" text-anchor="middle">' + esc(e.mid) + '</text>';
      if (e.ai && !SEG.has(e.a)) out += endLabel(c, e.ai, true);
      if (e.bi && !SEG.has(e.b)) out += endLabel(c, e.bi, false);
      out += '</g>';
    }
    for (const l of LABELS) {
      out += '<text class="lane' + (l.heading ? ' h' : '') + '" x="' + Number(l.x).toFixed(1) + '" y="' + Number(l.y).toFixed(1) + '">' + esc(txt(l.text)) + '</text>';
    }
    for (const n of sc.nodes) {
      const p = POS.get(n.id);
      if (!p) continue;
      REG.set(n.id, n.ref);
      const sel = pick && pick.id === n.id ? ' sel' : '';
      const tr = ' transform="translate(' + p.x.toFixed(1) + ',' + p.y.toFixed(1) + ')"';
      if (n.shape === 'seg') {
        out += '<g class="node seg' + sel + '" data-id="' + esc(n.id) + '"' + tr + '><title>Shared Segment: something the tool cannot see, such as an unmanaged switch</title>' +
          '<circle r="15"/><text class="t" y="4" text-anchor="middle">?</text><text class="s" y="29" text-anchor="middle">Shared Segment</text></g>';
        continue;
      }
      out += '<g class="node ' + n.cls + sel + '" data-id="' + esc(n.id) + '"' + tr + '><title>' + esc(n.t) + '</title><rect x="-64" y="-20" width="128" height="40" rx="6"/>' +
        '<text class="t" y="-3" text-anchor="middle">' + esc(short(n.t, 20)) + '</text><text class="s" y="12" text-anchor="middle">' +
        (n.plat ? '<tspan class="plat">' + esc(n.plat) + '</tspan> ' : '') + esc(short(n.s, n.plat ? 14 : 26)) + '</text></g>';
    }
    g.innerHTML = out;
  }

  function bounds() {
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    POS.forEach(p => { x0 = Math.min(x0, p.x - 70); x1 = Math.max(x1, p.x + 70); y0 = Math.min(y0, p.y - 30); y1 = Math.max(y1, p.y + 40); });
    LABELS.forEach(l => { x0 = Math.min(x0, l.x); y0 = Math.min(y0, l.y - 16); x1 = Math.max(x1, l.x + 340); });
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
  function findingBoxes(ids) {
    return arr(ids).map(id => FINDING.get(id)).filter(Boolean)
      .map(f => '<div class="find"><b>' + h(f.kind) + '.</b> ' + h(f.summary) + '</div>').join('');
  }
  function interfaceOf(device, short) {
    const d = DEV.get(device);
    if (!d) return null;
    return arr(d.interfaces).find(i => i && ifn(i.name) === short) || null;
  }
  function vlanTable(columns) {
    // columns: [{device, port}] side by side
    const cells = columns.map(c => ({ c, i: interfaceOf(c.device, c.port) }));
    const line = (label, f) => '<tr><td>' + esc(label) + '</td>' + cells.map(x => td(x.i ? esc(f(x.i)) : (DEV.has(x.c.device) ? 'not recorded' : 'not a Visited Device'), true)).join('') + '</tr>';
    return '<div class="tblwrap"><table><tr><th></th>' + cells.map(x => '<th>' + esc(nameOf(x.c.device)) + ' <span class="mono">' + esc(x.c.port) + '</span></th>').join('') + '</tr>' +
      line('Mode', i => txt(i.mode)) + line('Allowed VLANs', i => ranges(i.allowed_vlans)) + line('Native VLAN', i => txt(i.native_vlan)) +
      line('Access VLAN', i => txt(i.access_vlan)) + line('Status', i => (i.line_up === true ? 'up' : i.line_up === false ? 'down' : txt(i.line_up))) +
      '</table></div>';
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
    for (const l of LINK.values()) {
      const ends = endsOf(l);
      const me = ends.findIndex(e => e.device === d.id);
      if (ends.length !== 2 || me < 0) continue;
      const far = ends[1 - me];
      const bundle = typeof l.bundle === 'string' ? BUNDLE.get(l.bundle) : undefined;
      links.push('<tr>' + td(esc(ifn(ends[me].interface)), true) + td(esc(nameOf(far.device)) + ' <span class="mono">' + esc(ifn(far.interface)) + '</span>') +
        td(h(l.status) + (bundle ? ' · ' + esc(portChannel(bundle, d.id)) : '') + (l.role ? ' · ' + h(l.role) : '')) + '</tr>');
    }
    for (const s of SEG.values()) arr(s.ports).forEach(p => {
      if (p && p.device === d.id) links.push('<tr>' + td(esc(ifn(p.interface)), true) + td('Shared Segment') + td('hears two or more Neighbours') + '</tr>');
    });
    const l3 = arr(d.interfaces).filter(i => i && i.ip && typeof i.ip === 'object' && !isUnk(i.ip) && arr(i.ip.addresses).length)
      .map(i => '<tr>' + td(esc(ifn(i.name)), true) + td(h(i.ip.addresses), true) + td(h(i.ip.vrf)) + '</tr>');
    const stack = arr(d.stack_members).map(m => txt(m.number) + ': ' + txt(m.model) + ' ' + txt(m.serial));
    const vpc = d.vpc && typeof d.vpc === 'object' && !isUnk(d.vpc)
      ? row('vPC domain', h(d.vpc.domain) + ', peer-link <span class="mono">' + esc(ifn(d.vpc.peer_link)) + '</span>') : (isUnk(d.vpc) ? row('vPC', h(d.vpc)) : '');
    return '<div class="det"><div><h3>' + esc(nameOf(d.id)) + '</h3><span class="pill acc">Visited Device</span>' +
      (d.outcome === 'partial' ? '<span class="pill bad">partial: ' + h(d.partial_reason) + '</span>' : '') + '<dl>' +
      row('Platform', h(d.platform)) + row('Model', h(d.model)) + row('Software', '<span class="mono">' + h(d.software_version) + '</span>') +
      row('Serials', '<span class="mono">' + h(d.serials) + '</span>') + (stack.length ? row('Stack members', esc(stack.join('; '))) : '') +
      row('Logged into at', '<span class="mono">' + h(d.management_ip) + '</span>') + row('Alias IPs', '<span class="mono">' + h(d.alias_ips) + '</span>') + vpc +
      row('Id', '<span class="mono">' + esc(d.id) + '</span>') + '</dl></div>' +
      '<div><h4>Interfaces with a Link</h4>' + table(['Local', 'Far end', 'Status'], links) + '</div>' +
      (l3.length ? '<div><h4>L3 interfaces</h4>' + table(['Interface', 'Addresses', 'VRF'], l3) + '</div>' : '') +
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
    return '<div class="det"><div><h3>Shared Segment</h3><span class="pill unv">not a device the tool can see</span>' +
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
      (arr(l.conflicts).length ? '<span class="pill conflict">conflicting evidence</span>' : '') + findingBoxes(l.conflicts) +
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
    const findings = [...FINDING.values()].filter(f => arr(f.items).includes(b.id)).map(f => f.id);
    return '<div class="det"><div><h3>' + esc(nameOf(ref.a) + ' ' + na + ' ⇄ ' + nameOf(ref.b) + ' ' + nb) + '</h3>' +
      '<span class="pill ok">Bundle · ' + esc(String(ref.links.length)) + ' member' + (ref.links.length === 1 ? '' : 's') + ' here</span>' +
      (bundleIsVpc(b) ? '<span class="pill acc">vPC</span>' : '') + (b.role ? '<span class="pill acc">' + h(b.role) + '</span>' : '') +
      findingBoxes(findings) + '<dl>' + row('Sides', sides.join('<br>')) + row('Id', '<span class="mono">' + esc(b.id) + '</span>') + '</dl>' +
      '<h4>Member Links here</h4>' + table([nameOf(ref.a), nameOf(ref.b), 'Status'], members) +
      '<h4>Evidence</h4>' + evidenceList(ref.links.flatMap(l => arr(l.evidence))) + '</div>' +
      '<div><h4>VLANs</h4>' + vlanTable(columns) + '</div></div>';
  }
  function detail() {
    const hint = '<div class="det"><p class="hint">Select a device, Link, Bundle or Shared Segment to see what the Topology recorded about it.</p></div>';
    if (!pick) return hint;
    const r = REG.get(pick.id);
    if (!r) return hint;
    if (r.type === 'device') return deviceDetail(r.id);
    if (r.type === 'link') return linkDetail(r.link);
    if (r.type === 'bundle') return bundleDetail(r);
    if (r.type === 'segment') return segmentDetail(r.segment);
    return hint;
  }

  /* ---------- the page ---------- */
  const sample = (cls, double) => '<svg width="34" height="12" aria-hidden="true"><g class="edge ' + cls + '"><path class="ln" d="M2,6 L32,6"/>' + (double ? '<path class="ln2" d="M2,6 L32,6"/>' : '') + '</g></svg>';
  const count = (n, one, many) => '<span><b>' + n + '</b> ' + (n === 1 ? one : many) + '</span>';
  app.innerHTML = '<header class="top gut"><h1>Network diagram</h1><div class="stats">' +
    count(DEV.size, 'Visited Device', 'Visited Devices') + count(UNV.size, 'Unvisited Device', 'Unvisited Devices') +
    count(LINK.size, 'Link', 'Links') + count(BUNDLE.size, 'Bundle', 'Bundles') + count(SEG.size, 'Shared Segment', 'Shared Segments') + '</div></header>' +
    '<div class="tabs gut"><button class="tab" role="tab" aria-selected="true">Map</button>' +
    '<div class="views" role="tablist" aria-label="Views"><button class="tab" role="tab" aria-selected="true">Physical</button></div>' +
    '<div class="key"><span>' + sample('st-confirmed') + 'confirmed</span><span>' + sample('st-one-sided') + 'one-sided</span>' +
    '<span>' + sample('st-inferred') + 'inferred</span><span>' + sample('bundle st-confirmed', true) + 'Bundle</span>' +
    '<span>' + sample('segment') + 'to a Shared Segment</span></div></div>' +
    '<div class="stage"><svg class="canvas" id="map" role="img" aria-label="Physical view of the Topology"><g class="vp"></g></svg>' +
    '<div class="zoom"><button data-z="in" aria-label="Zoom in">+</button><button data-z="out" aria-label="Zoom out">−</button><button data-z="fit" aria-label="Fit to view">⤢</button></div></div>' +
    '<div class="detail gut" id="detail" aria-live="polite"></div>';

  const svg = document.getElementById('map'), vp = svg.querySelector('.vp'), panel = document.getElementById('detail');
  const draw = () => { render(vp, scene()); panel.innerHTML = detail(); };
  const canvas = attachCanvas(svg, id => { pick = id ? { id } : null; draw(); });
  app.querySelectorAll('.zoom button').forEach(b => b.addEventListener('click', () => {
    const z = b.getAttribute('data-z');
    if (z === 'in') canvas.zoom(1.3); else if (z === 'out') canvas.zoom(1 / 1.3); else canvas.fit(bounds());
  }));

  function openFromAddress() {
    // diagram.html#device=<id> opens that device; an id the Topology does not hold is ignored
    const m = /^#device=([A-Za-z0-9._%-]+)$/.exec(location.hash);
    if (!m) return;
    let id;
    try { id = decodeURIComponent(m[1]); } catch (_) { return; }
    if (!DEV.has(id) && !UNV.has(id) && !SEG.has(id)) return;
    pick = { id };
    draw();
    const p = POS.get(id);
    if (p) canvas.centerOn(p);
  }
  window.addEventListener('hashchange', openFromAddress);
  draw();
  canvas.fit(bounds());
  openFromAddress();
})();
