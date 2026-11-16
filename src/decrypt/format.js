export function emptyResult(format) {
  return { format, links: [], vless: null, server: {}, servers: null, note: null };
}

export function buildVless(s) {
  if (!s?.uuid || !s?.host || !s?.port) return null;
  const q = new URLSearchParams();
  q.set("encryption", s.encryption || "none");
  const sec = s.security || (s.tls === true || s.tls === "tls" ? "tls" : "none");
  q.set("security", sec);
  if (s.sni) q.set("sni", s.sni);
  if (s.alpn) q.set("alpn", Array.isArray(s.alpn) ? s.alpn.join(",") : s.alpn);
  if (s.fp) q.set("fp", s.fp);
  if (s.transport) q.set("type", s.transport);
  if (s.hostHeader) q.set("host", s.hostHeader);
  if (s.path) q.set("path", s.path);
  if (s.flow) q.set("flow", s.flow);
  if (s.mode) q.set("mode", s.mode);
  const hash = s.remark ? `#${encodeURIComponent(s.remark)}` : "";
  return `vless://${s.uuid}@${s.host}:${s.port}?${q.toString()}${hash}`;
}

export function buildSs(s) {
  if (!s?.method || !s?.password || !s?.host || !s?.port) return null;
  const user = Buffer.from(`${s.method}:${s.password}`).toString("base64url");
  const hash = s.remark ? `#${encodeURIComponent(s.remark)}` : "";
  return `ss://${user}@${s.host}:${s.port}${hash}`;
}

export function buildTrojan(s) {
  if (!s?.password || !s?.host || !s?.port) return null;
  const q = new URLSearchParams();
  if (s.sni) q.set("sni", s.sni);
  if (s.transport) q.set("type", s.transport);
  if (s.path) q.set("path", s.path);
  if (s.hostHeader) q.set("host", s.hostHeader);
  if (s.alpn) q.set("alpn", Array.isArray(s.alpn) ? s.alpn.join(",") : s.alpn);
  if (s.fp) q.set("fp", s.fp);
  q.set("security", "tls");
  const hash = s.remark ? `#${encodeURIComponent(s.remark)}` : "";
  return `trojan://${encodeURIComponent(s.password)}@${s.host}:${s.port}?${q.toString()}${hash}`;
}

/** Split result into separate Telegram messages (format, links, servers). */
export function formatMessages(r) {
  const msgs = [];
  const blocks = Array.isArray(r.servers) && r.servers.length ? r.servers : [r.server || {}];
  const shown = blocks.filter((b) => b && Object.values(b).some((v) => v !== undefined && v !== null && v !== ""));
  const links = [...new Set((r.links || []).filter(Boolean))];
  const hasData = Boolean(r.vless || links.length || shown.length);

  msgs.push(`📦 <b>فرمت:</b> ${esc(r.format)}`);

  if (r.vless) {
    msgs.push(`🔗 <b>VLESS</b>\n<code>${esc(r.vless)}</code>`);
  }

  for (const l of links) {
    if (l === r.vless) continue;
    let kind = "لینک";
    if (/:\/\//.test(l)) kind = l.split("://")[0].toUpperCase();
    else if (/^(obfs4|snowflake|meek|webtunnel)\b/i.test(l)) kind = l.split(/\s+/)[0].toUpperCase();
    msgs.push(`🔗 <b>${esc(kind)}</b>\n<code>${esc(l)}</code>`);
  }

  shown.forEach((srv, i) => {
    const rows = serverRows(srv);
    if (!rows.length) return;
    const title = shown.length > 1 ? `📋 <b>اطلاعات سرور ${i + 1}</b>` : "📋 <b>اطلاعات سرور</b>";
    const body = rows.map(([k, v]) => `• <b>${esc(k)}:</b> <code>${esc(String(v))}</code>`).join("\n");
    msgs.push(`${title}\n${body}`);
  });

  if (r.note) {
    const note = String(r.note).slice(0, 1500);
    msgs.push(`ℹ️ ${esc(note)}`);
  }

  if (!hasData && !r.note) {
    msgs.push("⚠️ چیزی استخراج نشد.");
  }

  return msgs;
}

export function formatReply(r) {
  return formatMessages(r).join("\n\n");
}

function serverRows(s) {
  return [
    ["پروتکل", s.protocol],
    ["آدرس", s.host],
    ["پورت", s.port],
    ["UUID", s.uuid],
    ["کاربر", s.user],
    ["رمز", s.password],
    ["متد", s.method],
    ["Transport", s.transport],
    ["TLS", s.tls ?? s.security],
    ["SNI", s.sni],
    ["Host", s.hostHeader],
    ["Path", s.path],
    ["Payload", s.payload],
    ["Remote", s.remoteProxy],
    ["ALPN", s.alpn],
    ["FP", s.fp],
    ["Flow", s.flow],
    ["Mode", s.mode],
    ["Fingerprint", s.fingerprint],
    ["Cert", s.cert],
    ["Remark", s.remark],
  ].filter(([, v]) => v !== undefined && v !== null && v !== "");
}

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
