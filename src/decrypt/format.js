export function emptyResult(format) {
  return { format, links: [], vless: null, server: {}, note: null };
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
  const hash = s.remark ? `#${encodeURIComponent(s.remark)}` : "";
  return `vless://${s.uuid}@${s.host}:${s.port}?${q.toString()}${hash}`;
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

export function formatReply(r) {
  const lines = [];
  lines.push(`📦 <b>فرمت:</b> ${esc(r.format)}`);
  if (r.vless) {
    lines.push("");
    lines.push("🔗 <b>VLESS</b>");
    lines.push(`<code>${esc(r.vless)}</code>`);
  }
  const other = (r.links || []).filter((l) => l && l !== r.vless);
  if (other.length) {
    lines.push("");
    lines.push("🔗 <b>لینک‌ها</b>");
    for (const l of other) lines.push(`<code>${esc(l)}</code>`);
  }
  const s = r.server || {};
  const rows = [
    ["پروتکل", s.protocol],
    ["آدرس", s.host],
    ["پورت", s.port],
    ["UUID", s.uuid],
    ["کاربر", s.user],
    ["رمز", s.password],
    ["Transport", s.transport],
    ["TLS", s.tls ?? s.security],
    ["SNI", s.sni],
    ["Host", s.hostHeader],
    ["Path", s.path],
    ["ALPN", s.alpn],
    ["FP", s.fp],
    ["Flow", s.flow],
    ["Remark", s.remark],
  ].filter(([, v]) => v !== undefined && v !== null && v !== "");
  if (rows.length) {
    lines.push("");
    lines.push("📋 <b>اطلاعات سرور</b>");
    for (const [k, v] of rows) lines.push(`• <b>${esc(k)}:</b> <code>${esc(String(v))}</code>`);
  }
  if (r.note) {
    lines.push("");
    lines.push(`ℹ️ ${esc(r.note)}`);
  }
  if (!r.vless && !other.length && !rows.length) {
    lines.push("");
    lines.push("⚠️ چیزی استخراج نشد.");
  }
  return lines.join("\n");
}

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
