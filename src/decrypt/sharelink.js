import { emptyResult } from "./format.js";

export function tryShareLink(text) {
  const m = text.match(
    /((?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|wireguard):\/\/[^\s<>"']+)/i
  );
  if (!m) return null;
  const link = m[1];
  const r = emptyResult("Share Link");
  r.links.push(link);
  try {
    const scheme = link.split("://")[0].toLowerCase();
    if (scheme === "vless") {
      const u = new URL(link);
      r.server.protocol = "vless";
      r.server.uuid = decodeURIComponent(u.username);
      r.server.host = u.hostname;
      r.server.port = u.port;
      r.server.transport = u.searchParams.get("type") || "tcp";
      r.server.security = u.searchParams.get("security");
      r.server.tls = u.searchParams.get("security");
      r.server.sni = u.searchParams.get("sni");
      r.server.path = u.searchParams.get("path");
      r.server.hostHeader = u.searchParams.get("host");
      r.server.alpn = u.searchParams.get("alpn");
      r.server.fp = u.searchParams.get("fp");
      r.server.flow = u.searchParams.get("flow");
      r.server.encryption = u.searchParams.get("encryption") || "none";
      r.server.remark = decodeURIComponent(u.hash.replace(/^#/, ""));
      r.vless = link;
    } else if (scheme === "trojan") {
      const u = new URL(link);
      r.server.protocol = "trojan";
      r.server.password = decodeURIComponent(u.username);
      r.server.host = u.hostname;
      r.server.port = u.port;
      r.server.transport = u.searchParams.get("type") || "tcp";
      r.server.sni = u.searchParams.get("sni");
      r.server.path = u.searchParams.get("path");
      r.server.hostHeader = u.searchParams.get("host");
      r.server.alpn = u.searchParams.get("alpn");
      r.server.fp = u.searchParams.get("fp");
      r.server.tls = "tls";
      r.server.remark = decodeURIComponent(u.hash.replace(/^#/, ""));
      r.note = "Trojan — به VLESS تبدیل نمی‌شود.";
    } else if (scheme === "wireguard") {
      parseWireguardLink(link, r);
    } else {
      r.server.protocol = scheme;
    }
  } catch (e) {
    r.note = "پارس URL ناموفق بود: " + (e.message || "");
  }
  return r;
}

function parseWireguardLink(link, r) {
  // wireguard://PRIVATE@host:port?publickey=...&address=...&mtu=...#remark
  const u = new URL(link);
  r.server.protocol = "wireguard";
  r.format = "WireGuard Link";
  r.server.privateKey = decodeURIComponent(u.username || "");
  r.server.host = u.hostname;
  r.server.port = u.port;
  r.server.password = u.searchParams.get("publickey") || u.searchParams.get("peer"); // peer pubkey
  r.server.user = u.searchParams.get("address") || "";
  r.server.remark = decodeURIComponent((u.hash || "").replace(/^#/, ""));
  r.server.mtu = u.searchParams.get("mtu") || undefined;
  r.server.keepalive = u.searchParams.get("keepalive") || u.searchParams.get("persistentkeepalive") || undefined;
  r.server.presharedKey = u.searchParams.get("presharedkey") || u.searchParams.get("psk") || undefined;
  // Amnezia-style noise params
  const noise = {};
  for (const k of ["wnoise", "wnoisedelay", "wnoisecount", "wpayloadsize", "reserved", "jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"]) {
    const v = u.searchParams.get(k);
    if (v != null && v !== "") noise[k] = v;
  }
  if (Object.keys(noise).length) r.server.noise = noise;

  // Build standard-ish conf for rebrand/file export
  const conf = buildWgConf(r.server);
  r._rawConf = conf;
  r.links = [link];
  r.note = Object.keys(noise).length
    ? "WireGuard/Amnezia URI — پارامترهای نویز حفظ شد."
    : "WireGuard URI";
}

export function buildWgConf(s) {
  const lines = [];
  lines.push("[Interface]");
  if (s.privateKey) lines.push(`PrivateKey = ${s.privateKey}`);
  if (s.user) lines.push(`Address = ${s.user}`);
  if (s.mtu) lines.push(`MTU = ${s.mtu}`);
  const n = s.noise || {};
  // AmneziaWG optional
  if (n.jc) lines.push(`Jc = ${n.jc}`);
  if (n.jmin) lines.push(`Jmin = ${n.jmin}`);
  if (n.jmax) lines.push(`Jmax = ${n.jmax}`);
  for (const k of ["S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"]) {
    const v = n[k.toLowerCase()] || n[k];
    if (v) lines.push(`${k} = ${v}`);
  }
  lines.push("");
  lines.push("[Peer]");
  if (s.password) lines.push(`PublicKey = ${s.password}`);
  if (s.presharedKey) lines.push(`PresharedKey = ${s.presharedKey}`);
  lines.push(`AllowedIPs = 0.0.0.0/0, ::/0`);
  if (s.host) lines.push(`Endpoint = ${s.host}${s.port ? ":" + s.port : ""}`);
  if (s.keepalive) lines.push(`PersistentKeepalive = ${s.keepalive}`);
  return lines.join("\n");
}

/** Rebuild wireguard:// URI with new remark */
export function buildWireguardLink(s, remark) {
  if (!s?.privateKey || !s?.host) return null;
  const user = encodeURIComponent(s.privateKey);
  const host = s.host;
  const port = s.port || "51820";
  const q = new URLSearchParams();
  if (s.password) q.set("publickey", s.password);
  if (s.user) q.set("address", s.user);
  if (s.presharedKey) q.set("presharedkey", s.presharedKey);
  if (s.mtu) q.set("mtu", String(s.mtu));
  if (s.keepalive) q.set("keepalive", String(s.keepalive));
  const n = s.noise || {};
  for (const [k, v] of Object.entries(n)) {
    if (v != null && v !== "") q.set(k, String(v));
  }
  const hash = remark ? `#${encodeURIComponent(remark)}` : s.remark ? `#${encodeURIComponent(s.remark)}` : "";
  return `wireguard://${user}@${host}:${port}?${q.toString()}${hash}`;
}
