import { emptyResult } from "./format.js";

export function tryShareLink(text) {
  const m = text.match(/((?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic):\/\/[^\s<>"']+)/i);
  if (!m) return null;
  const link = m[1];
  const r = emptyResult("Share Link");
  r.links.push(link);
  try {
    if (link.startsWith("vless://")) {
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
    } else if (link.startsWith("trojan://")) {
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
    } else {
      r.server.protocol = link.split("://")[0];
    }
  } catch {
    r.note = "پارس URL ناموفق بود.";
  }
  return r;
}
