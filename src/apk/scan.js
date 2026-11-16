import { openBytes } from "../decrypt/open.js";

const LINK_RE =
  /(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|wireguard):\/\/[^\s\x00-\x1f"'<>\\]{8,}/gi;
const SLIP_RE = /slipnet(?:-enc|-bundle-enc)?:\/\/[A-Za-z0-9+/=_%-]{20,}/gi;
const ROCKET_RE = /https?:\/\/rcktnl\.site\/i\/[A-Za-z0-9_%+.\/=-]{20,}/gi;
const ARGO_RE =
  /-----BEGIN ARGO VPN BRIDGE BLOCK-----[\s\S]{20,2000}?-----END ARGO VPN BRIDGE BLOCK-----/gi;
const OVPN_HINT = /(?:client\s*\n[\s\S]{0,200}remote\s+\S+\s+\d+|remote\s+\S+\s+\d+[\s\S]{0,100}client)/i;
const WG_HINT = /\[Interface\][\s\S]{20,3000}?\[Peer\][\s\S]{20,2000}/gi;
const TOR_RE =
  /\b(?:obfs4|snowflake|webtunnel|meek_lite)\s+\S+:\d+\s+[A-F0-9]{40}\b(?:\s+\S+=\S+)*/gi;
const SUB_URL_RE =
  /https?:\/\/[^\s\x00-\x1f"'<>\\]{12,}(?:sub|subscribe|subscription|config|clash|v2ray|vpn)[^\s\x00-\x1f"'<>\\]*/gi;
const GENERIC_URL_RE =
  /https?:\/\/(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d{2,5})?(?:\/[^\s\x00-\x1f"'<>\\]*)?/gi;
const HOSTPORT_RE =
  /\b(?:(?:\d{1,3}\.){3}\d{1,3}|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+):(\d{2,5})\b/gi;

/**
 * Scan APK/binary for embedded connection material.
 */
export async function scanApk(name, bytes) {
  const findings = {
    links: [],
    tor: [],
    ovpn: [],
    wireguard: [],
    argo: [],
    slipnet: [],
    rocket: [],
    subUrls: [],
    hosts: [],
    otherUrls: [],
    decrypted: [],
  };

  const strings = extractStrings(bytes, 10);
  const blob = strings.join("\n");

  collect(blob, LINK_RE, findings.links);
  collect(blob, SLIP_RE, findings.slipnet);
  collect(blob, ROCKET_RE, findings.rocket);
  collect(blob, TOR_RE, findings.tor);
  collect(blob, SUB_URL_RE, findings.subUrls);

  // Argo / WG blocks may span newlines in real text files; also search raw utf8 decode
  let fullText = "";
  try {
    fullText = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    fullText = blob;
  }
  collect(fullText, ARGO_RE, findings.argo);
  collect(fullText, WG_HINT, findings.wireguard);

  // OpenVPN-like chunks from strings
  for (const s of strings) {
    if (s.length > 80 && /remote\s+\S+/i.test(s) && (/BEGIN CERTIFICATE/i.test(s) || /client/i.test(s))) {
      if (!findings.ovpn.includes(s)) findings.ovpn.push(s.slice(0, 8000));
    }
  }

  // Host:port candidates (filter common junk)
  const hostHits = fullText.match(HOSTPORT_RE) || blob.match(HOSTPORT_RE) || [];
  const junk = /^(127\.|0\.0\.0\.0|255\.|localhost|example\.|android\.|google\.|facebook\.|twitter\.|schema|xmlns)/i;
  for (const h of hostHits) {
    if (junk.test(h)) continue;
    if (!findings.hosts.includes(h)) findings.hosts.push(h);
    if (findings.hosts.length >= 40) break;
  }

  // Generic https urls (cap)
  const urls = blob.match(GENERIC_URL_RE) || [];
  for (const u of urls) {
    if (/android|google|maven|github\.com\/|schemas\.|w3\.org|apple\.com|microsoft/i.test(u)) continue;
    if (findings.subUrls.includes(u) || findings.rocket.includes(u)) continue;
    if (!findings.otherUrls.includes(u)) findings.otherUrls.push(u);
    if (findings.otherUrls.length >= 30) break;
  }

  // Try decrypt/parse interesting chunks via existing pipeline
  const candidates = [
    ...findings.links,
    ...findings.slipnet,
    ...findings.rocket,
    ...findings.argo,
    ...findings.tor,
    ...findings.ovpn.slice(0, 5),
    ...findings.wireguard.slice(0, 3),
  ];
  const seen = new Set();
  for (const c of candidates.slice(0, 25)) {
    const key = c.slice(0, 120);
    if (seen.has(key)) continue;
    seen.add(key);
    try {
      const bytes2 = new TextEncoder().encode(c);
      const r = await openBytes("apk-extract.txt", bytes2, c, null);
      if (r && r.format && r.format !== "unknown") {
        findings.decrypted.push(r);
      }
    } catch {}
  }

  findings.links = uniq(findings.links).slice(0, 40);
  findings.tor = uniq(findings.tor).slice(0, 20);
  findings.ovpn = uniq(findings.ovpn).slice(0, 10);
  findings.wireguard = uniq(findings.wireguard).slice(0, 10);
  findings.argo = uniq(findings.argo).slice(0, 10);
  findings.slipnet = uniq(findings.slipnet).slice(0, 10);
  findings.rocket = uniq(findings.rocket).slice(0, 10);
  findings.subUrls = uniq(findings.subUrls).slice(0, 20);
  findings.hosts = uniq(findings.hosts).slice(0, 30);
  findings.otherUrls = uniq(findings.otherUrls).slice(0, 20);

  return findings;
}

export function formatApkFindings(findings, fileName) {
  const msgs = [];
  msgs.push(`📱 <b>اسکن اپ:</b> <code>${esc(fileName || "app.apk")}</code>`);

  const addList = (title, arr, asCode = true) => {
    if (!arr?.length) return;
    msgs.push(`\n<b>${title}</b> (${arr.length})`);
    for (const x of arr.slice(0, 15)) {
      const t = String(x);
      const body = asCode ? `<code>${esc(t.slice(0, 3500))}</code>` : esc(t.slice(0, 3500));
      msgs.push(body);
    }
  };

  addList("🔗 لینک کانفیگ", findings.links);
  addList("🛰️ SlipNet", findings.slipnet);
  addList("🚀 Rocket", findings.rocket);
  addList("🌉 Argo", findings.argo);
  addList("🧅 Tor Bridge", findings.tor);
  addList("📄 OpenVPN تکه", findings.ovpn);
  addList("🔐 WireGuard تکه", findings.wireguard);
  addList("📥 احتمالی Subscription", findings.subUrls);
  addList("🖥️ Host:Port", findings.hosts);
  addList("🌐 URLهای مرتبط", findings.otherUrls);

  if (findings.decrypted?.length) {
    msgs.push(`\n<b>🔓 پارس/دیکریپت موفق:</b> ${findings.decrypted.length}`);
  }

  const total =
    findings.links.length +
    findings.slipnet.length +
    findings.rocket.length +
    findings.argo.length +
    findings.tor.length +
    findings.ovpn.length +
    findings.wireguard.length +
    findings.subUrls.length;

  if (!total && !findings.hosts.length) {
    msgs.push("\n⚠️ چیز واضحی پیدا نشد. ممکن است کانفیگ از سرور لود شود یا رمز اختصاصی داشته باشد.");
  }

  // Telegram message size — split
  const chunks = [];
  let buf = "";
  for (const m of msgs) {
    if ((buf + "\n" + m).length > 3500) {
      chunks.push(buf);
      buf = m;
    } else {
      buf = buf ? buf + "\n" + m : m;
    }
  }
  if (buf) chunks.push(buf);
  return { chunks, decrypted: findings.decrypted || [] };
}

function extractStrings(buf, minLen) {
  const out = [];
  let start = -1;
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    const ok = b >= 32 && b < 127;
    if (ok) {
      if (start < 0) start = i;
    } else if (start >= 0) {
      if (i - start >= minLen) {
        out.push(String.fromCharCode(...buf.subarray(start, i)));
      }
      start = -1;
    }
  }
  if (start >= 0 && buf.length - start >= minLen) {
    out.push(String.fromCharCode(...buf.subarray(start)));
  }
  // also light UTF-16LE pass for "https" patterns
  let u = "";
  for (let i = 0; i + 1 < buf.length; i += 2) {
    const c = buf[i];
    const hi = buf[i + 1];
    if (hi === 0 && c >= 32 && c < 127) u += String.fromCharCode(c);
    else {
      if (u.length >= minLen) out.push(u);
      u = "";
    }
  }
  if (u.length >= minLen) out.push(u);
  return out;
}

function collect(text, re, arr) {
  if (!text) return;
  const r = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
  let m;
  while ((m = r.exec(text)) !== null) {
    const v = m[0];
    if (v && !arr.includes(v)) arr.push(v);
    if (arr.length >= 50) break;
  }
}

function uniq(arr) {
  return [...new Set(arr.map((x) => String(x).trim()).filter(Boolean))];
}

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
