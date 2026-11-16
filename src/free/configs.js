/**
 * Fetch free public configs from known public sources.
 */
const UA = "config-decrypt-bot/2.5";

export const FREE_TYPES = [
  { id: "vless", title: "VLESS رایگان" },
  { id: "ss", title: "Shadowsocks" },
  { id: "trojan", title: "Trojan" },
  { id: "ovpn", title: "OpenVPN" },
  { id: "sstp", title: "SSTP عمومی" },
  { id: "tor", title: "Tor Bridge" },
  { id: "wg", title: "WireGuard" },
];

export async function fetchFreeConfigs(type, limit = 5) {
  switch (type) {
    case "ovpn":
      return fetchVpnGateOpenvpn(limit);
    case "sstp":
      return fetchVpnGateSstp(limit);
    case "vless":
      return fetchShareLinks("vless", limit);
    case "ss":
      return fetchShareLinks("ss", limit);
    case "trojan":
      return fetchShareLinks("trojan", limit);
    case "tor":
      return fetchTorBridges(limit);
    case "wg":
      return {
        ok: false,
        message: "منبع عمومی پایدار برای WireGuard/Amnezia پیدا نشد.\nاز کانال‌های عمومی یا فایل خودت استفاده کن.",
        items: [],
      };
    default:
      return { ok: false, message: "نوع ناشناخته.", items: [] };
  }
}

async function fetchText(url, timeoutMs = 15000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      headers: { "user-agent": UA, accept: "*/*" },
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.text();
  } finally {
    clearTimeout(t);
  }
}

async function fetchVpnGateServers() {
  const urls = [
    "https://cdn.jsdelivr.net/gh/GeorgeXie2333/vpngate-list-mirror@latest/data/servers.json",
    "https://raw.githubusercontent.com/GeorgeXie2333/vpngate-list-mirror/main/data/servers.json",
  ];
  for (const url of urls) {
    try {
      const text = await fetchText(url);
      const data = JSON.parse(text);
      const list = Array.isArray(data) ? data : data.servers || data.data || [];
      if (list.length) return list;
    } catch {}
  }
  try {
    const csv = await fetchText("http://www.vpngate.net/api/iphone/");
    return parseVpnGateCsv(csv);
  } catch {
    return [];
  }
}

function parseVpnGateCsv(csv) {
  const lines = csv.split(/\r?\n/).filter((l) => l && !l.startsWith("*") && !l.startsWith("#"));
  if (lines.length < 2) return [];
  const header = lines[0].split(",");
  const idx = Object.fromEntries(header.map((h, i) => [h.trim(), i]));
  const out = [];
  for (const line of lines.slice(1)) {
    const cols = splitCsv(line);
    if (cols.length < 10) continue;
    out.push({
      HostName: cols[idx.HostName] || cols[0],
      IP: cols[idx.IP] || cols[1],
      Score: Number(cols[idx.Score] || 0),
      CountryShort: cols[idx.CountryShort] || "",
      OpenVPN_ConfigData_Base64: cols[idx.OpenVPN_ConfigData_Base64] || cols[cols.length - 1],
    });
  }
  return out;
}

function splitCsv(line) {
  const res = [];
  let cur = "";
  let q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') q = !q;
    else if (c === "," && !q) {
      res.push(cur);
      cur = "";
    } else cur += c;
  }
  res.push(cur);
  return res;
}

async function fetchVpnGateOpenvpn(limit) {
  const servers = await fetchVpnGateServers();
  if (!servers.length) {
    return { ok: false, message: "لیست VPN Gate در دسترس نیست.", items: [] };
  }
  const sorted = [...servers].sort((a, b) => (Number(b.Score) || 0) - (Number(a.Score) || 0));
  const items = [];
  for (const s of sorted) {
    if (items.length >= limit) break;
    const b64 = s.OpenVPN_ConfigData_Base64 || s.openvpn_config || s.config;
    if (!b64) continue;
    try {
      const conf = Buffer.from(String(b64).replace(/\s+/g, ""), "base64").toString("utf8");
      if (!/client|remote\s+/i.test(conf)) continue;
      const country = s.CountryShort || s.country || "?";
      const host = s.IP || s.ip || s.HostName || "server";
      items.push({
        title: `OpenVPN ${country} ${host}`,
        text: conf,
        filename: `vpngate-${country}-${String(host).replace(/[^\w.-]/g, "_")}.ovpn`,
      });
    } catch {}
  }
  return {
    ok: items.length > 0,
    message: items.length ? `${items.length} کانفیگ OpenVPN از VPN Gate` : "کانفیگ OpenVPN پیدا نشد.",
    items,
  };
}

async function fetchVpnGateSstp(limit) {
  const servers = await fetchVpnGateServers();
  if (!servers.length) {
    return { ok: false, message: "لیست VPN Gate در دسترس نیست.", items: [] };
  }
  const sorted = [...servers].sort((a, b) => (Number(b.Score) || 0) - (Number(a.Score) || 0));
  const items = [];
  for (const s of sorted) {
    if (items.length >= limit) break;
    const host = s.HostName || s.hostname || s.IP || s.ip;
    if (!host) continue;
    const country = s.CountryShort || s.country || "?";
    const text = [
      `# SSTP free — VPN Gate ${country}`,
      `Server: ${host}`,
      `Port: 443`,
      `Protocol: SSTP`,
      `Username: vpn`,
      `Password: vpn`,
      ``,
      `# Windows: Add VPN → SSTP → ${host}`,
      `# user/pass: vpn / vpn`,
    ].join("\n");
    items.push({ title: `SSTP ${country} ${host}`, text });
  }
  return {
    ok: items.length > 0,
    message: items.length
      ? `${items.length} سرور SSTP عمومی (VPN Gate — user/pass: vpn)`
      : "سرور SSTP پیدا نشد.",
    items,
  };
}

const SUB_SOURCES = [
  "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
  "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge_base64.txt",
  "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_base64_Sub.txt",
];

async function fetchShareLinks(kind, limit) {
  const found = [];
  for (const url of SUB_SOURCES) {
    if (found.length >= limit) break;
    try {
      let body = await fetchText(url);
      if (!/vless:\/\/|ss:\/\/|trojan:\/\//i.test(body)) {
        try {
          body = Buffer.from(body.replace(/\s+/g, ""), "base64").toString("utf8");
        } catch {}
      }
      const re =
        kind === "vless"
          ? /vless:\/\/[^\s<>"']+/gi
          : kind === "ss"
            ? /ss:\/\/[^\s<>"']+/gi
            : /trojan:\/\/[^\s<>"']+/gi;
      const matches = body.match(re) || [];
      for (const link of matches) {
        if (found.length >= limit) break;
        if (!found.includes(link)) found.push(link);
      }
    } catch {}
  }
  return {
    ok: found.length > 0,
    message: found.length
      ? `${found.length} لینک ${kind.toUpperCase()} عمومی`
      : `الان لینک ${kind} عمومی در دسترس نیست.`,
    items: found.map((text, i) => ({ title: `${kind} #${i + 1}`, text })),
  };
}

async function fetchTorBridges(limit) {
  const items = [];
  try {
    const body = await fetchText(
      "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-obfs4"
    );
    const lines = body.split(/\r?\n/).filter((l) => /^obfs4\s+/i.test(l.trim()));
    for (const line of lines.slice(0, limit)) {
      items.push({ title: "Tor obfs4", text: line.trim() });
    }
  } catch {}
  if (!items.length) {
    return {
      ok: false,
      message: "لیست پل Tor در دسترس نیست.\nاز https://bridges.torproject.org پل بگیر.",
      items: [],
    };
  }
  return { ok: true, message: `${items.length} پل Tor (obfs4)`, items };
}
