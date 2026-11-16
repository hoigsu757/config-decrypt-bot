import { emptyResult } from "./format.js";

const BRIDGE_RE =
  /\b(obfs4|snowflake|meek_lite|meek|webtunnel|scramblesuit|fte)\s+(\S+):(\d+)\s+([A-F0-9]{40})((?:\s+\S+=\S+)*)/gi;

export function tryTor(text) {
  if (!text) return null;
  const bridges = [];
  let m;
  const re = new RegExp(BRIDGE_RE.source, "gi");
  while ((m = re.exec(text)) !== null) {
    const transport = m[1].toLowerCase();
    const host = m[2];
    const port = m[3];
    const fingerprint = m[4].toUpperCase();
    const params = {};
    const rest = m[5] || "";
    for (const part of rest.trim().split(/\s+/).filter(Boolean)) {
      const eq = part.indexOf("=");
      if (eq > 0) params[part.slice(0, eq)] = part.slice(eq + 1);
    }
    bridges.push({
      protocol: `tor-${transport}`,
      host,
      port,
      fingerprint,
      params,
      line: m[0].trim(),
    });
  }
  if (!bridges.length) {
    // BridgeDB / torrc style: "Bridge obfs4 ..."
    const re2 = /(?:^|\n)\s*(?:Bridge\s+)?(obfs4|snowflake|meek_lite|webtunnel)\s+\S+/gi;
    if (!re2.test(text) && !/\biat-mode=/i.test(text) && !/\bcert=/i.test(text)) return null;
    return null;
  }

  const r = emptyResult("Tor Bridge");
  r.server = {
    protocol: bridges[0].protocol,
    host: bridges[0].host,
    port: bridges[0].port,
    remark: bridges[0].fingerprint.slice(0, 16) + "…",
    fingerprint: bridges[0].fingerprint,
  };
  if (bridges[0].params.cert) r.server.cert = bridges[0].params.cert.slice(0, 24) + "…";
  if (bridges[0].params["iat-mode"] != null) r.server.mode = `iat-mode=${bridges[0].params["iat-mode"]}`;

  r.servers = bridges.map((b) => ({
    protocol: b.protocol,
    host: b.host,
    port: b.port,
    fingerprint: b.fingerprint,
    cert: b.params.cert,
    mode: b.params["iat-mode"] != null ? `iat-mode=${b.params["iat-mode"]}` : undefined,
    remark: b.fingerprint.slice(0, 12),
  }));

  r.links = bridges.map((b) => b.line);
  r.note = `${bridges.length} پل Tor — در torrc با پیشوند Bridge استفاده کن.`;
  r._torBridges = bridges.map((b) => b.line);
  return r;
}

export function formatTorrc(bridges, name) {
  const lines = [];
  if (name) lines.push(`# ${name}`);
  lines.push("UseBridges 1");
  // ClientTransportPlugin left to user/app
  for (const line of bridges) {
    const cleaned = line.replace(/^\s*Bridge\s+/i, "").trim();
    lines.push(`Bridge ${cleaned}`);
  }
  return lines.join("\n");
}
