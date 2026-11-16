import { b64encode, b64decode, hexToBytes, utf8Encode, aesGcmEncrypt, aesGcmDecrypt, utf8 } from "../crypto/util.js";
import { buildVless, buildTrojan, buildSs } from "./format.js";

const SLIP_KEY = hexToBytes("214F052025B2F949605A5429EC3D5FA80C2022C168AD946E68852D447214DBD3");

/**
 * Rebuild shareable config with a new display name.
 * Returns { texts: string[], files: { name, content }[] }
 */
export async function rebrandConfig(result, originalText, newName) {
  const name = String(newName || "").trim().slice(0, 64);
  const out = { texts: [], files: [] };
  if (!name) return out;

  const text = originalText || "";
  const seen = new Set();
  const add = (t) => {
    if (!t || seen.has(t)) return;
    seen.add(t);
    out.texts.push(t);
  };

  // Existing share links only: rewrite #remark (never invent protocol)
  const linkRe = /(vless|vmess|trojan|ss|ssr|hysteria2|hy2|wireguard):\/\/[^\s"'<>]+/gi;
  const fromText = text.match(linkRe) || [];
  for (const raw of fromText) {
    try {
      let l = raw;
      const hash = l.indexOf("#");
      if (hash >= 0) l = l.slice(0, hash);
      add(`${l}#${encodeURIComponent(name)}`);
    } catch {}
  }

  // SlipNet encrypted

  const slip = text.match(/slipnet-enc:\/\/([A-Za-z0-9+/=]+)/i);
  if (slip) {
    try {
      const data = b64decode(slip[1]);
      const pt = utf8(await aesGcmDecrypt(SLIP_KEY, data.slice(1, 13), data.slice(13)));
      const fields = pt.split("|");
      if (fields.length > 2) fields[2] = name.replace(/\|/g, "/");
      const plain = utf8Encode(fields.join("|"));
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const ct = await aesGcmEncrypt(SLIP_KEY, nonce, plain);
      const packed = new Uint8Array(1 + 12 + ct.length);
      packed[0] = data[0] || 1;
      packed.set(nonce, 1);
      packed.set(ct, 13);
      add(`slipnet-enc://${b64encode(packed)}`);
    } catch {}
  }

  const slipPlain = text.match(/slipnet:\/\/([^\s]+)/i);
  if (slipPlain && !slip) {
    try {
      const fields = decodeURIComponent(slipPlain[1]).split("|");
      if (fields.length > 2) fields[2] = name.replace(/\|/g, "/");
      add(`slipnet://${encodeURIComponent(fields.join("|"))}`);
    } catch {}
  }

  // OpenVPN
  if (/^\s*client\b/im.test(text) && /\bremote\s+\S+/i.test(text)) {
    let ovpn = text.replace(/^#.*$/gm, "").trim();
    ovpn = `# ${name}\n${ovpn}`;
    out.files.push({ name: `${safeFile(name)}.ovpn`, content: ovpn });
  }

  // Rocket / SSH-style: keep as labeled text, do NOT fake trojan/vless
  const fmt = String(result.format || "").toLowerCase();
  const proto = String(result.server?.protocol || "").toLowerCase();

  // Telegram MTProto proxy
  if (fmt.includes("telegram proxy") || proto === "mtproto" || /t\.me\/proxy\?/i.test(text) || /tg:\/\/proxy\?/i.test(text)) {
    try {
      const { buildTgProxyLink } = await import("./tgproxy.js");
      const s = result.server || {};
      if (s.host && s.port && s.password) {
        add(`# ${name}\n${buildTgProxyLink(s.host, s.port, s.password)}`);
      }
    } catch {}
  }


  // WireGuard URI rebuild
  if ((fmt.includes("wireguard") || proto === "wireguard" || /wireguard:\/\//i.test(text)) && result.server?.privateKey) {
    try {
      const { buildWireguardLink, buildWgConf } = await import("./sharelink.js");
      const link = buildWireguardLink(result.server, name);
      if (link) add(link);
      const conf = buildWgConf({ ...result.server });
      out.files.push({ name: `${safeFile(name)}.conf`, content: `# ${name}\n${conf}` });
    } catch {}
  }

  const isSshLike =
    fmt.includes("rocket") ||
    proto.includes("ssh") ||
    proto === "ssh+payload" ||
    proto === "ssh_direct";

  if (isSshLike && result.server?.host) {
    const s = result.server;
    // Rocket: rebuild importable rcktnl.site link
    if (fmt.includes("rocket") || /rcktnl\.site\/i\//i.test(text)) {
      try {
        const { buildRocketUrl } = await import("./rocket.js");
        const url = await buildRocketUrl(s, { remark: name });
        add(url);
      } catch {}
    } else {
      const lines = [
        `# ${name}`,
        `protocol: ${s.protocol || "ssh"}`,
        `host: ${s.host}`,
        s.port ? `port: ${s.port}` : null,
        s.user ? `user: ${s.user}` : null,
        s.password ? `password: ${s.password}` : null,
        s.sni ? `sni: ${s.sni}` : null,
        s.payload ? `payload: ${s.payload}` : null,
      ].filter(Boolean);
      add(lines.join("\n"));
    }
  }

  // Tor bridges
  if (fmt.includes("tor") || result._torBridges?.length || /\bobfs4\s+\S+:\d+/i.test(text)) {
    const bridges = result._torBridges || result.links?.filter((l) => /\bobfs4\b|\bsnowflake\b|\bwebtunnel\b/i.test(l)) || [];
    if (bridges.length) {
      const { formatTorrc } = await import("./tor.js");
      add(formatTorrc(bridges, name));
      for (const b of bridges) add(b);
    }
  }

  // ArgoVPN Bridge: keep original signed block (app verifies signature)
  if (fmt.includes("argo") || /BEGIN ARGO VPN BRIDGE BLOCK/i.test(text)) {
    const m = text.match(/-----BEGIN ARGO VPN BRIDGE BLOCK-----[\s\S]*?-----END ARGO VPN BRIDGE BLOCK-----/i);
    const block = result._argoRawBlock || (m && m[0]) || null;
    if (block) {
      add(`# ${name}\n${block}`);
    } else {
      try {
        const { buildArgoBlock } = await import("./argo.js");
        const block2 = await buildArgoBlock(result.server || {}, {
          remark: name,
          signature: result._argoOuter?.signature || "",
          version: result._argoOuter?.version || 1,
        });
        add(`# ${name}\n${block2}`);
      } catch {}
    }
  }

  // WireGuard / AmneziaWG: full .conf with name comment (never fake vless)

  const isWg =
    fmt.includes("wireguard") ||
    fmt.includes("amnezia") ||
    proto.includes("wireguard") ||
    proto.includes("amnezia") ||
    (/\[Interface\]/i.test(text) && /PrivateKey\s*=/i.test(text));
  if (isWg && (/\[Interface\]/i.test(text) || result._rawConf)) {
    let conf = (result._rawConf || text).replace(/^#.*$/gm, "").trim();
    conf = `# ${name}\n${conf}`;
    out.files.push({ name: `${safeFile(name)}.conf`, content: conf });
    add(conf);
  }

  // Build share links only when protocol is actually that type

  const servers = Array.isArray(result.servers) && result.servers.length
    ? result.servers
    : result.server?.host
      ? [result.server]
      : [];

  for (const srv of servers) {
    const s = { ...srv, remark: name };
    const p = String(s.protocol || "").toLowerCase();
    if (p === "vless" && s.uuid) {
      const link = buildVless({ ...s, protocol: "vless", uuid: s.uuid });
      if (link) add(link);
    } else if (p === "trojan" && s.password) {
      const link = buildTrojan(s);
      if (link) add(link);
    } else if ((p === "ss" || p === "shadowsocks") && s.method && s.password) {
      const link = buildSs(s);
      if (link) add(link);
    }
    // never invent links for wireguard/amnezia/ssh from private keys
  }

  // Result links that were produced by decrypt (vless/ss/...)
  for (const l of result.links || []) {
    if (!/^(vless|vmess|trojan|ss|ssr|hysteria2|hy2):\/\//i.test(l)) continue;
    try {
      let x = l;
      const hash = x.indexOf("#");
      if (hash >= 0) x = x.slice(0, hash);
      add(`${x}#${encodeURIComponent(name)}`);
    } catch {}
  }

  if (!out.texts.length && !out.files.length) {
    add(
      `# ${name}\n# فرمت «${result.format || "unknown"}» قابل تبدیل خودکار به لینک قابل‌اشتراک نیست.\n# از دکمه «باز کردن» اطلاعات سرور را ببین.`
    );
  }

  return out;
}

function safeFile(n) {
  return n.replace(/[^\w\u0600-\u06FF-]+/g, "_").slice(0, 40) || "config";
}
