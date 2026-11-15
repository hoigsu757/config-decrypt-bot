import { b64encode, b64decode, hexToBytes, utf8Encode, aesGcmEncrypt, aesGcmDecrypt, utf8 } from "../crypto/util.js";

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

  // Share links: rewrite #remark
  const linkRe = /(vless|vmess|trojan|ss|ssr|hysteria2|hy2):\/\/[^\s"'<>]+/gi;
  const links = text.match(linkRe) || result.links || [];
  const seen = new Set();
  for (const raw of links) {
    let l = raw;
    try {
      const hash = l.indexOf("#");
      if (hash >= 0) l = l.slice(0, hash);
      l = `${l}#${encodeURIComponent(name)}`;
    } catch {
      continue;
    }
    if (seen.has(l)) continue;
    seen.add(l);
    out.texts.push(l);
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
      out.texts.push(`slipnet-enc://${b64encode(packed)}`);
    } catch {}
  }

  // plain slipnet://
  const slipPlain = text.match(/slipnet:\/\/([^\s]+)/i);
  if (slipPlain && !slip) {
    try {
      const fields = decodeURIComponent(slipPlain[1]).split("|");
      if (fields.length > 2) fields[2] = name.replace(/\|/g, "/");
      out.texts.push(`slipnet://${encodeURIComponent(fields.join("|"))}`);
    } catch {}
  }

  // OpenVPN: rewrite comments / filename tag
  if (/client\s*$/im.test(text) && /remote\s+\S+/i.test(text)) {
    let ovpn = text.replace(/^#.*$/gm, "").trim();
    ovpn = `# ${name}\n${ovpn}`;
    out.files.push({ name: `${safeFile(name)}.ovpn`, content: ovpn });
  }

  // From decrypted server → vless/trojan/ss with new remark
  if (result.server?.host) {
    const s = { ...result.server, remark: name };
    const { buildVless, buildTrojan, buildSs } = await import("./format.js");
    for (const fn of [buildVless, buildTrojan, buildSs]) {
      try {
        const link = fn(s);
        if (link && !seen.has(link)) {
          seen.add(link);
          out.texts.push(link);
        }
      } catch {}
    }
  }

  // Multiple servers
  if (Array.isArray(result.servers)) {
    const { buildVless, buildTrojan, buildSs } = await import("./format.js");
    for (const srv of result.servers) {
      const s = { ...srv, remark: name };
      for (const fn of [buildVless, buildTrojan, buildSs]) {
        try {
          const link = fn(s);
          if (link && !seen.has(link)) {
            seen.add(link);
            out.texts.push(link);
          }
        } catch {}
      }
    }
  }

  if (!out.texts.length && !out.files.length) {
    out.texts.push(`# ${name}\n# فرمت ${result.format} قابل تبدیل خودکار نیست (مثل NPVS).\n# فقط اطلاعات سرور را با نام جدید نگه دار.`);
  }

  return out;
}

function safeFile(n) {
  return n.replace(/[^\w\u0600-\u06FF-]+/g, "_").slice(0, 40) || "config";
}
