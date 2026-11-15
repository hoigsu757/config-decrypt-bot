import { spawn } from "child_process";
import { mkdtemp, writeFile, readFile, rm, readdir } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { emptyResult, buildVless, buildTrojan, buildSs } from "./format.js";

const BIN = process.env.PANTEGNOS_BIN || "pantegnos";

/**
 * Run Pantegnos batch mode on a single file.
 * Returns unified result or null if binary missing / failed.
 */
export async function tryPantegnos(name, bytes, password) {
  let dir;
  try {
    dir = await mkdtemp(join(tmpdir(), "pg-"));
    const inDir = join(dir, "in");
    const outDir = join(dir, "out");
    await import("fs/promises").then((fs) => fs.mkdir(inDir));
    await import("fs/promises").then((fs) => fs.mkdir(outDir));

    const safe = (name || "file.bin").replace(/[^\w.\u0600-\u06FF-]+/g, "_").slice(0, 80);
    const inPath = join(inDir, safe || "file.bin");
    await writeFile(inPath, bytes);

    const args = ["-input", inDir, "-output", outDir];
    // some versions accept password via env
    const env = { ...process.env };
    if (password) env.PANTEGNOS_PASSWORD = password;

    const { code, stdout, stderr } = await run(BIN, args, env, 120_000);
    const combined = `${stdout}\n${stderr}`;

    // read any output files
    let text = "";
    try {
      const files = await readdir(outDir);
      for (const f of files) {
        text += await readFile(join(outDir, f), "utf8") + "\n";
      }
    } catch {}

    if (!text.trim() && code !== 0) {
      if (/not found|ENOENT/i.test(combined)) return null;
      const r = emptyResult("Pantegnos");
      r.note = `Pantegnos ناموفق بود:\n${combined.slice(0, 400)}`;
      return r;
    }
    if (!text.trim()) {
      // maybe password needed
      if (/passphrase|password|locked/i.test(combined)) {
        const r = emptyResult(detectFormat(name, bytes));
        r.note = "این فایل رمز دارد. بفرست: /pass رمز";
        return r;
      }
      return null;
    }

    return parsePantegnosText(text, name, bytes);
  } catch (e) {
    if (e.code === "ENOENT") return null;
    console.error("pantegnos", e);
    return null;
  } finally {
    if (dir) await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

function run(cmd, args, env, timeout) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    const t = setTimeout(() => {
      child.kill("SIGKILL");
      resolve({ code: -1, stdout, stderr: stderr + "\ntimeout" });
    }, timeout);
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (code) => {
      clearTimeout(t);
      resolve({ code, stdout, stderr });
    });
    child.on("error", (err) => {
      clearTimeout(t);
      resolve({ code: -1, stdout, stderr: String(err) });
    });
  });
}

function detectFormat(name, bytes) {
  if (bytes?.length >= 4) {
    const m = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]);
    if (m === "NPVS") return "NPVS";
  }
  if (/\.ehi$/i.test(name || "")) return "HTTP Injector (.ehi)";
  if (/\.hc$/i.test(name || "")) return "HTTP Custom (.hc)";
  if (/\.npvs$/i.test(name || "")) return "NPVS";
  return "Pantegnos";
}

function parsePantegnosText(text, name, bytes) {
  const r = emptyResult(detectFormat(name, bytes));
  const links = text.match(/(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2):\/\/[^\s"'<>]+/gi) || [];
  for (const l of links) {
    r.links.push(l);
    if (l.startsWith("vless://") && !r.vless) r.vless = l;
  }

  const parsed = extractJson(text);
  const profiles = profilesFrom(parsed);
  if (profiles.length) {
    r.servers = profiles;
    r.server = profiles[0];
    for (const s of profiles) {
      if (s.protocol === "vless" && !r.vless) {
        const link = buildVless(s);
        if (link) {
          r.vless = link;
          r.links.push(link);
        }
      } else if (s.protocol === "trojan") {
        const link = buildTrojan(s);
        if (link) r.links.push(link);
      } else if (s.protocol === "ss") {
        const link = buildSs(s);
        if (link) r.links.push(link);
      }
    }
  } else {
    const jsonMatch = text.match(/\{[\s\S]*"Common"[\s\S]*\}/);
    if (jsonMatch) {
      try {
        const j = JSON.parse(jsonMatch[0]);
        const p = (j.Common || [])[0] || {};
        applyCommon(r, p);
      } catch {}
    }
  }

  if (r.vless) fillFromLink(r, r.vless);
  else if (r.links[0] && !r.server?.host) fillFromLink(r, r.links[0]);

  if (!r.links.length && !r.server?.host) {
    const msg = text
      .split("\n")
      .filter((l) => !l.startsWith("//") && !l.includes("Saved to") && l.trim())
      .slice(0, 8)
      .join("\n")
      .slice(0, 300);
    r.note = msg || "خروجی خالی از Pantegnos";
  }
  return r;
}

function extractJson(text) {
  const start = text.search(/[[{]/);
  if (start < 0) return null;
  const slice = text.slice(start);
  try {
    return JSON.parse(slice);
  } catch {
    const end = Math.max(slice.lastIndexOf("]"), slice.lastIndexOf("}"));
    if (end > 0) {
      try { return JSON.parse(slice.slice(0, end + 1)); } catch {}
    }
  }
  return null;
}

function profilesFrom(parsed) {
  const list = Array.isArray(parsed) ? parsed : parsed ? [parsed] : [];
  const out = [];
  for (const item of list) {
    if (!item || typeof item !== "object") continue;
    if (item.v2rayProfile || item.address || item.type) out.push(fromNpv(item));
    else if (item.Common) {
      const stub = emptyResult("x");
      applyCommon(stub, (item.Common || [])[0] || {});
      if (stub.server.host) out.push(stub.server);
    }
  }
  return out.filter((s) => s.host);
}

function fromNpv(item) {
  const p = item.v2rayProfile || item;
  const addr = String(item.address || "");
  const [addrHost, addrPort] = addr.split(":");
  const host = p.server || addrHost;
  const port = String(p.serverPort || addrPort || "");
  const method = p.method || "";
  const password = p.password || p.id || "";
  const uuidLike = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(password);
  const ssMethod = /^(aes-256-gcm|aes-128-gcm|chacha20-ietf-poly1305|chacha20-poly1305|2022-blake3-aes-256-gcm|2022-blake3-aes-128-gcm)$/i.test(method);
  let protocol = String(item.type || "v2ray").toLowerCase();
  if (uuidLike && (method === "none" || method === "" || p.network)) protocol = "vless";
  else if (ssMethod) protocol = "ss";
  else if (p.network === "tcp" && method === "chacha20-poly1305") protocol = "trojan";

  return {
    protocol,
    host,
    port,
    uuid: protocol === "vless" ? password : undefined,
    password: protocol === "vless" ? undefined : password,
    method: ssMethod ? method : undefined,
    transport: p.network || undefined,
    tls: p.security || undefined,
    security: p.security || undefined,
    sni: p.sni || undefined,
    hostHeader: p.host || undefined,
    path: p.path || undefined,
    alpn: p.alpn || undefined,
    fp: p.fingerPrint || p.fp || undefined,
    mode: p.xhttpMode || p.mode || undefined,
    remark: p.remarks || item.name || undefined,
    encryption: protocol === "vless" ? "none" : undefined,
  };
}

function applyCommon(r, p) {
  r.server.protocol = String(p.Protocol || "vless").toLowerCase();
  r.server.host = p.Hostname || p.Host;
  r.server.port = p.Port;
  r.server.uuid = p.UserID;
  r.server.sni = p.SNI;
  r.server.path = p.Path;
  r.server.transport = (p.TransferProtocol || "tcp").toLowerCase();
  r.server.tls = (p.TLSType || "").toLowerCase();
  r.server.alpn = p.Alpn;
  r.server.remark = p.Remark;
  r.server.encryption = p.EncryptMethod || "none";
  if (r.server.protocol === "vless" && !r.vless) {
    r.vless = buildVless(r.server);
    if (r.vless) r.links.push(r.vless);
  }
}

function fillFromLink(r, link) {
  try {
    if (link.startsWith("vless://")) {
      const u = new URL(link);
      r.server.protocol = "vless";
      r.server.uuid = decodeURIComponent(u.username);
      r.server.host = u.hostname;
      r.server.port = u.port;
      r.server.transport = u.searchParams.get("type") || "tcp";
      r.server.sni = u.searchParams.get("sni");
      r.server.path = u.searchParams.get("path");
      r.server.hostHeader = u.searchParams.get("host");
      r.server.alpn = u.searchParams.get("alpn");
      r.server.fp = u.searchParams.get("fp");
      r.server.tls = u.searchParams.get("security");
      r.server.remark = decodeURIComponent(u.hash.replace(/^#/, ""));
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
      r.server.tls = "tls";
      r.server.remark = decodeURIComponent(u.hash.replace(/^#/, ""));
    }
  } catch {}
}
