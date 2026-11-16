import { tryShareLink } from "./sharelink.js";
import { tryOvpn } from "./ovpn.js";
import { tryAmnezia } from "./amnezia.js";
import { tryArgo } from "./argo.js";
import { tryRocket } from "./rocket.js";
import { trySlipnet } from "./slipnet.js";
import { tryNetmod } from "./netmod.js";
import { tryV2box } from "./v2box.js";
import { tryPantegnos } from "./pantegnos.js";
import { tryTor } from "./tor.js";
import { tryTgProxy } from "./tgproxy.js";
import { emptyResult } from "./format.js";

function isHeavy(name, bytes) {
  if (bytes?.length >= 4) {
    const m = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]);
    if (m === "NPVS") return true;
  }
  return /\.(npvs|npvt|ehi|hc|hat|dark|happ|bpf|zsx)$/i.test(name || "");
}

export async function openBytes(name, bytes, textHint, password) {
  const text =
    textHint ||
    (() => {
      try {
        return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      } catch {
        return "";
      }
    })();

  // Heavy proprietary → Pantegnos first
  if (isHeavy(name, bytes)) {
    const pg = await tryPantegnos(name, bytes, password);
    if (pg && (pg.links?.length || pg.server?.host || pg.note)) return pg;
  }

  const order = [
    () => tryTgProxy(text),
    () => tryShareLink(text),
    () => tryV2box(name, text, password),
    () => tryOvpn(name, text),
    () => tryAmnezia(text),
    () => tryArgo(text),
    () => tryRocket(name, text),
    () => tryTor(text),
    () => trySlipnet(text, password),
    () => tryNetmod(name, text),
  ];

  for (const fn of order) {
    try {
      const r = await fn();
      if (r) return r;
    } catch (e) {
      console.error("step", e);
    }
  }

  // last resort: pantegnos on anything
  const pg = await tryPantegnos(name, bytes, password);
  if (pg && (pg.links?.length || pg.server?.host)) return pg;

  const r = emptyResult("unknown");
  r.note = `فرمت شناسایی نشد (${name || "file"}, ${bytes.length} bytes).`;
  return r;
}
