import express from "express";
import { sendMessage, downloadFile, tgApi } from "./telegram/api.js";
import { openBytes } from "./decrypt/open.js";
import { formatMessages } from "./decrypt/format.js";
import { rebrandConfig } from "./decrypt/rebrand.js";

const TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const PORT = Number(process.env.PORT || 3000);
const PUBLIC_URL = (process.env.PUBLIC_URL || process.env.RAILWAY_PUBLIC_DOMAIN || "").replace(/\/$/, "");
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || "";
const USE_POLLING = process.env.USE_POLLING === "1" || process.env.USE_POLLING === "true";

/** chatId -> password */
const pendingPass = new Map();
/** chatId -> { result, rawText, fileName } */
const pendingJob = new Map();
/** chatId -> true when waiting for rebrand name */
const waitingName = new Map();

const WELCOME = [
  "👋 خوش اومدی",
  "",
  "کانال: @Meowhub2",
  "",
  "فایل یا لینک کانفیگ رو بفرست تا باز بشه.",
  "",
  "<b>فرمت‌هایی که باز می‌کنم:</b>",
  "• NPVS / NPVT",
  "• HTTP Injector (.ehi)",
  "• HTTP Custom (.hc)",
  "• NetMod (.nm)",
  "• SlipNet",
  "• V2Box",
  "• OpenVPN / AmneziaWG",
  "• ArgoVPN / Rocket Tunnel",
  "• Tor Bridge (obfs4 / snowflake)
  • لینک vless / trojan / ss",
  "",
  "بعد از دریافت فایل دو گزینه می‌بینی:",
  "🔓 باز کردن — اطلاعات سرور",
  "✏️ تبدیل به مال من — اسم می‌ذاری و خروجی با نام خودت",
  "",
  "فایل رمزدار: <code>/pass رمز</code>",
].join("\n");

const START_KEYBOARD = {
  keyboard: [[{ text: "/start" }]],
  resize_keyboard: true,
  is_persistent: true,
};

const ACTION_KEYBOARD = {
  inline_keyboard: [
    [
      { text: "🔓 باز کردن", callback_data: "open" },
      { text: "✏️ تبدیل به مال من", callback_data: "mine" },
    ],
  ],
};

if (!TOKEN) {
  console.error("TELEGRAM_BOT_TOKEN is required");
  process.exit(1);
}

const app = express();
app.use(express.json({ limit: "25mb" }));

app.get("/", (_req, res) => {
  res.json({
    ok: true,
    service: "config-decrypt-bot",
    platform: "railway",
    version: "2.4",
    pantegnos: true,
  });
});

app.post("/webhook", async (req, res) => {
  if (WEBHOOK_SECRET) {
    const secret = req.get("X-Telegram-Bot-Api-Secret-Token");
    if (secret !== WEBHOOK_SECRET) return res.status(403).send("forbidden");
  }
  res.json({ ok: true });
  try {
    await handleUpdate(req.body);
  } catch (e) {
    console.error("handleUpdate", e);
  }
});

app.listen(PORT, async () => {
  console.log(`listening on :${PORT}`);
  if (USE_POLLING) {
    console.log("mode: long-polling");
    try {
      await tgApi(TOKEN, "deleteWebhook", { drop_pending_updates: false });
    } catch {}
    startPolling();
  } else if (PUBLIC_URL) {
    const hook = PUBLIC_URL.startsWith("http") ? `${PUBLIC_URL}/webhook` : `https://${PUBLIC_URL}/webhook`;
    try {
      const body = { url: hook };
      if (WEBHOOK_SECRET) body.secret_token = WEBHOOK_SECRET;
      const r = await tgApi(TOKEN, "setWebhook", body);
      console.log("webhook set:", hook, r);
    } catch (e) {
      console.error("setWebhook failed:", e.message);
      console.log("falling back to polling");
      startPolling();
    }
  } else {
    console.log("PUBLIC_URL not set — using long-polling");
    startPolling();
  }
});

async function startPolling() {
  let offset = 0;
  for (;;) {
    try {
      const updates = await tgApi(TOKEN, "getUpdates", {
        offset,
        timeout: 30,
        allowed_updates: ["message", "callback_query"],
      });
      for (const u of updates) {
        offset = u.update_id + 1;
        await handleUpdate(u);
      }
    } catch (e) {
      console.error("poll", e.message);
      await sleep(2000);
    }
  }
}

async function pulseTyping(chatId) {
  try {
    await tgApi(TOKEN, "sendChatAction", { chat_id: chatId, action: "typing" });
  } catch {}
}

function startTypingLoop(chatId) {
  pulseTyping(chatId);
  return setInterval(() => pulseTyping(chatId), 4000);
}

async function sendResult(chatId, result) {
  const parts = formatMessages(result);
  for (const part of parts) {
    await sendMessage(TOKEN, chatId, part);
  }
}

async function offerActions(chatId, result, rawText, fileName) {
  pendingJob.set(String(chatId), { result, rawText, fileName });
  const fmt = result?.format || "unknown";
  await sendMessage(
    TOKEN,
    chatId,
    `✅ فایل آماده است.\n📦 فرمت: <b>${esc(fmt)}</b>\n\nیکی را انتخاب کن:`,
    { reply_markup: ACTION_KEYBOARD }
  );
}

async function handleCallback(cq) {
  const chatId = cq.message?.chat?.id;
  const data = cq.data;
  if (!chatId) return;
  try {
    await tgApi(TOKEN, "answerCallbackQuery", { callback_query_id: cq.id });
  } catch {}

  const job = pendingJob.get(String(chatId));
  if (!job) {
    await sendMessage(TOKEN, chatId, "لطفاً دوباره فایل را بفرست.");
    return;
  }

  if (data === "open") {
    await sendResult(chatId, job.result);
    return;
  }

  if (data === "mine") {
    waitingName.set(String(chatId), true);
    await sendMessage(
      TOKEN,
      chatId,
      "✏️ اسم جدید کانفیگ را بفرست (مثلاً نام کانال یا برند خودت):"
    );
  }
}

async function doRebrand(chatId, name) {
  const job = pendingJob.get(String(chatId));
  waitingName.delete(String(chatId));
  if (!job) {
    await sendMessage(TOKEN, chatId, "جلسه منقضی شد. دوباره فایل را بفرست.");
    return;
  }

  const typing = startTypingLoop(chatId);
  try {
    const out = await rebrandConfig(job.result, job.rawText, name);
    clearInterval(typing);

    if (out.texts.length) {
      await sendMessage(TOKEN, chatId, `✏️ خروجی با نام <b>${esc(name)}</b>:`);
      for (const t of out.texts) {
        await sendMessage(TOKEN, chatId, `<code>${esc(t)}</code>`);
      }
    }

    for (const f of out.files) {
      await sendDocument(chatId, f.name, f.content);
    }

    if (!out.texts.length && !out.files.length) {
      await sendMessage(TOKEN, chatId, "چیزی برای تبدیل ساخته نشد.");
    }
  } catch (err) {
    clearInterval(typing);
    await sendMessage(TOKEN, chatId, `❌ خطا: <code>${esc(String(err.message || err))}</code>`);
  }
}

async function sendDocument(chatId, filename, content) {
  const form = new FormData();
  form.append("chat_id", String(chatId));
  form.append(
    "document",
    new Blob([content], { type: "application/octet-stream" }),
    filename
  );
  const res = await fetch(`https://api.telegram.org/bot${TOKEN}/sendDocument`, {
    method: "POST",
    body: form,
  });
  const j = await res.json();
  if (!j.ok) throw new Error(j.description || "sendDocument failed");
  return j.result;
}

async function handleUpdate(update) {
  if (update.callback_query) {
    await handleCallback(update.callback_query);
    return;
  }

  const msg = update.message || update.edited_message;
  if (!msg) return;
  const chatId = msg.chat.id;
  const text = (msg.text || msg.caption || "").trim();

  try {
    if (text === "/start" || text === "/help") {
      waitingName.delete(String(chatId));
      await sendMessage(TOKEN, chatId, WELCOME, { reply_markup: START_KEYBOARD });
      return;
    }

    if (text.startsWith("/pass")) {
      const pw = text.replace(/^\/pass(@\w+)?\s*/, "").trim();
      if (!pw) {
        await sendMessage(TOKEN, chatId, "مثال:\n<code>/pass mySecret</code>");
        return;
      }
      pendingPass.set(String(chatId), pw);
      await sendMessage(TOKEN, chatId, "✅ رمز ذخیره شد. حالا فایل را بفرست.");
      return;
    }

    // waiting for rebrand name
    if (waitingName.get(String(chatId)) && text && !text.startsWith("/")) {
      await doRebrand(chatId, text);
      return;
    }

    const password = pendingPass.get(String(chatId)) || null;

    if (msg.document) {
      const typing = startTypingLoop(chatId);
      try {
        const { name, bytes } = await downloadFile(TOKEN, msg.document.file_id);
        const rawText = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
        const result = await openBytes(name, bytes, rawText, password);
        clearInterval(typing);
        await offerActions(chatId, result, rawText, name);
      } catch (err) {
        clearInterval(typing);
        await sendMessage(TOKEN, chatId, `❌ خطا: <code>${esc(String(err.message || err))}</code>`);
      }
      return;
    }

    if (text && !text.startsWith("/")) {
      const typing = startTypingLoop(chatId);
      try {
        const bytes = new TextEncoder().encode(text);
        const result = await openBytes("message.txt", bytes, text, password);
        clearInterval(typing);
        await offerActions(chatId, result, text, "message.txt");
      } catch (err) {
        clearInterval(typing);
        await sendMessage(TOKEN, chatId, `❌ خطا: <code>${esc(String(err.message || err))}</code>`);
      }
    }
  } catch (err) {
    console.error(err);
    try {
      await sendMessage(TOKEN, chatId, `❌ خطا: <code>${esc(String(err.message || err))}</code>`);
    } catch {}
  }
}

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
