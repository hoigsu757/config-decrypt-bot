# Config Decrypt Telegram Bot — Railway

بات کامل دیکریپت کانفیگ VPN با پشتیبانی **Pantegnos** (NPVS / EHI / HC و …).

## قابلیت‌ها

- NPVS, EHI, HC, HAT, DarkTunnel, Happ (از طریق Pantegnos)
- NetMod, SlipNet, V2Box
- OpenVPN, AmneziaWG, ArgoVPN, Rocket Tunnel
- لینک‌های vless / trojan / ss
- خروجی یکدست: **VLESS + جدول سرور**
- دستور `/pass` برای فایل‌های رمزدار

## استقرار روی Railway

1. ریپو را به Railway وصل کن (یا `railway up`)
2. متغیرها:

| Variable | مقدار |
|----------|--------|
| `TELEGRAM_BOT_TOKEN` | توکن BotFather |
| `PUBLIC_URL` | آدرس عمومی سرویس، مثلاً `https://xxx.up.railway.app` |
| `WEBHOOK_SECRET` | اختیاری |
| `USE_POLLING` | `1` اگر وبهوک نخواستی |

3. Deploy — Dockerfile خودش Pantegnos را نصب می‌کند.

### از CLI

```bash
npm i -g @railway/cli
railway login
railway init
railway variables set TELEGRAM_BOT_TOKEN=...
railway variables set PUBLIC_URL=https://your-app.up.railway.app
railway up
```

## لوکال

```bash
cp .env.example .env
# توکن را بگذار
# Pantegnos اختیاری:
# curl -sL ... | tar xz -C /usr/local/bin
USE_POLLING=1 TELEGRAM_BOT_TOKEN=... npm start
```

## ساختار

```
src/
  index.js              # Express + webhook/polling
  telegram/api.js
  crypto/util.js
  decrypt/
    open.js             # dispatcher
    pantegnos.js        # باینری برای فرمت‌های سنگین
    netmod.js slipnet.js v2box.js ...
Dockerfile
railway.toml
```
