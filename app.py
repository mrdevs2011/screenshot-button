#!/usr/bin/env python3
"""Screenshot Button: tugmani bosing, kompyuter ekrani skrinshot qilinib sizga keladi."""
import glob
import hmac
import os
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, jsonify, request

BASE = Path(__file__).resolve().parent
# Kompyuterga xos sozlamalar va token kod papkasidan tashqarida turadi.
CONFIG_DIR = Path(os.environ.get("SCREENSHOT_CONFIG_DIR") or os.path.expanduser("~/.config/screenshot-button"))
TOKEN_FILE = CONFIG_DIR / "token"
LEGACY_TOKEN_FILE = BASE / ".token"


def load_config_env() -> None:
    """CONFIG_DIR/config.env dagi KEY=VALUE qatorlarini o'qiydi (muhit o'zgaruvchisi ustun turadi)."""
    path = CONFIG_DIR / "config.env"
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_config_env()
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8765"))

# Proksi rejimi: Vercel'da (yoki REMOTE_URL berilganda) hech narsa yozilmaydi va skrinshot olinmaydi,
# so'rov kompyuterdagi serverga uzatiladi. Token Vercel'da saqlanmaydi.
ON_VERCEL = bool(os.environ.get("VERCEL"))
REMOTE_URL = os.environ.get("REMOTE_URL", "").strip().rstrip("/")
PROXY_MODE = ON_VERCEL or bool(REMOTE_URL)


def load_token() -> str:
    env = os.environ.get("SCREENSHOT_TOKEN", "").strip()
    if env:
        return env
    if TOKEN_FILE.exists():
        saved = TOKEN_FILE.read_text().strip()
        if saved:
            return saved
    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    new = ""
    if LEGACY_TOKEN_FILE.exists():  # eski joydan ko'chirish
        new = LEGACY_TOKEN_FILE.read_text().strip()
        LEGACY_TOKEN_FILE.unlink()
    new = new or secrets.token_urlsafe(24)
    fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(new + "\n")
    return new


TOKEN = "" if PROXY_MODE else load_token()
CAPTURE_LOCK = threading.Lock()
app = Flask(__name__)


def display_env() -> dict:
    """Wayland/X11 sessiyasini avtomatik topadi (server terminaldan ishga tushsa ham ishlaydi)."""
    env = os.environ.copy()
    runtime = env.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    env["XDG_RUNTIME_DIR"] = runtime
    if not env.get("WAYLAND_DISPLAY"):
        socks = sorted(p for p in glob.glob(os.path.join(runtime, "wayland-*")) if not p.endswith(".lock"))
        if socks:
            env["WAYLAND_DISPLAY"] = os.path.basename(socks[0])
    if not env.get("DISPLAY") and os.path.exists("/tmp/.X11-unix/X0"):
        env["DISPLAY"] = ":0"
    return env


def capture(path: str):
    """Skrinshot oladi. (vosita_nomi, None) yoki (None, xato_matni) qaytaradi."""
    env = display_env()
    attempts = []
    if env.get("WAYLAND_DISPLAY") and shutil.which("grim"):
        attempts.append(["grim", path])
    if env.get("DISPLAY"):
        if shutil.which("scrot"):
            attempts.append(["scrot", "-o", path])
        if shutil.which("import"):
            attempts.append(["import", "-window", "root", path])
    if not attempts:
        return None, "Skrinshot vositasi yoki ekran sessiyasi topilmadi (grim/scrot/import)."
    errors = []
    for cmd in attempts:
        try:
            r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired:
            errors.append(f"{cmd[0]}: vaqt tugadi")
            continue
        if r.returncode == 0 and os.path.exists(path) and os.path.getsize(path) > 0:
            return cmd[0], None
        errors.append(f"{cmd[0]}: {(r.stderr or '').strip()[:200]}")
    return None, "; ".join(errors)


def authorized() -> bool:
    header = request.headers.get("Authorization", "")
    supplied = header[7:] if header.lower().startswith("bearer ") else ""
    return hmac.compare_digest(supplied.strip().encode(), TOKEN.encode())


@app.after_request
def secure(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    # Brauzerdan to'g'ridan-to'g'ri (Vercel sahifasi yoki boshqa origin) chaqirish uchun
    origin = request.headers.get("Origin", "*")
    resp.headers["Access-Control-Allow-Origin"] = origin if origin else "*"
    resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, ngrok-skip-browser-warning"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Vary"] = "Origin"
    return resp


@app.route("/api/screenshot", methods=["OPTIONS"])
def screenshot_options():
    return ("", 204)


@app.get("/healthz")
def healthz():
    return "ok"


def proxy_screenshot():
    """So'rovni kompyuterdagi serverga uzatadi (Authorization sarlavhasi o'zgarishsiz o'tadi)."""
    if not REMOTE_URL:
        return jsonify(error="Kompyuter manzili sozlanmagan (REMOTE_URL)."), 503
    req = urllib.request.Request(
        REMOTE_URL + "/api/screenshot",
        data=b"",
        method="POST",
        headers={
            "Authorization": request.headers.get("Authorization", ""),
            "ngrok-skip-browser-warning": "1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return Response(r.read(), status=r.status, mimetype=r.headers.get_content_type())
    except urllib.error.HTTPError as e:
        return Response(e.read(), status=e.code, mimetype=e.headers.get_content_type() or "application/json")
    except Exception:
        return jsonify(error="Kompyuterga ulanib bo'lmadi. U o'chiq yoki tunnel ishlamayapti."), 502


@app.post("/api/screenshot")
def screenshot():
    if PROXY_MODE:
        return proxy_screenshot()
    if not authorized():
        time.sleep(0.5)
        return jsonify(error="Token noto'g'ri."), 401
    with CAPTURE_LOCK:
        fd, path = tempfile.mkstemp(suffix=".png", prefix="shot_")
        os.close(fd)
        try:
            tool, err = capture(path)
            if err:
                return jsonify(error=err), 500
            with open(path, "rb") as f:
                data = f.read()
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
    name = "skrinshot_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".png"
    return Response(
        data,
        mimetype="image/png",
        headers={"Content-Disposition": f'inline; filename="{name}"', "X-Capture-Tool": tool},
    )


PAGE = """<!doctype html>
<html lang="uz">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Skrinshot</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:#000;color:#eee;font:16px/1.5 system-ui,sans-serif;display:flex;flex-direction:column;align-items:center;padding:24px 16px;gap:16px}
h1{font-size:18px;font-weight:600;margin:0;color:#aaa}
button,input,a{font:inherit}
.shoot{width:100%;max-width:420px;padding:18px;background:#fff;color:#000;border:0;font-weight:600;font-size:18px;cursor:pointer}
.shoot:disabled{opacity:.4;cursor:wait}
.row{display:flex;gap:8px;width:100%;max-width:420px}
input{flex:1;padding:12px;background:#111;color:#eee;border:1px solid #333}
.small{padding:12px 16px;background:#222;color:#eee;border:1px solid #333;cursor:pointer;text-decoration:none;text-align:center}
#msg{min-height:1.5em;color:#aaa;font-size:14px}
#msg.err{color:#f87171}
#out{display:none;width:100%;max-width:1100px;flex-direction:column;gap:10px;align-items:center}
#out img{width:100%;height:auto;border:1px solid #333}
</style>
</head>
<body>
<h1>Kompyuter skrinshoti</h1>
<div class="row" id="tokenRow"><input id="token" type="password" placeholder="Token" autocomplete="off"><button class="small" id="save">Saqlash</button></div>
<div class="row" id="remoteRow" style="display:none"><input id="remote" type="url" placeholder="Kompyuter manzili (https://..../shot)" autocomplete="off"><button class="small" id="saveRemote">Saqlash</button></div>
<button class="shoot" id="shoot">Skrinshot qilish</button>
<div id="msg"></div>
<div id="out"><img id="img" alt="Skrinshot"><a class="small" id="dl">Yuklab olish</a></div>
<script>
const $ = (id) => document.getElementById(id);
const KEY = "shot_token";
const RKEY = "shot_remote";
let token = "";
let remote = "";
try { token = localStorage.getItem(KEY) || ""; } catch (e) {}
try { remote = (localStorage.getItem(RKEY) || "").replace(/\/+$/, ""); } catch (e) {}
let blobUrl = null;
function setMsg(t, err) { $("msg").textContent = t; $("msg").className = err ? "err" : ""; }
function needsRemote() {
  // Vercel yoki boshqa proksi host: agar remote saqlanmagan bo'lsa so'raymiz
  const h = location.hostname;
  return h.endsWith(".vercel.app") || h.endsWith(".vercel.sh");
}
function refresh() {
  $("tokenRow").style.display = token ? "none" : "flex";
  $("remoteRow").style.display = (needsRemote() && !remote) ? "flex" : "none";
}
$("save").onclick = () => {
  const v = $("token").value.trim();
  if (!v) return;
  token = v;
  try { localStorage.setItem(KEY, v); } catch (e) {}
  $("token").value = "";
  refresh();
  setMsg("Token saqlandi.");
};
$("saveRemote").onclick = () => {
  let v = $("remote").value.trim().replace(/\/+$/, "");
  if (!v) return;
  if (!/^https?:\/\//i.test(v)) v = "https://" + v;
  remote = v.replace(/\/+$/, "");
  try { localStorage.setItem(RKEY, remote); } catch (e) {}
  $("remote").value = "";
  refresh();
  setMsg("Kompyuter manzili saqlandi.");
};
$("shoot").onclick = async () => {
  if (!token) { setMsg("Avval tokenni kiriting.", true); return; }
  if (needsRemote() && !remote) { setMsg("Kompyuter manzilini kiriting (ngrok /shot).", true); refresh(); return; }
  const btn = $("shoot");
  btn.disabled = true;
  setMsg("Skrinshot olinmoqda...");
  try {
    let url;
    if (remote) {
      url = remote + "/api/screenshot";
    } else {
      const base = (location.pathname.replace(/\/+$/, "") || "") + "/";
      url = base + "api/screenshot";
    }
    const r = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: "Bearer " + token,
        "ngrok-skip-browser-warning": "1"
      }
    });
    if (r.status === 401) {
      token = "";
      try { localStorage.removeItem(KEY); } catch (e) {}
      refresh();
      throw new Error("Token noto'g'ri. Qayta kiriting.");
    }
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      throw new Error(j.error || ("Xato: " + r.status));
    }
    const blob = await r.blob();
    if (blobUrl) URL.revokeObjectURL(blobUrl);
    blobUrl = URL.createObjectURL(blob);
    const name = "skrinshot_" + new Date().toISOString().replace(/[:.]/g, "-") + ".png";
    $("img").src = blobUrl;
    $("dl").href = blobUrl;
    $("dl").download = name;
    $("out").style.display = "flex";
    setMsg("Tayyor: " + new Date().toLocaleTimeString());
  } catch (e) {
    setMsg(e.message || String(e), true);
  } finally {
    btn.disabled = false;
  }
};
refresh();
</script>
</body>
</html>"""


@app.get("/")
def index():
    return Response(PAGE, mimetype="text/html")


if __name__ == "__main__":
    print(f"Skrinshot serveri: http://{HOST}:{PORT}", flush=True)
    print(f"Token faylda: {TOKEN_FILE}", flush=True)
    try:
        from waitress import serve
    except ImportError:
        app.run(host=HOST, port=PORT, threaded=True)
    else:
        serve(app, host=HOST, port=PORT, threads=4)
