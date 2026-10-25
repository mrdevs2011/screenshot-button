#!/usr/bin/env python3
"""Screenshot Button — xavfsiz sessiya (5 daqiqa), tez JPEG + live buffer."""
import glob
import hashlib
import hmac
import os
import secrets
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, jsonify, request

BASE = Path(__file__).resolve().parent
CONFIG_DIR = Path(os.environ.get("SCREENSHOT_CONFIG_DIR") or os.path.expanduser("~/.config/screenshot-button"))
TOKEN_FILE = CONFIG_DIR / "token"
LEGACY_TOKEN_FILE = BASE / ".token"

SESSION_TTL = int(os.environ.get("SESSION_TTL", "300"))  # 5 daqiqa
JPEG_QUALITY = int(os.environ.get("JPEG_QUALITY", "72"))
LIVE_INTERVAL = float(os.environ.get("LIVE_INTERVAL", "0.25"))  # live buffer yangilanishi
MAX_SESSIONS = int(os.environ.get("MAX_SESSIONS", "5"))
MAX_FAILS = 8
FAIL_WINDOW = 300


def load_config_env() -> None:
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
    if LEGACY_TOKEN_FILE.exists():
        new = LEGACY_TOKEN_FILE.read_text().strip()
        LEGACY_TOKEN_FILE.unlink()
    new = new or secrets.token_urlsafe(24)
    fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(new + "\n")
    return new


MASTER_TOKEN = "" if PROXY_MODE else load_token()
# Session imzolash kaliti (har ishga tushishda yangi — restart bo'lsa sessiyalar yopiladi)
SESSION_SECRET = secrets.token_bytes(32)

app = Flask(__name__)

# --- xavfsizlik holati ---
_sessions: dict[str, dict] = {}  # sid -> {exp, ip_hash, ua_hash, created}
_sessions_lock = threading.Lock()
_fails: dict[str, list[float]] = defaultdict(list)
_fails_lock = threading.Lock()
_capture_lock = threading.Lock()

# Live buffer: faol sessiya bo'lganda fon rejimida yangilanadi
_live = {"jpeg": None, "ts": 0.0, "tool": None, "err": None}
_live_stop = threading.Event()
_live_thread: threading.Thread | None = None
_live_lock = threading.Lock()


def _client_ip() -> str:
    # faqat to'g'ridan-to'g'ri (proksi orqali X-Forwarded-For ishonchsiz bo'lishi mumkin)
    return (request.headers.get("X-Real-IP") or request.remote_addr or "").strip()


def _ip_hash(ip: str) -> str:
    return hashlib.sha256((ip or "").encode()).hexdigest()[:16]


def _ua_hash() -> str:
    return hashlib.sha256((request.headers.get("User-Agent") or "").encode()).hexdigest()[:16]


def _prune_sessions() -> None:
    now = time.time()
    dead = [s for s, m in _sessions.items() if m["exp"] <= now]
    for s in dead:
        _sessions.pop(s, None)


def _active_session_count() -> int:
    with _sessions_lock:
        _prune_sessions()
        return len(_sessions)


def _record_fail(ip: str) -> None:
    now = time.time()
    with _fails_lock:
        arr = _fails[ip]
        arr.append(now)
        _fails[ip] = [t for t in arr if now - t < FAIL_WINDOW]


def _is_blocked(ip: str) -> bool:
    now = time.time()
    with _fails_lock:
        arr = [t for t in _fails.get(ip, []) if now - t < FAIL_WINDOW]
        _fails[ip] = arr
        return len(arr) >= MAX_FAILS


def _clear_fails(ip: str) -> None:
    with _fails_lock:
        _fails.pop(ip, None)


def _bearer() -> str:
    h = request.headers.get("Authorization", "")
    if h.lower().startswith("bearer "):
        return h[7:].strip()
    return ""


def _check_master(token: str) -> bool:
    if not MASTER_TOKEN or not token:
        return False
    return hmac.compare_digest(token.encode(), MASTER_TOKEN.encode())


def _make_session(ip: str) -> tuple[str, int]:
    with _sessions_lock:
        _prune_sessions()
        if len(_sessions) >= MAX_SESSIONS:
            # eng eski sessiya o'chiriladi
            oldest = min(_sessions.items(), key=lambda x: x[1]["created"])[0]
            _sessions.pop(oldest, None)
        sid = secrets.token_urlsafe(32)
        exp = int(time.time()) + SESSION_TTL
        _sessions[sid] = {
            "exp": exp,
            "ip_hash": _ip_hash(ip),
            "ua_hash": _ua_hash(),
            "created": time.time(),
        }
    _ensure_live_loop()
    return sid, exp


def _revoke_session(sid: str) -> None:
    with _sessions_lock:
        _sessions.pop(sid, None)
    if _active_session_count() == 0:
        _stop_live_loop()


def _valid_session(sid: str, ip: str) -> bool:
    if not sid:
        return False
    with _sessions_lock:
        _prune_sessions()
        meta = _sessions.get(sid)
        if not meta:
            return False
        if meta["exp"] <= time.time():
            _sessions.pop(sid, None)
            return False
        # IP o'zgarsa ham ruxsat (mobil tarmoq almashtirish), lekin UA keskin o'zgasa yo'q
        if meta["ua_hash"] != _ua_hash():
            return False
        # sliding expiry: har muvaffaqiyatli so'rovda yangilanadi
        meta["exp"] = int(time.time()) + SESSION_TTL
        return True


def display_env() -> dict:
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


def capture_jpeg() -> tuple[bytes | None, str | None, str | None]:
    """(jpeg_bytes, tool, error)"""
    env = display_env()
    attempts: list[list[str]] = []
    if env.get("WAYLAND_DISPLAY") and shutil.which("grim"):
        attempts.append(["grim", "-t", "jpeg", "-q", str(JPEG_QUALITY), "-"])
    if env.get("DISPLAY"):
        # scrot/import faylga yozadi — vaqtinchalik
        pass
    if not attempts and env.get("DISPLAY") and shutil.which("import"):
        # ImageMagick import PPM/JPEG
        attempts.append(["import", "-window", "root", "jpeg:-"])

    errors = []
    for cmd in attempts:
        try:
            r = subprocess.run(cmd, env=env, capture_output=True, timeout=8)
        except subprocess.TimeoutExpired:
            errors.append(f"{cmd[0]}: timeout")
            continue
        if r.returncode == 0 and r.stdout and len(r.stdout) > 100:
            return r.stdout, cmd[0], None
        err = (r.stderr or b"").decode("utf-8", "replace").strip()[:200]
        errors.append(f"{cmd[0]}: {err or r.returncode}")

    # fallback: grim png -> still better than nothing via tempfile path
    if env.get("WAYLAND_DISPLAY") and shutil.which("grim"):
        import tempfile as _tf

        fd, path = _tf.mkstemp(suffix=".jpg", prefix="shot_")
        os.close(fd)
        try:
            r = subprocess.run(
                ["grim", "-t", "jpeg", "-q", str(JPEG_QUALITY), path],
                env=env,
                capture_output=True,
                timeout=8,
            )
            if r.returncode == 0 and os.path.getsize(path) > 100:
                with open(path, "rb") as f:
                    return f.read(), "grim", None
            errors.append(f"grim-file: {(r.stderr or b'').decode('utf-8','replace')[:120]}")
        finally:
            try:
                os.remove(path)
            except OSError:
                pass

    if not attempts and not errors:
        return None, None, "Skrinshot vositasi yoki ekran sessiyasi topilmadi (grim)."
    return None, None, "; ".join(errors) or "capture failed"


def _live_worker() -> None:
    while not _live_stop.wait(LIVE_INTERVAL):
        if _active_session_count() == 0:
            continue
        with _capture_lock:
            data, tool, err = capture_jpeg()
        with _live_lock:
            if data:
                _live["jpeg"] = data
                _live["ts"] = time.time()
                _live["tool"] = tool
                _live["err"] = None
            elif err:
                _live["err"] = err


def _ensure_live_loop() -> None:
    global _live_thread
    with _live_lock:
        if _live_thread and _live_thread.is_alive():
            return
        _live_stop.clear()
        _live_thread = threading.Thread(target=_live_worker, name="live-capture", daemon=True)
        _live_thread.start()


def _stop_live_loop() -> None:
    _live_stop.set()


def _get_live_or_capture(force: bool = False) -> tuple[bytes | None, str | None, str | None, float]:
    """Live buffer yangi bo'lsa darhol qaytaradi (< LIVE_INTERVAL); aks holda yangi capture."""
    now = time.time()
    with _live_lock:
        age = now - _live["ts"] if _live["ts"] else 999
        if not force and _live["jpeg"] and age < (LIVE_INTERVAL + 0.15):
            return _live["jpeg"], _live["tool"], None, age
    with _capture_lock:
        data, tool, err = capture_jpeg()
    if data:
        with _live_lock:
            _live["jpeg"] = data
            _live["ts"] = time.time()
            _live["tool"] = tool
            _live["err"] = None
        return data, tool, None, 0.0
    return None, None, err or "capture failed", 0.0


@app.after_request
def secure(resp):
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; img-src 'self' blob: data:; "
        "style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "connect-src 'self'; base-uri 'none'; form-action 'none"
    )
    origin = request.headers.get("Origin", "")
    # faqat o'zimiz va ma'lum frontendlar — ochiq * yo'q
    if origin and (
        origin.endswith(".vercel.app")
        or origin.endswith(".ngrok-free.dev")
        or origin.endswith(".ngrok-free.app")
        or origin.startswith("http://127.0.0.1")
        or origin.startswith("http://localhost")
    ):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Headers"] = (
            "Authorization, Content-Type, ngrok-skip-browser-warning, X-Session"
        )
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Vary"] = "Origin"
    return resp


@app.route("/api/login", methods=["OPTIONS"])
@app.route("/api/logout", methods=["OPTIONS"])
@app.route("/api/screenshot", methods=["OPTIONS"])
@app.route("/api/session", methods=["OPTIONS"])
def options_ok():
    return ("", 204)


@app.get("/healthz")
def healthz():
    return "ok"


def proxy_to_remote(path: str, method: str = "POST", body: bytes | None = None):
    if not REMOTE_URL:
        return jsonify(error="Kompyuter manzili sozlanmagan (REMOTE_URL)."), 503
    headers = {
        "Authorization": request.headers.get("Authorization", ""),
        "ngrok-skip-browser-warning": "1",
        "Content-Type": request.headers.get("Content-Type", "application/json"),
    }
    if request.headers.get("X-Session"):
        headers["X-Session"] = request.headers.get("X-Session", "")
    req = urllib.request.Request(
        REMOTE_URL + path,
        data=body if body is not None else (request.get_data() or b""),
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return Response(r.read(), status=r.status, mimetype=r.headers.get_content_type())
    except urllib.error.HTTPError as e:
        return Response(e.read(), status=e.code, mimetype=e.headers.get_content_type() or "application/json")
    except Exception:
        return jsonify(error="Kompyuterga ulanib bo'lmadi. U o'chiq yoki tunnel ishlamayapti."), 502


@app.post("/api/login")
def login():
    if PROXY_MODE:
        return proxy_to_remote("/api/login", "POST")
    ip = _client_ip()
    if _is_blocked(ip):
        time.sleep(1.0)
        return jsonify(error="Juda ko'p noto'g'ri urinish. Keyinroq qayta urinib ko'ring."), 429
    token = _bearer()
    if not _check_master(token):
        _record_fail(ip)
        time.sleep(0.6)
        return jsonify(error="Token noto'g'ri."), 401
    _clear_fails(ip)
    sid, exp = _make_session(ip)
    return jsonify(
        session=sid,
        expires_at=exp,
        expires_in=SESSION_TTL,
        ttl=SESSION_TTL,
    )


@app.post("/api/logout")
def logout():
    if PROXY_MODE:
        return proxy_to_remote("/api/logout", "POST")
    sid = (
        request.headers.get("X-Session", "").strip()
        or request.args.get("session", "").strip()
        or _bearer()
    )
    if sid:
        _revoke_session(sid)
    return jsonify(ok=True)


@app.get("/api/session")
def session_info():
    if PROXY_MODE:
        return proxy_to_remote("/api/session", "GET")
    sid = request.headers.get("X-Session", "").strip()
    ip = _client_ip()
    if not _valid_session(sid, ip):
        return jsonify(ok=False, remaining=0), 401
    with _sessions_lock:
        meta = _sessions.get(sid)
        remaining = max(0, int(meta["exp"] - time.time())) if meta else 0
    return jsonify(ok=True, remaining=remaining, ttl=SESSION_TTL)


@app.post("/api/screenshot")
def screenshot():
    if PROXY_MODE:
        return proxy_to_remote("/api/screenshot", "POST")
    ip = _client_ip()
    if _is_blocked(ip):
        time.sleep(0.8)
        return jsonify(error="Juda ko'p noto'g'ri urinish."), 429

    sid = request.headers.get("X-Session", "").strip()
    # orqaga moslik: to'g'ridan-to'g'ri master token (lekin sessiya ochilmaydi — sekinroq yo'l)
    auth = _bearer()
    ok = False
    if sid and _valid_session(sid, ip):
        ok = True
    elif _check_master(auth):
        # master token bilan ham ishlaydi, lekin live buffer yo'q bo'lishi mumkin
        ok = True
        _clear_fails(ip)
    else:
        _record_fail(ip)
        time.sleep(0.5)
        return jsonify(error="Sessiya yaroqsiz yoki muddati tugagan. Qayta kiring."), 401

    force = request.args.get("fresh") == "1" or request.headers.get("X-Fresh") == "1"
    t0 = time.perf_counter()
    data, tool, err, age = _get_live_or_capture(force=force)
    ms = int((time.perf_counter() - t0) * 1000)
    if err or not data:
        return jsonify(error=err or "capture failed"), 500

    name = "skrinshot_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".jpg"
    return Response(
        data,
        mimetype="image/jpeg",
        headers={
            "Content-Disposition": f'inline; filename="{name}"',
            "X-Capture-Tool": tool or "",
            "X-Capture-Ms": str(ms),
            "X-Buffer-Age-Ms": str(int(age * 1000)),
        },
    )


PAGE = r"""<!doctype html>
<html lang="uz">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Skrinshot</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:#000;color:#eee;font:16px/1.5 system-ui,sans-serif;display:flex;flex-direction:column;align-items:center;padding:24px 16px;gap:14px}
h1{font-size:18px;font-weight:600;margin:0;color:#aaa}
button,input,a{font:inherit}
.shoot{width:100%;max-width:420px;padding:18px;background:#fff;color:#000;border:0;font-weight:600;font-size:18px;cursor:pointer}
.shoot:disabled{opacity:.4;cursor:wait}
.row{display:flex;gap:8px;width:100%;max-width:420px}
input{flex:1;padding:12px;background:#111;color:#eee;border:1px solid #333}
.small{padding:12px 16px;background:#222;color:#eee;border:1px solid #333;cursor:pointer;text-decoration:none;text-align:center}
.small.danger{border-color:#7f1d1d;color:#fca5a5}
#msg{min-height:1.5em;color:#aaa;font-size:14px;text-align:center}
#msg.err{color:#f87171}
#out{display:none;width:100%;max-width:1100px;flex-direction:column;gap:10px;align-items:center}
#out img{width:100%;height:auto;border:1px solid #333}
#bar{width:100%;max-width:420px;display:none;justify-content:space-between;align-items:center;gap:8px;font-size:13px;color:#888}
#bar button{padding:8px 12px}
</style>
</head>
<body>
<h1>Kompyuter skrinshoti</h1>
<div class="row" id="tokenRow"><input id="token" type="password" placeholder="Token" autocomplete="off" inputmode="text"><button class="small" id="save">Kirish</button></div>
<div id="bar"><span id="ttl"></span><button class="small danger" id="logout">Chiqish</button></div>
<button class="shoot" id="shoot" disabled>Skrinshot qilish</button>
<div id="msg"></div>
<div id="out"><img id="img" alt="Skrinshot"><a class="small" id="dl">Yuklab olish</a></div>
<script>
const $ = (id) => document.getElementById(id);
const SKEY = "shot_session_v2";
const base = (location.pathname.replace(/\/+$/, "") || "") + "/";
let session = null;
let expAt = 0;
let blobUrl = null;
let timer = null;
let pingTimer = null;

try {
  const raw = sessionStorage.getItem(SKEY);
  if (raw) {
    const o = JSON.parse(raw);
    if (o && o.session && o.expAt > Date.now()) {
      session = o.session;
      expAt = o.expAt;
    }
  }
} catch (e) {}

function setMsg(t, err) { $("msg").textContent = t || ""; $("msg").className = err ? "err" : ""; }

function persist() {
  try {
    if (session && expAt > Date.now())
      sessionStorage.setItem(SKEY, JSON.stringify({ session, expAt }));
    else sessionStorage.removeItem(SKEY);
  } catch (e) {}
}

function clearSession() {
  session = null;
  expAt = 0;
  persist();
  if (timer) { clearInterval(timer); timer = null; }
  if (pingTimer) { clearInterval(pingTimer); pingTimer = null; }
  refresh();
}

function remainingSec() {
  return Math.max(0, Math.floor((expAt - Date.now()) / 1000));
}

function fmt(s) {
  const m = Math.floor(s / 60), r = s % 60;
  return m + ":" + String(r).padStart(2, "0");
}

function refresh() {
  const ok = !!(session && remainingSec() > 0);
  $("tokenRow").style.display = ok ? "none" : "flex";
  $("bar").style.display = ok ? "flex" : "none";
  $("shoot").disabled = !ok;
  if (ok) $("ttl").textContent = "Sessiya: " + fmt(remainingSec());
  else $("ttl").textContent = "";
}

function tick() {
  if (!session) return;
  if (remainingSec() <= 0) {
    clearSession();
    setMsg("Sessiya tugadi (5 daqiqa). Qayta kiring.", true);
    return;
  }
  refresh();
}

async function api(path, opts = {}) {
  const headers = Object.assign({
    "ngrok-skip-browser-warning": "1",
  }, opts.headers || {});
  if (session) headers["X-Session"] = session;
  const r = await fetch(base + path.replace(/^\//, ""), Object.assign({}, opts, { headers }));
  return r;
}

$("save").onclick = async () => {
  const v = $("token").value.trim();
  if (!v) return;
  $("save").disabled = true;
  setMsg("Kirish...");
  try {
    const r = await fetch(base + "api/login", {
      method: "POST",
      headers: {
        Authorization: "Bearer " + v,
        "ngrok-skip-browser-warning": "1",
      },
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || ("Xato: " + r.status));
    session = j.session;
    expAt = Date.now() + (j.expires_in || 300) * 1000;
    $("token").value = "";
    persist();
    if (timer) clearInterval(timer);
    timer = setInterval(tick, 1000);
    if (pingTimer) clearInterval(pingTimer);
    pingTimer = setInterval(async () => {
      if (!session) return;
      try {
        const r = await api("api/session");
        if (r.status === 401) {
          clearSession();
          setMsg("Sessiya tugadi. Qayta kiring.", true);
        } else if (r.ok) {
          const j = await r.json();
          if (typeof j.remaining === "number") {
            expAt = Date.now() + j.remaining * 1000;
            persist();
          }
        }
      } catch (e) {}
    }, 30000);
    refresh();
    setMsg("Kirildi. Sessiya 5 daqiqa (faollikda uzayadi).");
  } catch (e) {
    setMsg(e.message || String(e), true);
  } finally {
    $("save").disabled = false;
  }
};

$("logout").onclick = async () => {
  try { await api("api/logout", { method: "POST" }); } catch (e) {}
  clearSession();
  setMsg("Chiqildi.");
};

$("shoot").onclick = async () => {
  if (!session || remainingSec() <= 0) {
    clearSession();
    setMsg("Avval kiring.", true);
    return;
  }
  const btn = $("shoot");
  btn.disabled = true;
  const t0 = performance.now();
  setMsg("...");
  try {
    const r = await api("api/screenshot", { method: "POST" });
    if (r.status === 401) {
      clearSession();
      throw new Error("Sessiya tugadi. Qayta kiring.");
    }
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      throw new Error(j.error || ("Xato: " + r.status));
    }
    const blob = await r.blob();
    if (blobUrl) URL.revokeObjectURL(blobUrl);
    blobUrl = URL.createObjectURL(blob);
    const name = "skrinshot_" + new Date().toISOString().replace(/[:.]/g, "-") + ".jpg";
    $("img").src = blobUrl;
    $("dl").href = blobUrl;
    $("dl").download = name;
    $("out").style.display = "flex";
    const ms = Math.round(performance.now() - t0);
    const serverMs = r.headers.get("X-Capture-Ms") || "?";
    const age = r.headers.get("X-Buffer-Age-Ms") || "?";
    setMsg("Tayyor: " + ms + " ms (server " + serverMs + " ms, buffer " + age + " ms)");
    // sessiya sliding
    expAt = Date.now() + 300000;
    persist();
    refresh();
  } catch (e) {
    setMsg(e.message || String(e), true);
  } finally {
    btn.disabled = !(session && remainingSec() > 0);
  }
};

if (session && remainingSec() > 0) {
  timer = setInterval(tick, 1000);
  pingTimer = setInterval(async () => {
    try {
      const r = await api("api/session");
      if (r.status === 401) { clearSession(); setMsg("Sessiya tugadi. Qayta kiring.", true); }
    } catch (e) {}
  }, 30000);
}
refresh();

// sahifa yopilganda sessiya serverda ham yopiladi (best-effort)
window.addEventListener("pagehide", () => {
  if (!session) return;
  try {
    const u = base + "api/logout?session=" + encodeURIComponent(session);
    navigator.sendBeacon(u);
  } catch (e) {}
});
</script>
</body>
</html>
"""


@app.get("/")
def index():
    return Response(PAGE, mimetype="text/html")


if __name__ == "__main__":
    print(f"Skrinshot serveri: http://{HOST}:{PORT}", flush=True)
    if not PROXY_MODE:
        print(f"Token: {TOKEN_FILE}", flush=True)
        print(f"Sessiya TTL: {SESSION_TTL}s | JPEG q={JPEG_QUALITY} | live={LIVE_INTERVAL}s", flush=True)
    try:
        from waitress import serve
    except ImportError:
        app.run(host=HOST, port=PORT, threaded=True)
    else:
        serve(app, host=HOST, port=PORT, threads=8)
