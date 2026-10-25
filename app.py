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

SESSION_TTL = int(os.environ.get("SESSION_TTL", "300"))  # so'rovlar orasidagi faolsizlik limiti (sekund)
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
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<meta name="theme-color" content="#0a0a0a">
<title>·</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:#0a0a0a;color:#e5e5e5;font:13px/1.35 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;-webkit-tap-highlight-color:transparent}
body{
  min-height:100dvh;
  display:flex;flex-direction:column;
  padding:0;
  padding-top:env(safe-area-inset-top);
  padding-bottom:env(safe-area-inset-bottom);
  padding-left:env(safe-area-inset-left);
  padding-right:env(safe-area-inset-right);
}
header{
  display:flex;align-items:center;gap:6px;flex-wrap:wrap;
  padding:8px 10px;
  border-bottom:1px solid #222;
  background:#0a0a0a;
  flex-shrink:0;
}
input{
  flex:1;min-width:80px;max-width:200px;
  height:36px;width:36px;
  padding:0 10px;
  background:#111;color:#e5e5e5;
  border:1px solid #333;border-radius:0;
  outline:none;font:inherit;
}
input:focus{border-color:#666}
button,.btn{
  width:36px;height:36px;min-width:36px;padding:0;
  border:1px solid #333;border-radius:0;
  background:#111;color:#e5e5e5;
  font:inherit;font-size:14px;font-weight:600;
  cursor:pointer;user-select:none;
  display:inline-flex;align-items:center;justify-content:center;
  text-decoration:none;flex-shrink:0;
}
button:disabled{opacity:.35;cursor:not-allowed}
#go,#shot{background:#e5e5e5;color:#0a0a0a;border-color:#e5e5e5}
#shot{font-size:16px}
#logout{color:#888;border-color:#2a2a2a;background:transparent}
#logout:hover{color:#f87171;border-color:#7f1d1d}
#msg{min-height:0;font-size:11px;color:#555;text-align:center;padding:0 8px}
#msg.err{color:#f87171;padding:4px 8px}
main{
  flex:1;min-height:0;
  display:flex;flex-direction:column;
  padding:8px 10px 10px;
  gap:6px;
}
#stage{display:none;flex:1;min-height:0;flex-direction:column}
.frame{
  flex:1;min-height:120px;
  width:100%;
  border:1px solid #333;
  background:#000;
  overflow:hidden;
  position:relative;
  touch-action:none;
  cursor:grab;
}
.frame.drag{cursor:grabbing}
.frame img{
  position:absolute;left:50%;top:50%;
  transform-origin:center center;
  max-width:none;
  user-select:none;-webkit-user-drag:none;pointer-events:none;
}
.spacer{flex:1;min-width:4px}
@media (min-width:768px){
  header{padding:10px 14px;gap:8px}
  button,.btn,input{height:40px}
  button,.btn{width:40px;min-width:40px}
  input{max-width:240px}
  main{padding:12px 14px 14px}
}
</style>
</head>
<body>
<header>
  <input id="token" type="password" placeholder="parol" autocomplete="current-password" enterkeyhint="go" style="display:none">
  <button type="button" id="go" title="Enter" style="display:none">→</button>
  <button type="button" id="shot" title="Space / Enter / S" disabled>●</button>
  <button type="button" id="zout" title="-" disabled>−</button>
  <button type="button" id="zfit" title="fit" disabled>⊡</button>
  <button type="button" id="zin" title="+" disabled>+</button>
  <a class="btn" id="dl" download title="Download" style="pointer-events:none;opacity:.35">↓</a>
  <span class="spacer"></span>
  <button type="button" id="logout" title="Esc / L" style="display:none">✕</button>
</header>
<div id="msg"></div>
<main>
  <div id="stage"><div class="frame" id="frame"><img id="img" alt=""></div></div>
</main>
<script>
const $ = (id) => document.getElementById(id);
const SKEY = "shot_session_v3";
const IDLE_MS = 5 * 60 * 1000;
const base = (location.pathname.replace(/\/+$/, "") || "") + "/";
let session = null, blobUrl = null, idleTimer = null, pingTimer = null, busy = false, lastAct = 0;
let scale = 1, tx = 0, ty = 0, natW = 0, natH = 0, fit = 1;
let dragging = false, lx = 0, ly = 0;
let pins = new Map();
let hasImg = false;

try {
  const raw = sessionStorage.getItem(SKEY);
  if (raw) {
    const o = JSON.parse(raw);
    if (o && o.session) {
      session = o.session;
      lastAct = o.lastAct || Date.now();
      if (Date.now() - lastAct >= IDLE_MS) { session = null; lastAct = 0; sessionStorage.removeItem(SKEY); }
    }
  }
} catch (e) {}

function setMsg(t, err) { $("msg").textContent = t || ""; $("msg").className = err ? "err" : ""; }
function persist() {
  try {
    if (session) sessionStorage.setItem(SKEY, JSON.stringify({ session, lastAct }));
    else sessionStorage.removeItem(SKEY);
  } catch (e) {}
}
function touch() {
  lastAct = Date.now(); persist();
  if (session) armIdle();
}
function clearSession() {
  session = null; lastAct = 0; persist();
  if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
  if (pingTimer) { clearInterval(pingTimer); pingTimer = null; }
  refresh();
}
function armIdle() {
  if (idleTimer) clearTimeout(idleTimer);
  const left = IDLE_MS - (Date.now() - lastAct);
  idleTimer = setTimeout(() => {
    if (!session) return;
    if (Date.now() - lastAct >= IDLE_MS) doLogout(true);
    else armIdle();
  }, Math.max(500, left));
}
function refresh() {
  const ok = !!session;
  $("token").style.display = ok ? "none" : "";
  $("go").style.display = ok ? "none" : "";
  $("logout").style.display = ok ? "" : "none";
  $("shot").disabled = !ok || busy;
  $("zout").disabled = !hasImg;
  $("zfit").disabled = !hasImg;
  $("zin").disabled = !hasImg;
  const dl = $("dl");
  if (hasImg && blobUrl) {
    dl.style.pointerEvents = "";
    dl.style.opacity = "1";
  } else {
    dl.style.pointerEvents = "none";
    dl.style.opacity = ".35";
  }
}

function calcFit() {
  const fr = $("frame");
  if (!natW || !natH || !fr.clientWidth) return 1;
  return Math.min(fr.clientWidth / natW, fr.clientHeight / natH);
}
function applyTransform() {
  const img = $("img");
  const s = fit * scale;
  img.style.width = natW + "px";
  img.style.height = natH + "px";
  img.style.transform = "translate(-50%,-50%) translate(" + tx + "px," + ty + "px) scale(" + s + ")";
}
function resetView() {
  fit = calcFit();
  scale = 1; tx = 0; ty = 0;
  applyTransform();
}
function zoomBy(factor, cx, cy) {
  if (!hasImg) return;
  const fr = $("frame");
  const rect = fr.getBoundingClientRect();
  const px = (cx != null ? cx : rect.left + rect.width / 2) - rect.left - rect.width / 2;
  const py = (cy != null ? cy : rect.top + rect.height / 2) - rect.top - rect.height / 2;
  const prev = scale;
  scale = Math.min(8, Math.max(1, scale * factor));
  if (scale === 1) { tx = 0; ty = 0; }
  else {
    const k = scale / prev;
    tx = px - (px - tx) * k;
    ty = py - (py - ty) * k;
  }
  applyTransform();
}

$("frame").addEventListener("wheel", (e) => {
  e.preventDefault();
  zoomBy(e.deltaY < 0 ? 1.12 : 1 / 1.12, e.clientX, e.clientY);
  touch();
}, { passive: false });
$("frame").addEventListener("pointerdown", (e) => {
  if (e.pointerType === "touch") return;
  dragging = true; lx = e.clientX; ly = e.clientY;
  $("frame").classList.add("drag");
  $("frame").setPointerCapture(e.pointerId);
  touch();
});
$("frame").addEventListener("pointermove", (e) => {
  if (!dragging || e.pointerType === "touch") return;
  if (scale <= 1) return;
  tx += e.clientX - lx; ty += e.clientY - ly;
  lx = e.clientX; ly = e.clientY;
  applyTransform();
});
function endDrag() { dragging = false; $("frame").classList.remove("drag"); }
$("frame").addEventListener("pointerup", endDrag);
$("frame").addEventListener("pointercancel", endDrag);
$("frame").addEventListener("touchstart", (e) => {
  touch();
  for (const t of e.changedTouches) pins.set(t.identifier, { x: t.clientX, y: t.clientY });
}, { passive: true });
$("frame").addEventListener("touchmove", (e) => {
  e.preventDefault();
  if (e.touches.length === 1 && scale > 1) {
    const t = e.touches[0];
    const p = pins.get(t.identifier);
    if (p) { tx += t.clientX - p.x; ty += t.clientY - p.y; applyTransform(); }
    pins.set(t.identifier, { x: t.clientX, y: t.clientY });
  } else if (e.touches.length === 2) {
    const a = e.touches[0], b = e.touches[1];
    const pa = pins.get(a.identifier), pb = pins.get(b.identifier);
    if (pa && pb) {
      const d0 = Math.hypot(pa.x - pb.x, pa.y - pb.y) || 1;
      const d1 = Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY);
      zoomBy(d1 / d0, (a.clientX + b.clientX) / 2, (a.clientY + b.clientY) / 2);
    }
    pins.set(a.identifier, { x: a.clientX, y: a.clientY });
    pins.set(b.identifier, { x: b.clientX, y: b.clientY });
  }
}, { passive: false });
$("frame").addEventListener("touchend", (e) => { for (const t of e.changedTouches) pins.delete(t.identifier); });
$("frame").addEventListener("touchcancel", (e) => { for (const t of e.changedTouches) pins.delete(t.identifier); });

$("zin").onclick = () => { zoomBy(1.25); touch(); };
$("zout").onclick = () => { zoomBy(1 / 1.25); touch(); };
$("zfit").onclick = () => { resetView(); touch(); };
window.addEventListener("resize", () => { if (hasImg) resetView(); });

async function api(path, opts = {}) {
  const headers = Object.assign({ "ngrok-skip-browser-warning": "1" }, opts.headers || {});
  if (session) headers["X-Session"] = session;
  return fetch(base + path.replace(/^\//, ""), Object.assign({}, opts, { headers }));
}
async function doLogin() {
  const v = $("token").value.trim();
  if (!v || busy) return;
  busy = true; $("go").disabled = true; setMsg("");
  try {
    const r = await fetch(base + "api/login", {
      method: "POST",
      headers: { Authorization: "Bearer " + v, "ngrok-skip-browser-warning": "1" },
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || String(r.status));
    session = j.session; $("token").value = "";
    touch(); startPing(); refresh();
  } catch (e) { setMsg("·", true); }
  finally { busy = false; $("go").disabled = false; }
}
function startPing() {
  if (pingTimer) clearInterval(pingTimer);
  pingTimer = setInterval(async () => {
    if (!session) return;
    if (Date.now() - lastAct >= IDLE_MS) { doLogout(true); return; }
    try { const r = await api("api/session"); if (r.status === 401) clearSession(); } catch (e) {}
  }, 30000);
}
async function doLogout(silent) {
  try { if (session) await api("api/logout", { method: "POST" }); } catch (e) {}
  clearSession();
  if (!silent) setMsg("");
  hasImg = false;
  $("stage").style.display = "none";
  refresh();
}
async function doShot() {
  if (!session) return;
  if (Date.now() - lastAct >= IDLE_MS) { doLogout(true); return; }
  if (busy) return;
  busy = true; $("shot").disabled = true; setMsg(""); touch();
  try {
    const r = await api("api/screenshot", { method: "POST" });
    if (r.status === 401) { clearSession(); return; }
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      throw new Error(j.error || String(r.status));
    }
    const blob = await r.blob();
    if (blobUrl) URL.revokeObjectURL(blobUrl);
    blobUrl = URL.createObjectURL(blob);
    const name = "skrinshot_" + new Date().toISOString().replace(/[:.]/g, "-") + ".jpg";
    const img = $("img");
    img.onload = () => {
      natW = img.naturalWidth; natH = img.naturalHeight;
      hasImg = true;
      $("stage").style.display = "flex";
      resetView();
      refresh();
    };
    img.src = blobUrl;
    $("dl").href = blobUrl; $("dl").download = name;
    touch();
  } catch (e) { setMsg("·", true); }
  finally { busy = false; refresh(); }
}
$("go").onclick = doLogin;
$("logout").onclick = () => doLogout(false);
$("shot").onclick = doShot;
$("token").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); doLogin(); } });
["pointerdown", "keydown", "touchstart"].forEach((ev) => {
  document.addEventListener(ev, () => { if (session) touch(); }, { passive: true });
});
document.addEventListener("keydown", (e) => {
  const tag = (e.target && e.target.tagName) || "";
  const typing = tag === "INPUT" || tag === "TEXTAREA";
  if (e.key === "Escape") { e.preventDefault(); if (session) doLogout(false); return; }
  if (typing) return;
  if (e.key === " " || e.key === "Enter") { e.preventDefault(); if (session) doShot(); }
  if (e.key === "s" || e.key === "S") { e.preventDefault(); if (session) doShot(); }
  if (e.key === "l" || e.key === "L") { e.preventDefault(); if (session) doLogout(false); }
  if (e.key === "+" || e.key === "=") { e.preventDefault(); zoomBy(1.25); }
  if (e.key === "-" || e.key === "_") { e.preventDefault(); zoomBy(1 / 1.25); }
  if (e.key === "0") { e.preventDefault(); resetView(); }
});
if (session) { armIdle(); startPing(); }
refresh();
window.addEventListener("pagehide", () => {
  if (!session) return;
  try { navigator.sendBeacon(base + "api/logout?session=" + encodeURIComponent(session)); } catch (e) {}
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
