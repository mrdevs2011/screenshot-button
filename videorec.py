#!/usr/bin/env python3
"""Video rejim: ekranni 5 soniyalik MP4 segmentlarga yozadi.

wf-recorder (Wayland) -> ffmpeg (H.264, segment muxer). Segmentlar RAM'da (/dev/shm)
turadi, diskka yozilmaydi; faqat oxirgi KEEP tasi saqlanadi (halqa-bufer).
"""
import os
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path

SEG_SECONDS = max(2, int(os.environ.get("VIDEO_SEG", "5")))
FPS = max(1, int(os.environ.get("VIDEO_FPS", "15")))
WIDTH = max(320, int(os.environ.get("VIDEO_WIDTH", "1280")))
CRF = os.environ.get("VIDEO_CRF", "30")
MAXRATE = os.environ.get("VIDEO_MAXRATE", "3000k")  # segment hajmini cheklaydi (~2 MB / 5s)
KEEP = max(4, int(os.environ.get("VIDEO_KEEP", "24")))  # nechta oxirgi segment saqlansin
OUTPUT = os.environ.get("VIDEO_OUTPUT", "").strip()  # ko'p monitor bo'lsa: monitor nomi


class Recorder:
    def __init__(self, env_fn):
        self._env_fn = env_fn
        self.dir = Path(os.environ.get("VIDEO_DIR") or f"/dev/shm/screenshot-button-{os.getuid()}")
        self._lock = threading.RLock()
        self._wf = None
        self._ff = None
        self._logs = []
        self._next_seq = 0
        self._retry_at = 0.0
        self.error = None

    @property
    def running(self) -> bool:
        wf, ff = self._wf, self._ff
        return bool(wf and ff and wf.poll() is None and ff.poll() is None)

    # ---- segmentlar ro'yxati (faqat tugallanganlari) ----
    def segments(self) -> list:
        try:
            lines = (self.dir / "list.csv").read_text().splitlines()
        except OSError:
            return []
        out = []
        for line in lines:
            parts = line.strip().split(",")
            if len(parts) < 3:
                continue
            name = Path(parts[0]).name
            if not (name.startswith("seg_") and name.endswith(".mp4")):
                continue
            try:
                seq = int(name[4:-4])
                dur = float(parts[2]) - float(parts[1])
            except ValueError:
                continue
            if (self.dir / name).exists():
                out.append({"seq": seq, "dur": round(dur, 2)})
        return out[-KEEP:]

    def read(self, seq: int):
        if not any(s["seq"] == seq for s in self.segments()):
            return None
        try:
            return (self.dir / f"seg_{seq:06d}.mp4").read_bytes()
        except OSError:
            return None

    def prune(self) -> None:
        """Eski segmentlarni o'chiradi (halqa-bufer)."""
        segs = self.segments()
        if not segs:
            return
        lo = segs[0]["seq"]
        for p in self.dir.glob("seg_*.mp4"):
            try:
                n = int(p.stem[4:])
            except ValueError:
                continue
            if n < lo:
                try:
                    p.unlink()
                except OSError:
                    pass

    # ---- boshqarish ----
    def start(self) -> bool:
        with self._lock:
            if self.running:
                return True
            if time.time() < self._retry_at:
                return False
            self._stop_locked()
            if not shutil.which("wf-recorder") or not shutil.which("ffmpeg"):
                return self._fail("wf-recorder yoki ffmpeg o'rnatilmagan")
            env = self._env_fn()
            if not env.get("WAYLAND_DISPLAY"):
                return self._fail("Wayland sessiyasi topilmadi")

            wf_cmd = ["wf-recorder", "-y", "-D", "-r", str(FPS), "-c", "rawvideo", "-x", "yuv420p", "-m", "nut"]
            if OUTPUT:
                wf_cmd += ["-o", OUTPUT]
            wf_cmd += ["-f", "/dev/stdout"]
            ff_cmd = [
                "ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin",
                "-f", "nut", "-i", "pipe:0",
                "-vf", f"scale=w=min({WIDTH}\\,iw):h=-2",
                "-an",
                "-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency",
                "-crf", CRF, "-maxrate", MAXRATE, "-bufsize", MAXRATE,
                "-pix_fmt", "yuv420p",
                "-force_key_frames", f"expr:gte(t,n_forced*{SEG_SECONDS})",
                "-f", "segment", "-segment_time", str(SEG_SECONDS),
                "-segment_format", "mp4",
                "-segment_format_options", "movflags=+frag_keyframe+empty_moov+default_base_moof",
                "-segment_start_number", str(self._next_seq),
                "-segment_list", str(self.dir / "list.csv"),
                "-segment_list_type", "csv",
                "-reset_timestamps", "1",
                str(self.dir / "seg_%06d.mp4"),
            ]
            try:
                self.dir.mkdir(parents=True, mode=0o700, exist_ok=True)
                wf_log = open(self.dir / "wf.log", "wb")
                ff_log = open(self.dir / "ff.log", "wb")
                self._logs = [wf_log, ff_log]
                self._wf = subprocess.Popen(
                    wf_cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=wf_log,
                    env=env, start_new_session=True,
                )
                self._ff = subprocess.Popen(
                    ff_cmd, stdin=self._wf.stdout, stdout=subprocess.DEVNULL, stderr=ff_log,
                    env=env, start_new_session=True,
                )
                self._wf.stdout.close()
            except OSError as e:
                self._stop_locked()
                return self._fail(f"ishga tushmadi: {e}")
            time.sleep(0.5)  # darhol yiqilishni aniqlash
            if not self.running:
                msg = self._tail_log() or "yozuv jarayoni darhol to'xtadi"
                self._stop_locked()
                return self._fail(msg)
            self.error = None
            return True

    def stop(self) -> None:
        with self._lock:
            self._stop_locked()

    def _fail(self, msg: str) -> bool:
        self.error = msg
        self._retry_at = time.time() + 5
        return False

    def _tail_log(self) -> str:
        out = []
        for name in ("wf.log", "ff.log"):
            try:
                txt = (self.dir / name).read_text(errors="replace").strip()
            except OSError:
                continue
            if txt:
                out.append(f"{name}: {txt[-160:]}")
        return " | ".join(out)

    def _stop_locked(self) -> None:
        segs = self.segments()
        if segs:  # raqamlash davom etadi — brauzer eski/yangi segmentni adashtirmaydi
            self._next_seq = max(self._next_seq, segs[-1]["seq"] + 2)
        wf, ff = self._wf, self._ff
        self._wf = self._ff = None
        for p, sig in ((wf, signal.SIGINT), (ff, signal.SIGTERM)):
            if p is not None and p.poll() is None:
                try:
                    p.send_signal(sig)
                except OSError:
                    pass
        for p in (wf, ff):
            if p is None:
                continue
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    p.kill()
                    p.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        for f in self._logs:
            try:
                f.close()
            except OSError:
                pass
        self._logs = []
        shutil.rmtree(self.dir, ignore_errors=True)



# ---------------- "Bosib turib yozib olish": bitta uzluksiz video ----------------
CLIP_FPS = max(1, int(os.environ.get("CLIP_FPS", "12")))
CLIP_WIDTH = max(320, int(os.environ.get("CLIP_WIDTH", "1280")))
CLIP_CRF = os.environ.get("CLIP_CRF", "30")
CLIP_MAXRATE = os.environ.get("CLIP_MAXRATE", "800k")
CLIP_MAX_SECONDS = max(10, int(os.environ.get("CLIP_MAX_SECONDS", "600")))
CLIP_CHUNK = 1_000_000  # brauzerga shuncha baytlik bo'laklab beriladi (Vercel javob limiti uchun)


class ClipRecorder:
    """start() -> yozadi (RAM, /dev/shm); stop() -> tugatadi va bo'laklab o'qishga tayyorlaydi."""

    def __init__(self, env_fn):
        self._env_fn = env_fn
        self.dir = Path(os.environ.get("CLIP_DIR") or f"/dev/shm/screenshot-button-clip-{os.getuid()}")
        self.file = self.dir / "clip.mp4"
        self._lock = threading.RLock()
        self._wf = None
        self._ff = None
        self._logs = []
        self._t0 = 0.0
        self._info = None
        self.error = None

    @property
    def running(self) -> bool:
        wf, ff = self._wf, self._ff
        return bool(wf and ff and wf.poll() is None and ff.poll() is None)

    @property
    def elapsed(self) -> float:
        return (time.time() - self._t0) if self.running else 0.0

    def _tail_log(self) -> str:
        out = []
        for name in ("wf.log", "ff.log"):
            try:
                txt = (self.dir / name).read_text(errors="replace").strip()
            except OSError:
                continue
            if txt:
                out.append(f"{name}: {txt[-160:]}")
        return " | ".join(out)

    def _kill_locked(self) -> None:
        wf, ff = self._wf, self._ff
        self._wf = self._ff = None
        for p, sig in ((wf, signal.SIGINT), (ff, signal.SIGTERM)):
            if p is not None and p.poll() is None:
                try:
                    p.send_signal(sig)
                except OSError:
                    pass
        for p in (wf, ff):
            if p is None:
                continue
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    p.kill()
                    p.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        for f in self._logs:
            try:
                f.close()
            except OSError:
                pass
        self._logs = []

    def start(self) -> bool:
        with self._lock:
            if self.running:
                return True
            self._kill_locked()
            shutil.rmtree(self.dir, ignore_errors=True)
            self._info = None
            if not shutil.which("wf-recorder") or not shutil.which("ffmpeg"):
                self.error = "wf-recorder yoki ffmpeg o'rnatilmagan"
                return False
            env = self._env_fn()
            if not env.get("WAYLAND_DISPLAY"):
                self.error = "Wayland sessiyasi topilmadi"
                return False
            wf_cmd = ["wf-recorder", "-y", "-D", "-r", str(CLIP_FPS), "-c", "rawvideo", "-x", "yuv420p", "-m", "nut"]
            if OUTPUT:
                wf_cmd += ["-o", OUTPUT]
            wf_cmd += ["-f", "/dev/stdout"]
            ff_cmd = [
                "ffmpeg", "-hide_banner", "-loglevel", "error", "-nostdin", "-y",
                "-f", "nut", "-i", "pipe:0",
                "-vf", f"scale=w=min({CLIP_WIDTH}\\,iw):h=-2",
                "-an",
                "-c:v", "libx264", "-preset", "veryfast",
                "-crf", CLIP_CRF, "-maxrate", CLIP_MAXRATE, "-bufsize", "2M",
                "-pix_fmt", "yuv420p",
                "-movflags", "+faststart",
                str(self.file),
            ]
            try:
                self.dir.mkdir(parents=True, mode=0o700, exist_ok=True)
                wf_log = open(self.dir / "wf.log", "wb")
                ff_log = open(self.dir / "ff.log", "wb")
                self._logs = [wf_log, ff_log]
                self._wf = subprocess.Popen(
                    wf_cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=wf_log,
                    env=env, start_new_session=True,
                )
                self._ff = subprocess.Popen(
                    ff_cmd, stdin=self._wf.stdout, stdout=subprocess.DEVNULL, stderr=ff_log,
                    env=env, start_new_session=True,
                )
                self._wf.stdout.close()
            except OSError as e:
                self._kill_locked()
                self.error = f"ishga tushmadi: {e}"
                return False
            time.sleep(0.6)
            if not self.running:
                self.error = self._tail_log() or "yozuv jarayoni darhol to'xtadi"
                self._kill_locked()
                return False
            self._t0 = time.time()
            self.error = None
            return True

    def stop(self):
        """Yozuvni to'g'ri yopadi. {size, n, chunk, dur} yoki None qaytaradi."""
        with self._lock:
            wf, ff = self._wf, self._ff
            if wf is None and ff is None:
                return self._info
            dur = time.time() - self._t0
            if wf is not None and wf.poll() is None:
                try:
                    wf.send_signal(signal.SIGINT)
                except OSError:
                    pass
            if ff is not None:
                try:
                    ff.wait(timeout=25)  # EOF -> ffmpeg faylni yopadi (faststart)
                except subprocess.TimeoutExpired:
                    try:
                        ff.terminate()
                        ff.wait(timeout=3)
                    except (OSError, subprocess.TimeoutExpired):
                        try:
                            ff.kill()
                        except OSError:
                            pass
            if wf is not None:
                try:
                    wf.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    try:
                        wf.kill()
                    except OSError:
                        pass
            tail = self._tail_log()
            self._wf = self._ff = None
            for f in self._logs:
                try:
                    f.close()
                except OSError:
                    pass
            self._logs = []
            try:
                size = self.file.stat().st_size
            except OSError:
                size = 0
            if size < 1000:
                self.error = tail or "Video bo'sh chiqdi"
                self._info = None
                return None
            self._info = {"size": size, "n": (size + CLIP_CHUNK - 1) // CLIP_CHUNK, "chunk": CLIP_CHUNK, "dur": round(dur, 1)}
            return self._info

    def read_chunk(self, i: int):
        info = self._info
        if not info or i < 0 or i >= info["n"]:
            return None
        try:
            with open(self.file, "rb") as f:
                f.seek(i * CLIP_CHUNK)
                return f.read(CLIP_CHUNK)
        except OSError:
            return None

    def wipe(self) -> None:
        with self._lock:
            self._kill_locked()
            self._info = None
            shutil.rmtree(self.dir, ignore_errors=True)
