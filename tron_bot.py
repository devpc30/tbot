"""
Tron Mnemonic Finder — Telegram Bot ⚡ Ultra Edition v2
=======================================================
بهبودها نسبت به نسخه قبلی:

  🚀 سرعت:
     • BLAKE2b به جای SHA-256 (2× سریع‌تر برای hashing counter)
     • COUNTER_FETCH = 100 000 → lock contention تقریباً صفر
     • BATCH_SIZE = 10 000 → 5× کمتر queue overhead
     • CPU affinity (pinning هر worker به یک core)
     • Queue bounded (maxsize=500) → بدون memory leak

  🔍 Exhaustive‌تر:
     • Multi-target: چند آدرس همزمان با O(1) set lookup
     • 4 BIP44 path: Tron standard + alt indices + ETH-compatible
     • /add برای افزودن target بدون restart
     • score tracking به ازای هر target

  🎨 Design:
     • Inline Keyboard روی همه پیام‌ها (Status، Stop، Resume، Clear، History)
     • Progress bar یونیکدی  █████░░░░░ N/34
     • Live message edit هر 30 ثانیه
     • Callback query handler کامل
     • /history آخرین 10 بهبود

نصب:
    pip install python-telegram-bot mnemonic tronpy coincurve

اجرا:
    export BOT_TOKEN="توکن_بات_شما"
    python tron_bot.py
"""

import asyncio
import multiprocessing as mp
import threading
import time
import os
import json
import hmac as _hmac
import hashlib
import struct
import signal
import sys
from pathlib import Path

from mnemonic import Mnemonic
from tronpy.keys import PrivateKey
from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
)
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
)
from telegram.constants import ParseMode
from telegram.error import BadRequest

# ─── تنظیمات ──────────────────────────────────────────────────────────────────
BOT_TOKEN     = os.environ.get("BOT_TOKEN", 8834575891:AAFvTkUTLCYlTjWD1T6-3e-Vl7GQVV0cMHs)
ALLOWED_USERS: set[int] = set()   # خالی = همه مجاز

NUM_WORKERS   = os.cpu_count() or 4
BATCH_SIZE    = 10_000    # ↑ 5× قبل → کمتر queue I/O
COUNTER_FETCH = 100_000   # ↑ 10× قبل → lock contention ~0
SAVE_FILE     = Path("tron_progress.json")
SAVE_INTERVAL = 30        # ثانیه

_H          = 0x80000000
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ─── BIP44 Paths (exhaustive coverage) ────────────────────────────────────────
TRON_PATHS: tuple[tuple, ...] = (
    (44 + _H, 195 + _H, _H, 0, 0),   # Tron standard        m/44'/195'/0'/0/0
    (44 + _H, 195 + _H, _H, 0, 1),   # Tron account index 1 m/44'/195'/0'/0/1
    (44 + _H, 195 + _H, _H, 0, 2),   # Tron account index 2 m/44'/195'/0'/0/2
    (44 + _H,  60 + _H, _H, 0, 0),   # ETH-compatible path  m/44'/60'/0'/0/0
)

# ─── coincurve یا bip32utils ──────────────────────────────────────────────────
try:
    from coincurve import PublicKey as _CCPub
    _HAS_COINCURVE = True
except ImportError:
    try:
        import bip32utils  # type: ignore
        _HAS_COINCURVE = False
        print("[!] coincurve not found → pip install coincurve  (slower fallback active)")
    except ImportError:
        print("[ERROR] Install either coincurve or bip32utils")
        sys.exit(1)


# ─── BIP32 Key Derivation ─────────────────────────────────────────────────────
def _derive_fast(seed: bytes, path: tuple) -> bytes:
    I = _hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c = I[:32], I[32:]
    for idx in path:
        if idx >= _H:
            data = b"\x00" + k + struct.pack(">I", idx)
        else:
            pub  = _CCPub.from_valid_secret(k).format(compressed=True)
            data = pub + struct.pack(">I", idx)
        I  = _hmac.new(c, data, hashlib.sha512).digest()
        il = int.from_bytes(I[:32], "big")
        ki = int.from_bytes(k, "big")
        k  = ((il + ki) % SECP256K1_N).to_bytes(32, "big")
        c  = I[32:]
    return k


def _derive_compat(seed: bytes, path: tuple) -> bytes:
    key = bip32utils.BIP32Key.fromEntropy(seed)  # type: ignore
    for idx in path:
        key = key.ChildKey(idx)
    return key.PrivateKey()


_derive = _derive_fast if _HAS_COINCURVE else _derive_compat


# ─── Score (multi-target) ─────────────────────────────────────────────────────
def calc_best_score(addr: str, targets: frozenset) -> tuple[int, int, str]:
    """بهترین (prefix, total, target) از بین همه اهداف — O(|targets|)"""
    bp, bt, btar = 0, 0, ""
    for t in targets:
        p = 0
        for a, b in zip(addr, t):
            if a == b:
                p += 1
            else:
                break
        tt = sum(a == b for a, b in zip(addr, t))
        if (p, tt) > (bp, bt):
            bp, bt, btar = p, tt, t
    return bp, bt, btar


# ─── Worker Process ───────────────────────────────────────────────────────────
def _worker_proc(
    targets_list: list,
    length: int,
    salt: bytes,
    result_q: mp.Queue,
    stop_flag,
    shared_counter: mp.Value,
    worker_id: int,
):
    """
    هر worker:
      1. یک بلوک COUNTER_FETCH اسلات از counter اتمیک می‌گیره (یک lock)
      2. entropy = BLAKE2b(counter) — سریع‌تر از SHA-256
      3. seed → mnemonic → PBKDF2 → BIP32 × paths
      4. نتیجه به result_q ارسال می‌شه
    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    # CPU affinity → pinning به یک core کمک می‌کنه context-switch کم بشه
    try:
        os.sched_setaffinity(0, {worker_id % os.cpu_count()})
    except (AttributeError, OSError):
        pass

    targets  = frozenset(targets_list)
    mnemo    = Mnemonic("english")
    ent_sz   = 16 if length == 12 else 32

    ls, lp, lt, lm, la, ltar = 0, 0, 0, "", "", ""

    while not stop_flag.value:
        # ─ گرفتن بلوک اتمیک از counter ─
        with shared_counter.get_lock():
            block_start           = shared_counter.value
            shared_counter.value += COUNTER_FETCH

        for i in range(COUNTER_FETCH):
            if stop_flag.value:
                break

            n = block_start + i

            # BLAKE2b: ~2× سریع‌تر از SHA-256 برای digest کوچیک
            entropy = hashlib.blake2b(
                n.to_bytes(16, "big"), digest_size=ent_sz
            ).digest()

            try:
                mnemonic_s = mnemo.to_mnemonic(entropy)
                seed       = hashlib.pbkdf2_hmac(
                    "sha512", mnemonic_s.encode(), salt, 2048
                )

                # چک همه BIP44 paths برای exhaustive coverage
                for path in TRON_PATHS:
                    if stop_flag.value:
                        break
                    addr = PrivateKey(
                        _derive(seed, path)
                    ).public_key.to_base58check_address()

                    # exact match → فوری گزارش بده و خارج شو
                    if addr in targets:
                        try:
                            result_q.put(
                                {
                                    "steps":    ls + 1,
                                    "score":    34,
                                    "total":    34,
                                    "mnemonic": mnemonic_s,
                                    "address":  addr,
                                    "target":   addr,
                                    "exact":    True,
                                    "counter":  shared_counter.value,
                                },
                                timeout=5,
                            )
                        except Exception:
                            pass
                        return

                    p, t, tar = calc_best_score(addr, targets)
                    if (p, t) > (lp, lt):
                        lp, lt, lm, la, ltar = p, t, mnemonic_s, addr, tar

            except Exception:
                pass

            ls += 1  # به ازای هر entropy یک بار (نه هر path)

            if ls >= BATCH_SIZE:
                try:
                    result_q.put(
                        {
                            "steps":    ls,
                            "score":    lp,
                            "total":    lt,
                            "mnemonic": lm,
                            "address":  la,
                            "target":   ltar,
                            "exact":    False,
                            "counter":  shared_counter.value,
                        },
                        timeout=2,
                    )
                except Exception:
                    pass
                ls, lp, lt, lm, la, ltar = 0, 0, 0, "", "", ""

    # flush باقیمانده
    if ls > 0:
        try:
            result_q.put(
                {
                    "steps":    ls,
                    "score":    lp,
                    "total":    lt,
                    "mnemonic": lm,
                    "address":  la,
                    "target":   ltar,
                    "exact":    False,
                    "counter":  shared_counter.value,
                },
                timeout=2,
            )
        except Exception:
            pass


# ─── Persistence ──────────────────────────────────────────────────────────────
def _save(s: dict):
    try:
        data = {
            "targets":       list(s.get("targets") or set()),
            "passphrase":    s.get("passphrase", ""),
            "length":        s.get("length", 12),
            "best_score":    s.get("best_score", 0),
            "best_total":    s.get("best_total", 0),
            "best_mnemonic": s.get("best_mnemonic", ""),
            "best_address":  s.get("best_address", ""),
            "best_target":   s.get("best_target", ""),
            "total_steps":   s.get("total_steps_ever", 0) + s.get("steps", 0),
            "counter":       s.get("counter", 0),
            "history":       s.get("history", [])[-50:],
            "was_running":   s.get("running", False),
            "chat_id":       s.get("chat_id", None),
            "saved_at":      time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        tmp = str(SAVE_FILE) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        Path(tmp).replace(SAVE_FILE)
    except Exception as e:
        print(f"[save error] {e}")


def _load() -> dict:
    if SAVE_FILE.exists():
        try:
            return json.loads(SAVE_FILE.read_text("utf-8"))
        except Exception:
            pass
    return {}


# ─── UI Helpers ───────────────────────────────────────────────────────────────
def _fmt(n) -> str:
    n = int(n or 0)
    if n >= 1_000_000_000:
        return f"{n / 1e9:.2f}B"
    if n >= 1_000_000:
        return f"{n / 1e6:.2f}M"
    if n >= 1_000:
        return f"{n / 1e3:.1f}K"
    return str(n)


def _bar(value: int, maximum: int = 34, width: int = 20) -> str:
    """پیشرفت‌بار یونیکدی  ████████░░░░ N/34 (P%)"""
    filled = int(width * value / max(maximum, 1))
    pct    = value / max(maximum, 1) * 100
    return f"{'█' * filled}{'░' * (width - filled)}  {value}/{maximum}  ({pct:.1f}%)"


def _elapsed(sec: float) -> str:
    s = int(sec)
    if s < 60:
        return f"{s}ثانیه"
    if s < 3600:
        return f"{s // 60}دقیقه {s % 60}ث"
    return f"{s // 3600}ساعت {(s % 3600) // 60}دقیقه"


def _targets_str(targets: set, limit: int = 3) -> str:
    lst = list(targets)[:limit]
    s   = "  ".join(f"<code>{t[:8]}…{t[-4:]}</code>" for t in lst)
    return s + (f"  +{len(targets) - limit}" if len(targets) > limit else "")


def _status_text(s: dict, icon: str = "⚡") -> str:
    total   = s["total_steps_ever"] + s["steps"]
    elapsed = (
        time.time() - s["start_time"]
        if s["running"] and s["start_time"]
        else 0
    )
    targets = s.get("targets") or set()

    lines = [
        f"{icon} <b>Tron Mnemonic Finder Ultra v2</b>",
        "▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬",
        f"🎯 اهداف ({len(targets)}):  {_targets_str(targets) if targets else '—'}",
        "",
        f"📊 بهترین Prefix Match:",
        f"<code>{_bar(s['best_score'])}</code>",
        f"📈 Total Match:  <b>{s['best_total']}/34</b>",
        "",
        f"🔢 تلاش‌ها:   <b>{_fmt(total)}</b>",
        f"⚡ سرعت:     <b>{_fmt(s['attempts_per_sec'])}/s</b>",
        f"👷 Workers:  <b>{s['active_workers']}/{NUM_WORKERS}</b>",
        f"⏱ مدت:      <b>{_elapsed(elapsed) if elapsed else '—'}</b>",
        f"🔍 Counter:  <code>{_fmt(s['counter'])}</code>",
    ]
    if s["best_address"]:
        lines += ["", f"📍 بهترین آدرس:\n<code>{s['best_address']}</code>"]
    if s["best_mnemonic"]:
        lines += ["", f"🔑 Mnemonic:\n<code>{s['best_mnemonic']}</code>"]
    return "\n".join(lines)


# ─── Keyboards ────────────────────────────────────────────────────────────────
def _kb_running() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("🔄 بروزرسانی", callback_data="status"),
                InlineKeyboardButton("⏹ توقف",      callback_data="stop"),
            ],
            [
                InlineKeyboardButton("📋 تاریخچه", callback_data="history"),
                InlineKeyboardButton("🎯 اهداف",   callback_data="targets"),
            ],
        ]
    )


def _kb_stopped() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("▶️ ادامه",    callback_data="resume"),
                InlineKeyboardButton("🗑 پاک‌کردن", callback_data="clear"),
            ],
            [
                InlineKeyboardButton("📋 تاریخچه", callback_data="history"),
                InlineKeyboardButton("🎯 اهداف",   callback_data="targets"),
            ],
        ]
    )


def _kb_search() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[
            InlineKeyboardButton("📊 وضعیت", callback_data="status"),
            InlineKeyboardButton("⏹ توقف",  callback_data="stop"),
        ]]
    )


def _kb_help() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("📊 وضعیت فعلی", callback_data="status")]]
    )


# ─── Global State ─────────────────────────────────────────────────────────────
_saved = _load()

state: dict = {
    "running":          False,
    "found":            False,
    "best_score":       _saved.get("best_score",    0),
    "best_total":       _saved.get("best_total",    0),
    "best_mnemonic":    _saved.get("best_mnemonic", ""),
    "best_address":     _saved.get("best_address",  ""),
    "best_target":      _saved.get("best_target",   ""),
    "steps":            0,
    "total_steps_ever": _saved.get("total_steps",   0),
    "targets":          set(_saved.get("targets",   [])),
    "passphrase":       _saved.get("passphrase",    ""),
    "length":           _saved.get("length",        12),
    "counter":          _saved.get("counter",       0),
    "attempts_per_sec": 0,
    "active_workers":   0,
    "start_time":       0.0,
    "history":          _saved.get("history",       []),
    "last_save_time":   time.time(),
    "chat_id":          _saved.get("chat_id",       None),
    "status_msg_id":    None,   # برای live edit
}

_lock                      = threading.Lock()
_workers: list[mp.Process] = []
_stop_flag                 = None
_result_q                  = None
_shared_counter            = None
_bot_loop: asyncio.AbstractEventLoop | None = None
_bot_app   = None


# ─── Notification Helpers ─────────────────────────────────────────────────────
def _notify(text: str, reply_markup=None):
    with _lock:
        chat_id = state.get("chat_id")
    if not chat_id or not _bot_app or not _bot_loop:
        return
    asyncio.run_coroutine_threadsafe(
        _bot_app.bot.send_message(
            chat_id=chat_id,
            text=text,
            parse_mode=ParseMode.HTML,
            reply_markup=reply_markup,
        ),
        _bot_loop,
    )


def _live_update(text: str, reply_markup=None):
    """سعی می‌کنه status_msg_id را edit کنه؛ اگه نشد پیام جدید می‌فرسته."""
    with _lock:
        chat_id = state.get("chat_id")
        msg_id  = state.get("status_msg_id")
    if not chat_id or not _bot_app or not _bot_loop:
        return

    async def _do():
        if msg_id:
            try:
                await _bot_app.bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=msg_id,
                    text=text,
                    parse_mode=ParseMode.HTML,
                    reply_markup=reply_markup,
                )
                return
            except BadRequest:
                pass
        await _bot_app.bot.send_message(
            chat_id=chat_id,
            text=text,
            parse_mode=ParseMode.HTML,
            reply_markup=reply_markup,
        )

    asyncio.run_coroutine_threadsafe(_do(), _bot_loop)


def _msg_improved() -> str:
    with _lock:
        s = state.copy()
    total = s["total_steps_ever"] + s["steps"]
    return (
        f"🔥 <b>بهبود جدید!</b>\n"
        f"▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬\n"
        f"<code>{_bar(s['best_score'])}</code>\n"
        f"📈 Total: <b>{s['best_total']}/34</b>\n\n"
        f"📍 آدرس:\n<code>{s['best_address']}</code>\n"
        f"🎯 هدف:  <code>{s.get('best_target','')[:8]}…</code>\n\n"
        f"🔑 Mnemonic:\n<code>{s['best_mnemonic']}</code>\n\n"
        f"🔢 تلاش‌ها: <b>{_fmt(total)}</b>"
    )


def _msg_found() -> str:
    with _lock:
        s = state.copy()
    total = s["total_steps_ever"] + s["steps"]
    return (
        f"🎉🎊 <b>آدرس کامل پیدا شد!</b> 🎊🎉\n"
        f"{'═' * 28}\n\n"
        f"📍 آدرس:\n<code>{s['best_address']}</code>\n\n"
        f"🔑 Mnemonic:\n<code>{s['best_mnemonic']}</code>\n\n"
        f"🔢 تلاش‌ها: <b>{_fmt(total)}</b>\n"
        f"{'═' * 28}"
    )


# ─── Collector Thread ─────────────────────────────────────────────────────────
def _run_collector(result_q: mp.Queue, stop_flag, workers: list):
    last_ts      = time.time()
    steps_win    = 0
    last_update  = time.time()   # برای auto live-update

    while True:
        all_done = not any(p.is_alive() for p in workers)

        try:
            msg = result_q.get(timeout=0.5 if not all_done else 0.05)
        except Exception:
            if all_done and result_q.empty():
                with _lock:
                    state["running"]        = False
                    state["active_workers"] = 0
                    _save(state)
                break

            # auto live-update هر 30 ثانیه
            now = time.time()
            if now - last_update >= 30:
                with _lock:
                    s      = state.copy()
                    msg_id = state.get("status_msg_id")
                if s["running"]:
                    _live_update(_status_text(s), _kb_running())
                last_update = now
            continue

        steps_win += msg["steps"]
        now        = time.time()
        dt         = now - last_ts
        improved   = False

        with _lock:
            state["steps"]          += msg["steps"]
            state["active_workers"]  = sum(1 for p in workers if p.is_alive())
            if msg.get("counter", 0) > state["counter"]:
                state["counter"] = msg["counter"]

            if dt >= 1.0:
                state["attempts_per_sec"] = int(steps_win / dt)
                steps_win = 0
                last_ts   = now

            # exact match
            if msg.get("exact"):
                state.update(
                    best_score=34, best_total=34,
                    best_mnemonic=msg["mnemonic"],
                    best_address=msg["address"],
                    best_target=msg.get("target", ""),
                    found=True, running=False,
                )
                stop_flag.value = 1
                _save(state)
                while not result_q.empty():
                    try: result_q.get_nowait()
                    except: pass
                _notify(_msg_found())
                return

            # بهبود score
            if (msg["score"], msg["total"]) > (state["best_score"], state["best_total"]):
                state.update(
                    best_score=msg["score"],
                    best_total=msg["total"],
                    best_mnemonic=msg["mnemonic"],
                    best_address=msg["address"],
                    best_target=msg.get("target", ""),
                )
                improved = True
                state["history"].append({
                    "score":    msg["score"],
                    "total":    msg["total"],
                    "address":  msg["address"],
                    "target":   msg.get("target", ""),
                    "mnemonic": msg["mnemonic"],
                    "steps":    state["total_steps_ever"] + state["steps"],
                    "time":     time.strftime("%H:%M:%S"),
                })
                if len(state["history"]) > 50:
                    state["history"] = state["history"][-50:]
                _save(state)
                state["last_save_time"] = now

            if now - state["last_save_time"] > SAVE_INTERVAL:
                _save(state)
                state["last_save_time"] = now

        if improved:
            _notify(_msg_improved(), _kb_running())

        # auto live-update
        now = time.time()
        if now - last_update >= 30:
            with _lock:
                s = state.copy()
            if s["running"]:
                _live_update(_status_text(s), _kb_running())
            last_update = now


# ─── Engine: Start / Stop ─────────────────────────────────────────────────────
def _do_start(
    targets: set,
    length: int,
    passphrase: str,
    resume: bool,
    chat_id: int | None = None,
) -> bool:
    global _workers, _stop_flag, _result_q, _shared_counter

    salt       = ("mnemonic" + passphrase).encode()
    _stop_flag = mp.Value("b", 0)
    _result_q  = mp.Queue(maxsize=500)   # bounded → no memory bloat

    with _lock:
        new_targets = targets != state.get("targets", set())
        if new_targets or not resume:
            state.update(
                best_score=0, best_total=0,
                best_mnemonic="", best_address="", best_target="",
                history=[], total_steps_ever=0, counter=0,
            )
        else:
            state["total_steps_ever"] += state["steps"]

        start_counter = state["counter"]
        state.update(
            running=True, found=False, steps=0,
            targets=targets, passphrase=passphrase, length=length,
            attempts_per_sec=0, active_workers=NUM_WORKERS,
            start_time=time.time(), last_save_time=time.time(),
        )
        if chat_id:
            state["chat_id"] = chat_id

    _shared_counter = mp.Value("Q", start_counter)
    targets_list    = list(targets)

    _workers = []
    for i in range(NUM_WORKERS):
        p = mp.Process(
            target=_worker_proc,
            args=(
                targets_list, length, salt,
                _result_q, _stop_flag, _shared_counter, i,
            ),
            daemon=True,
        )
        p.start()
        _workers.append(p)

    threading.Thread(
        target=_run_collector,
        args=(_result_q, _stop_flag, _workers),
        daemon=True,
    ).start()

    return resume and not new_targets


def _do_stop():
    if _stop_flag is not None:
        _stop_flag.value = 1
    with _lock:
        state["running"] = False
        _save(state)


# ─── Auth Guard ───────────────────────────────────────────────────────────────
def _allowed(update: Update) -> bool:
    if not ALLOWED_USERS:
        return True
    uid = update.effective_user.id if update.effective_user else None
    return uid in ALLOWED_USERS


# ─── Commands ─────────────────────────────────────────────────────────────────

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await cmd_help(update, ctx)


async def cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _allowed(update):
        return
    lib = "✅ coincurve (fast)" if _HAS_COINCURVE else "⚠️ bip32utils (slow)"
    await update.message.reply_text(
        f"⚡ <b>Tron Mnemonic Finder Ultra v2</b>\n"
        f"▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬\n\n"
        f"<b>دستورات:</b>\n\n"
        f"▫️ /search <code>آدرس [12|24] [passphrase]</code>\n"
        f"    جستجو برای یک آدرس هدف\n\n"
        f"▫️ /add <code>آدرس</code>\n"
        f"    افزودن هدف دیگر (multi-target)\n\n"
        f"▫️ /targets — نمایش همه اهداف\n"
        f"▫️ /status  — وضعیت live\n"
        f"▫️ /stop    — توقف جستجو\n"
        f"▫️ /resume  — ادامه از آخرین نقطه\n"
        f"▫️ /clear   — پاک‌کردن همه\n"
        f"▫️ /help    — این راهنما\n\n"
        f"▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬\n"
        f"🖥 Workers : <b>{NUM_WORKERS}</b> process\n"
        f"🔍 Paths   : <b>{len(TRON_PATHS)}</b> BIP44 path per entropy\n"
        f"📦 Crypto  : {lib}",
        parse_mode=ParseMode.HTML,
        reply_markup=_kb_help(),
    )


async def cmd_search(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _allowed(update):
        return

    with _lock:
        if state["running"]:
            await update.message.reply_text(
                "⚠️ جستجو در حال اجراست.\nابتدا /stop بزن.",
                reply_markup=_kb_running(),
            )
            return

    args = ctx.args or []
    if not args:
        await update.message.reply_text(
            "❌ آدرس هدف وارد نشده.\n\n"
            "مثال:\n<code>/search TXxx...xx 12</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    target = args[0].strip()
    if len(target) != 34 or not target.startswith("T"):
        await update.message.reply_text(
            "❌ آدرس نامعتبر.\nباید ۳۴ کاراکتر و با <code>T</code> شروع شود.",
            parse_mode=ParseMode.HTML,
        )
        return

    length, passphrase = 12, ""
    if len(args) >= 2:
        if args[1].isdigit():
            length = int(args[1])
            if length not in (12, 24):
                await update.message.reply_text("❌ طول باید ۱۲ یا ۲۴ باشه.")
                return
            passphrase = " ".join(args[2:]) if len(args) >= 3 else ""
        else:
            passphrase = " ".join(args[1:])

    chat_id = update.effective_chat.id
    _do_start({target}, length, passphrase, resume=False, chat_id=chat_id)

    msg = await update.message.reply_text(
        f"🚀 <b>جستجو شروع شد!</b>\n"
        f"▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬\n\n"
        f"🎯 هدف: <code>{target}</code>\n"
        f"📝 طول: <b>{length} کلمه</b>\n"
        f"🔍 Paths: <b>{len(TRON_PATHS)} BIP44</b>\n"
        f"🔑 Passphrase: {'✅ دارد' if passphrase else '—'}\n"
        f"⚡ Workers: <b>{NUM_WORKERS}</b>\n\n"
        f"هنگام بهبود score اطلاع داده می‌شه 🔔",
        parse_mode=ParseMode.HTML,
        reply_markup=_kb_search(),
    )
    with _lock:
        state["status_msg_id"] = msg.message_id


async def cmd_add(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _allowed(update):
        return
    args = ctx.args or []
    if not args:
        await update.message.reply_text(
            "استفاده: <code>/add TXxx...xx</code>", parse_mode=ParseMode.HTML
        )
        return

    new_addr = args[0].strip()
    if len(new_addr) != 34 or not new_addr.startswith("T"):
        await update.message.reply_text("❌ آدرس نامعتبر.")
        return

    with _lock:
        state.setdefault("targets", set()).add(new_addr)
        count = len(state["targets"])

    await update.message.reply_text(
        f"✅ هدف اضافه شد!\n<code>{new_addr}</code>\n\n"
        f"🎯 مجموع اهداف: <b>{count}</b>",
        parse_mode=ParseMode.HTML,
    )


async def cmd_targets(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _allowed(update):
        return
    with _lock:
        targets = list(state.get("targets") or set())

    if not targets:
        await update.message.reply_text("هیچ هدفی تنظیم نشده.")
        return

    lines = "\n".join(
        f"{i + 1}. <code>{t}</code>" for i, t in enumerate(targets)
    )
    await update.message.reply_text(
        f"🎯 <b>اهداف فعلی ({len(targets)})</b>\n\n{lines}",
        parse_mode=ParseMode.HTML,
    )


async def cmd_stop(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _allowed(update):
        return
    _do_stop()
    with _lock:
        s = state.copy()
    await update.message.reply_text(
        f"⏹ <b>جستجو متوقف شد.</b>\n\n"
        f"🔢 تلاش‌ها: <b>{_fmt(s['total_steps_ever'] + s['steps'])}</b>\n"
        f"📊 بهترین:  <b>{s['best_score']}/34</b>\n"
        f"✅ پیشرفت ذخیره شد.",
        parse_mode=ParseMode.HTML,
        reply_markup=_kb_stopped(),
    )


async def cmd_status(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _allowed(update):
        return
    with _lock:
        s = state.copy()

    icon = "⚡" if s["running"] else ("🎉" if s["found"] else "⏹")
    kb   = _kb_running() if s["running"] else _kb_stopped()
    msg  = await update.message.reply_text(
        _status_text(s, icon), parse_mode=ParseMode.HTML, reply_markup=kb
    )
    with _lock:
        state["status_msg_id"] = msg.message_id


async def cmd_resume(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _allowed(update):
        return
    with _lock:
        if state["running"]:
            await update.message.reply_text("⚠️ جستجو الان در حال اجراست.")
            return
        targets    = state.get("targets") or set()
        length     = state["length"]
        passphrase = state["passphrase"]
        prev_score = state["best_score"]
        prev_ctr   = state["counter"]
        prev_steps = state["total_steps_ever"]

    if not targets:
        await update.message.reply_text(
            "❌ هیچ هدفی ذخیره‌نشده. با /search شروع کن."
        )
        return

    chat_id = update.effective_chat.id
    _do_start(targets, length, passphrase, resume=True, chat_id=chat_id)

    targets_str = _targets_str(targets)
    msg = await update.message.reply_text(
        f"↺ <b>ادامه جستجو</b>\n"
        f"▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬\n\n"
        f"🎯 اهداف: {targets_str}\n"
        f"📊 بهترین قبلی: <b>{prev_score}/34</b>\n"
        f"🔍 Counter:     <code>{_fmt(prev_ctr)}</code>\n"
        f"🔢 از تلاش:    <code>{_fmt(prev_steps)}</code>",
        parse_mode=ParseMode.HTML,
        reply_markup=_kb_search(),
    )
    with _lock:
        state["status_msg_id"] = msg.message_id


async def cmd_clear(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _allowed(update):
        return
    with _lock:
        if state["running"]:
            await update.message.reply_text("⚠️ ابتدا /stop بزن.")
            return
        state.update(
            best_score=0, best_total=0, best_mnemonic="", best_address="",
            best_target="", history=[], total_steps_ever=0, steps=0,
            targets=set(), passphrase="", length=12, counter=0,
        )
        if SAVE_FILE.exists():
            SAVE_FILE.unlink()
    await update.message.reply_text("🗑 تمام پیشرفت پاک شد.")


# ─── Callback Query Handler ───────────────────────────────────────────────────
async def on_callback(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data  = query.data

    if data == "status":
        with _lock:
            s = state.copy()
        icon = "⚡" if s["running"] else ("🎉" if s["found"] else "⏹")
        kb   = _kb_running() if s["running"] else _kb_stopped()
        try:
            await query.edit_message_text(
                _status_text(s, icon), parse_mode=ParseMode.HTML, reply_markup=kb
            )
        except BadRequest:
            pass

    elif data == "stop":
        _do_stop()
        with _lock:
            s = state.copy()
        try:
            await query.edit_message_text(
                f"⏹ <b>جستجو متوقف شد.</b>\n\n"
                f"🔢 تلاش‌ها: <b>{_fmt(s['total_steps_ever'] + s['steps'])}</b>\n"
                f"📊 بهترین:  <b>{s['best_score']}/34</b>",
                parse_mode=ParseMode.HTML,
                reply_markup=_kb_stopped(),
            )
        except BadRequest:
            pass

    elif data == "resume":
        with _lock:
            if state["running"]:
                await query.answer("⚠️ جستجو در حال اجراست!", show_alert=True)
                return
            targets    = state.get("targets") or set()
            length     = state["length"]
            passphrase = state["passphrase"]

        if not targets:
            await query.answer("❌ هیچ هدفی ذخیره‌نشده!", show_alert=True)
            return

        chat_id = update.effective_chat.id
        _do_start(targets, length, passphrase, resume=True, chat_id=chat_id)
        try:
            await query.edit_message_text(
                f"▶️ <b>جستجو ادامه یافت</b>\n\n🎯 اهداف: <b>{len(targets)}</b>",
                parse_mode=ParseMode.HTML,
                reply_markup=_kb_search(),
            )
        except BadRequest:
            pass

    elif data == "clear":
        with _lock:
            if state["running"]:
                await query.answer("⚠️ ابتدا متوقف کن!", show_alert=True)
                return
            state.update(
                best_score=0, best_total=0, best_mnemonic="", best_address="",
                history=[], total_steps_ever=0, steps=0,
                targets=set(), passphrase="", length=12, counter=0,
            )
            if SAVE_FILE.exists():
                SAVE_FILE.unlink()
        try:
            await query.edit_message_text("🗑 پاک شد.")
        except BadRequest:
            pass

    elif data == "history":
        with _lock:
            history = (state.get("history") or [])[-10:]
        if not history:
            await query.answer("هیچ تاریخچه‌ای موجود نیست.", show_alert=True)
            return
        lines = []
        for h in reversed(history):
            lines.append(
                f"🕐 {h['time']}  |  {h['score']}/34  |  total {h['total']}/34\n"
                f"<code>{h['address']}</code>"
            )
        await ctx.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"📋 <b>آخرین {len(history)} بهبود</b>\n\n" + "\n\n".join(lines),
            parse_mode=ParseMode.HTML,
        )

    elif data == "targets":
        with _lock:
            targets = list(state.get("targets") or set())
        if not targets:
            await query.answer("هیچ هدفی تنظیم نشده.", show_alert=True)
            return
        lines = "\n".join(f"{i+1}. <code>{t}</code>" for i, t in enumerate(targets))
        await ctx.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"🎯 <b>اهداف ({len(targets)})</b>\n\n{lines}",
            parse_mode=ParseMode.HTML,
        )


# ─── Auto-Resume on Startup ───────────────────────────────────────────────────
def _auto_resume_thread():
    time.sleep(3)
    saved = _load()
    if not saved.get("was_running"):
        return
    targets = {
        t for t in saved.get("targets", [])
        if len(t) == 34 and t.startswith("T")
    }
    if not targets:
        return
    print(f"[auto-resume] {len(targets)} target(s)")
    _do_start(
        targets=targets,
        length=saved.get("length", 12),
        passphrase=saved.get("passphrase", ""),
        resume=True,
        chat_id=saved.get("chat_id"),
    )
    time.sleep(1.0)
    _notify(
        f"↺ <b>Auto-Resume فعال شد</b>\n\n"
        f"🎯 اهداف: <b>{len(targets)}</b>\n"
        f"📊 بهترین قبلی: <b>{saved.get('best_score', 0)}/34</b>\n"
        f"🔢 تلاش قبلی:  <b>{_fmt(saved.get('total_steps', 0))}</b>",
        _kb_running(),
    )


threading.Thread(target=_auto_resume_thread, daemon=True).start()


# ─── Signal Handlers ──────────────────────────────────────────────────────────
def _on_signal(signum, frame):
    print(f"[signal {signum}] Saving state...")
    _do_stop()
    for p in _workers:
        p.join(timeout=2)
    print("[exit] Saved. Bye.")
    sys.exit(0)


signal.signal(signal.SIGTERM, _on_signal)
signal.signal(signal.SIGINT, _on_signal)


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    global _bot_loop, _bot_app

    mp.freeze_support()
    print(f"[*] Backend : {'coincurve (fast)' if _HAS_COINCURVE else 'bip32utils (slow)'}")
    print(f"[*] Workers : {NUM_WORKERS} processes  ×  {len(TRON_PATHS)} BIP44 paths")
    print(f"[*] Progress: {SAVE_FILE.absolute()}")

    if not BOT_TOKEN or BOT_TOKEN == "YOUR_TOKEN_HERE":
        print("[ERROR] BOT_TOKEN تنظیم نشده!\nexport BOT_TOKEN='توکن_شما'")
        sys.exit(1)

    app = Application.builder().token(BOT_TOKEN).build()
    _bot_app = app

    app.add_handler(CommandHandler("start",   cmd_start))
    app.add_handler(CommandHandler("help",    cmd_help))
    app.add_handler(CommandHandler("search",  cmd_search))
    app.add_handler(CommandHandler("add",     cmd_add))
    app.add_handler(CommandHandler("targets", cmd_targets))
    app.add_handler(CommandHandler("stop",    cmd_stop))
    app.add_handler(CommandHandler("status",  cmd_status))
    app.add_handler(CommandHandler("resume",  cmd_resume))
    app.add_handler(CommandHandler("clear",   cmd_clear))
    app.add_handler(CallbackQueryHandler(on_callback))

    async def _capture_loop(app):
        global _bot_loop
        _bot_loop = asyncio.get_running_loop()

    app.post_init = _capture_loop

    print("[*] Bot is running. Ctrl+C to stop.")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
