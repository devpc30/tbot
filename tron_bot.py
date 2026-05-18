"""
Tron Mnemonic Finder — Telegram Bot (Exhaustive Edition)
=========================================================
• هر worker یه بلوک از counter می‌گیره (COUNTER_FETCH واحد)
• entropy از counter با SHA-256 ساخته می‌شه → deterministic، بدون تکرار
• counter در JSON ذخیره می‌شه → resume دقیقاً از همون جا ادامه میده
• هیچ entropy‌ای دوبار چک نمیشه → بازده ۱۰۰٪
• workers به دو گروه تقسیم میشن: نصف ۱۲‌کلمه‌ای، نصف ۲۴‌کلمه‌ای

نصب:
    pip install python-telegram-bot mnemonic tronpy coincurve

اجرا:
    export BOT_TOKEN="توکن_بات_شما"
    python tron_bot.py

دستورات:
    /search <address> [passphrase]
    /stop   — توقف جستجو
    /status — وضعیت فعلی
    /resume — ادامه از آخرین نقطه
    /clear  — پاک کردن پیشرفت
    /help   — راهنما
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
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from telegram.constants import ParseMode

# ─── تنظیمات ─────────────────────────────────────────────────────
BOT_TOKEN     = os.environ.get("BOT_TOKEN", "8834575891:AAFvTkUTLCYlTjWD1T6-3e-Vl7GQVV0cMHs")
ALLOWED_USERS: set[int] = set()   # خالی = همه مجاز؛ یا: {123456789, 987654321}

NUM_WORKERS    = os.cpu_count() or 4
# تقسیم workers: نصف برای ۱۲ کلمه، نصف برای ۲۴ کلمه
NUM_WORKERS_12 = max(1, NUM_WORKERS // 2)
NUM_WORKERS_24 = max(1, NUM_WORKERS - NUM_WORKERS_12)

BATCH_SIZE     = 2000
COUNTER_FETCH  = 10_000
SAVE_FILE      = Path("tron_progress.json")
SAVE_INTERVAL  = 20   # ثانیه

_H          = 0x80000000
TRON_PATH   = (44 + _H, 195 + _H, _H, 0, 0)
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ─── coincurve (سریع) یا bip32utils (fallback) ──────────────────
try:
    from coincurve import PublicKey as _CCPub
    _HAS_COINCURVE = True
except ImportError:
    try:
        import bip32utils
        _HAS_COINCURVE = False
        print("[!] coincurve not found — pip install coincurve  (slower fallback active)")
    except ImportError:
        print("[ERROR] Install either coincurve or bip32utils")
        sys.exit(1)


# ─── BIP32 Derivation ────────────────────────────────────────────
def _derive_fast(seed: bytes) -> bytes:
    I = _hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c = I[:32], I[32:]
    for idx in TRON_PATH:
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


def _derive_compat(seed: bytes) -> bytes:
    key = bip32utils.BIP32Key.fromEntropy(seed)
    for idx in TRON_PATH:
        key = key.ChildKey(idx)
    return key.PrivateKey()


_derive = _derive_fast if _HAS_COINCURVE else _derive_compat


# ─── Score ───────────────────────────────────────────────────────
def calc_score(addr: str, target: str):
    p = 0
    for a, b in zip(addr, target):
        if a == b: p += 1
        else: break
    t = sum(a == b for a, b in zip(addr, target))
    return p, t


# ─── Worker Process ───────────────────────────────────────────────
def _worker_proc(target: str, length: int, salt: bytes,
                 result_q: mp.Queue, stop_flag,
                 shared_counter: mp.Value):
    """
    length=12 → entropy 16 بایت
    length=24 → entropy 32 بایت
    هر گروه counter مستقل دارد — بدون تداخل
    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    mnemo  = Mnemonic("english")
    ent_sz = 16 if length == 12 else 32
    ls, lp, lt, lm, la = 0, 0, 0, "", ""

    while not stop_flag.value:
        with shared_counter.get_lock():
            block_start          = shared_counter.value
            shared_counter.value += COUNTER_FETCH

        for i in range(COUNTER_FETCH):
            if stop_flag.value:
                break

            n       = block_start + i
            entropy = hashlib.sha256(n.to_bytes(16, "big")).digest()[:ent_sz]

            try:
                mnemonic_s = mnemo.to_mnemonic(entropy)
                seed       = hashlib.pbkdf2_hmac("sha512", mnemonic_s.encode(), salt, 2048)
                addr       = PrivateKey(_derive(seed)).public_key.to_base58check_address()
            except Exception:
                continue

            p, t = calc_score(addr, target)
            ls  += 1
            if (p, t) > (lp, lt):
                lp, lt, lm, la = p, t, mnemonic_s, addr

            if ls >= BATCH_SIZE:
                try:
                    result_q.put(
                        {"steps": ls, "score": lp, "total": lt,
                         "mnemonic": lm, "address": la,
                         "length": length,
                         "counter": shared_counter.value},
                        timeout=2
                    )
                except Exception:
                    pass
                ls = 0

    if ls > 0:
        try:
            result_q.put(
                {"steps": ls, "score": lp, "total": lt,
                 "mnemonic": lm, "address": la,
                 "length": length,
                 "counter": shared_counter.value},
                timeout=2
            )
        except Exception:
            pass


# ─── Persistence ─────────────────────────────────────────────────
def _save(s: dict):
    try:
        data = {
            "target_address": s.get("target_address", ""),
            "passphrase":     s.get("passphrase",     ""),
            "best_score":     s.get("best_score",     0),
            "best_total":     s.get("best_total",     0),
            "best_mnemonic":  s.get("best_mnemonic",  ""),
            "best_address":   s.get("best_address",   ""),
            "best_length":    s.get("best_length",    0),
            "total_steps":    s.get("total_steps_ever", 0) + s.get("steps", 0),
            "counter_12":     s.get("counter_12",     0),
            "counter_24":     s.get("counter_24",     0),
            "history":        s.get("history", [])[-50:],
            "was_running":    s.get("running", False),
            "chat_id":        s.get("chat_id", None),
            "saved_at":       time.strftime("%Y-%m-%d %H:%M:%S"),
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


# ─── Global State ────────────────────────────────────────────────
_saved = _load()

state = {
    "running":          False,
    "found":            False,
    "best_score":       _saved.get("best_score",     0),
    "best_total":       _saved.get("best_total",     0),
    "best_mnemonic":    _saved.get("best_mnemonic",  ""),
    "best_address":     _saved.get("best_address",   ""),
    "best_length":      _saved.get("best_length",    0),
    "steps":            0,
    "total_steps_ever": _saved.get("total_steps",    0),
    "target_address":   _saved.get("target_address", ""),
    "passphrase":       _saved.get("passphrase",     ""),
    "counter_12":       _saved.get("counter_12",     0),
    "counter_24":       _saved.get("counter_24",     0),
    "attempts_per_sec": 0,
    "active_workers":   0,
    "start_time":       0.0,
    "history":          _saved.get("history",        []),
    "last_save_time":   time.time(),
    "chat_id":          _saved.get("chat_id",        None),
}

_lock                       = threading.Lock()
_workers: list[mp.Process]  = []
_stop_flag                  = None
_result_q                   = None
_shared_counter_12          = None
_shared_counter_24          = None
_bot_loop: asyncio.AbstractEventLoop | None = None
_bot_app   = None

# ─── آی‌دی آخرین پیام بهبود (برای edit به جای send) ──────────────
_last_status_msg_id: int | None = None
_last_status_msg_lock = threading.Lock()


# ─── Notification helpers ────────────────────────────────────────
def _fmt(n) -> str:
    n = int(n or 0)
    if n >= 1_000_000: return f"{n/1e6:.2f}M"
    if n >= 1_000:     return f"{n/1e3:.1f}K"
    return str(n)


async def _send_or_edit_msg(chat_id: int, text: str):
    """
    اگه پیام قبلی وجود داره → ویرایش می‌کنه
    اگه پیام قبلی نداره یا حذف شده → پیام جدید می‌فرسته
    """
    global _last_status_msg_id

    with _last_status_msg_lock:
        msg_id = _last_status_msg_id

    if msg_id:
        try:
            await _bot_app.bot.edit_message_text(
                chat_id=chat_id,
                message_id=msg_id,
                text=text,
                parse_mode=ParseMode.HTML
            )
            return
        except Exception:
            pass

    try:
        msg = await _bot_app.bot.send_message(
            chat_id=chat_id,
            text=text,
            parse_mode=ParseMode.HTML
        )
        with _last_status_msg_lock:
            _last_status_msg_id = msg.message_id
    except Exception as e:
        print(f"[notify error] {e}")


def _notify(text: str):
    """بهبود score → edit پیام قبلی."""
    with _lock:
        chat_id = state.get("chat_id")
    if not chat_id or not _bot_app or not _bot_loop:
        return
    asyncio.run_coroutine_threadsafe(
        _send_or_edit_msg(chat_id, text),
        _bot_loop
    )


def _notify_new(text: str):
    """رویدادهای مهم → همیشه پیام جدید."""
    global _last_status_msg_id
    with _last_status_msg_lock:
        _last_status_msg_id = None
    _notify(text)


def _reset_status_msg():
    global _last_status_msg_id
    with _last_status_msg_lock:
        _last_status_msg_id = None


def _msg_improved() -> str:
    with _lock:
        s = state.copy()
    total = s["total_steps_ever"] + s["steps"]
    length_tag = f"🔑 {s['best_length']} کلمه‌ای" if s["best_length"] else ""
    return (
        f"🔥 <b>بهترین یافته</b>  {length_tag}\n\n"
        f"Prefix: <b>{s['best_score']}/34</b>  |  Total: <b>{s['best_total']}/34</b>\n"
        f"📍 آدرس: <code>{s['best_address']}</code>\n\n"
        f"📄 Mnemonic:\n<code>{s['best_mnemonic']}</code>\n\n"
        f"🔢 تلاش‌ها: <code>{_fmt(total)}</code>\n"
        f"🕐 آخرین بروزرسانی: {time.strftime('%H:%M:%S')}"
    )


def _msg_found() -> str:
    with _lock:
        s = state.copy()
    total = s["total_steps_ever"] + s["steps"]
    length_tag = f"({s['best_length']} کلمه‌ای)" if s["best_length"] else ""
    return (
        f"🎉 <b>آدرس کامل پیدا شد!</b> {length_tag}\n\n"
        f"📍 آدرس: <code>{s['best_address']}</code>\n\n"
        f"📄 Mnemonic:\n<code>{s['best_mnemonic']}</code>\n\n"
        f"🔢 تلاش‌ها: <code>{_fmt(total)}</code>"
    )


# ─── Collector Thread ────────────────────────────────────────────
def _run_collector(result_q: mp.Queue, stop_flag, target: str, workers: list):
    target_len = len(target)
    last_ts    = time.time()
    steps_win  = 0

    while True:
        all_done = not any(p.is_alive() for p in workers)

        try:
            msg = result_q.get(timeout=0.3 if not all_done else 0.05)
        except Exception:
            if all_done and result_q.empty():
                with _lock:
                    state["running"]        = False
                    state["active_workers"] = 0
                    _save(state)
                break
            continue

        steps_win += msg["steps"]
        now      = time.time()
        dt       = now - last_ts
        improved = False

        with _lock:
            state["steps"]          += msg["steps"]
            state["active_workers"]  = sum(1 for p in workers if p.is_alive())

            # آپدیت counter گروه مربوطه
            msg_length = msg.get("length", 12)
            if msg_length == 12:
                if msg.get("counter", 0) > state["counter_12"]:
                    state["counter_12"] = msg["counter"]
            else:
                if msg.get("counter", 0) > state["counter_24"]:
                    state["counter_24"] = msg["counter"]

            if dt >= 1.0:
                state["attempts_per_sec"] = int(steps_win / dt)
                steps_win = 0
                last_ts   = now

            if (msg["score"], msg["total"]) > (state["best_score"], state["best_total"]):
                state["best_score"]    = msg["score"]
                state["best_total"]    = msg["total"]
                state["best_mnemonic"] = msg["mnemonic"]
                state["best_address"]  = msg["address"]
                state["best_length"]   = msg_length
                improved = True
                state["history"].append({
                    "score":    msg["score"],
                    "total":    msg["total"],
                    "address":  msg["address"],
                    "mnemonic": msg["mnemonic"],
                    "length":   msg_length,
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

            if state["best_score"] >= target_len:
                state["found"]   = True
                stop_flag.value  = 1
                state["running"] = False
                _save(state)
                while not result_q.empty():
                    try: result_q.get_nowait()
                    except: pass
                _notify_new(_msg_found())
                break

        if improved:
            _notify(_msg_improved())


# ─── Start / Stop Engine ─────────────────────────────────────────
def _do_start(target: str, passphrase: str,
              resume: bool, chat_id: int | None = None) -> bool:
    global _workers, _stop_flag, _result_q
    global _shared_counter_12, _shared_counter_24

    salt       = ("mnemonic" + passphrase).encode()
    _stop_flag = mp.Value("b", 0)
    _result_q  = mp.Queue()

    with _lock:
        new_target = (target != state["target_address"])
        if new_target or not resume:
            state.update(
                best_score=0, best_total=0,
                best_mnemonic="", best_address="",
                best_length=0,
                history=[], total_steps_ever=0,
                counter_12=0, counter_24=0,
            )
        else:
            state["total_steps_ever"] += state["steps"]

        start_c12 = state["counter_12"]
        start_c24 = state["counter_24"]

        state.update(
            running=True, found=False, steps=0,
            target_address=target, passphrase=passphrase,
            attempts_per_sec=0,
            active_workers=NUM_WORKERS_12 + NUM_WORKERS_24,
            start_time=time.time(), last_save_time=time.time(),
        )
        if chat_id:
            state["chat_id"] = chat_id

    # دو counter مستقل
    _shared_counter_12 = mp.Value("Q", start_c12)
    _shared_counter_24 = mp.Value("Q", start_c24)

    _workers = []

    # گروه ۱۲ کلمه‌ای
    for _ in range(NUM_WORKERS_12):
        p = mp.Process(
            target=_worker_proc,
            args=(target, 12, salt, _result_q, _stop_flag, _shared_counter_12),
            daemon=True,
        )
        p.start()
        _workers.append(p)

    # گروه ۲۴ کلمه‌ای
    for _ in range(NUM_WORKERS_24):
        p = mp.Process(
            target=_worker_proc,
            args=(target, 24, salt, _result_q, _stop_flag, _shared_counter_24),
            daemon=True,
        )
        p.start()
        _workers.append(p)

    threading.Thread(
        target=_run_collector,
        args=(_result_q, _stop_flag, target, _workers),
        daemon=True,
    ).start()

    return resume and not new_target


def _do_stop():
    if _stop_flag is not None:
        _stop_flag.value = 1
    with _lock:
        state["running"] = False
        _save(state)


# ─── Auto-Resume on Startup ──────────────────────────────────────
def _auto_resume_thread():
    time.sleep(2.5)
    saved = _load()
    if saved.get("was_running") and saved.get("target_address"):
        target = saved["target_address"]
        if len(target) == 34 and target.startswith("T"):
            print(f"[auto-resume] Resuming for {target}")
            _reset_status_msg()
            _do_start(
                target=target,
                passphrase=saved.get("passphrase", ""),
                resume=True,
                chat_id=saved.get("chat_id"),
            )
            time.sleep(1.0)
            _notify_new(
                f"↺ <b>Auto-Resume فعال شد</b>\n\n"
                f"🎯 هدف: <code>{target}</code>\n"
                f"📊 بهترین قبلی: <code>{saved.get('best_score', 0)}/34</code>\n"
                f"🔢 تلاش قبلی: <code>{_fmt(saved.get('total_steps', 0))}</code>\n"
                f"⚙️ {NUM_WORKERS_12} worker (12 کلمه) + {NUM_WORKERS_24} worker (24 کلمه)"
            )


threading.Thread(target=_auto_resume_thread, daemon=True).start()


# ─── Signal Handlers ─────────────────────────────────────────────
def _on_signal(signum, frame):
    print(f"[signal {signum}] Saving state...")
    _do_stop()
    for p in _workers:
        p.join(timeout=2)
    print("[exit] Saved. Bye.")
    sys.exit(0)


signal.signal(signal.SIGTERM, _on_signal)
signal.signal(signal.SIGINT,  _on_signal)


# ─── Auth Guard ──────────────────────────────────────────────────
def _allowed(update: Update) -> bool:
    if not ALLOWED_USERS:
        return True
    return update.effective_user.id in ALLOWED_USERS


# ─── /help & /start ──────────────────────────────────────────────
async def cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _allowed(update): return
    lib = "✅ coincurve (سریع)" if _HAS_COINCURVE else "⚠️ bip32utils (کند — pip install coincurve)"
    await update.message.reply_text(
        f"⚡ <b>Tron Mnemonic Finder Bot</b>\n\n"
        f"<b>دستورات:</b>\n"
        f"/search <code>آدرس</code> [passphrase]\n"
        f"  مثال: <code>/search TXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</code>\n"
        f"  ↳ همزمان ۱۲ و ۲۴ کلمه‌ای بررسی می‌شه\n\n"
        f"/stop — توقف جستجو\n"
        f"/status — وضعیت فعلی\n"
        f"/resume — ادامه از آخرین نقطه\n"
        f"/clear — پاک کردن تمام پیشرفت\n"
        f"/help — این راهنما\n\n"
        f"⚙️ Workers: <b>{NUM_WORKERS_12}</b> (12 کلمه) + <b>{NUM_WORKERS_24}</b> (24 کلمه)"
        f" = <b>{NUM_WORKERS_12+NUM_WORKERS_24}</b> کل\n"
        f"📦 کتابخانه: {lib}\n\n"
        f"💡 پیام‌های بهبود ویرایش می‌شن (بدون اسپم)\n"
        f"🔒 فقط یک آدرس در هر لحظه قابل جستجوست",
        parse_mode=ParseMode.HTML
    )


async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _allowed(update): return
    await cmd_help(update, ctx)


# ─── /search ─────────────────────────────────────────────────────
async def cmd_search(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _allowed(update): return

    with _lock:
        if state["running"]:
            await update.message.reply_text(
                "⛔ <b>جستجو در حال اجراست</b>\n\n"
                f"🎯 آدرس فعلی: <code>{state['target_address']}</code>\n\n"
                "ابتدا با /stop جستجو را متوقف کن، سپس آدرس جدید وارد کن.",
                parse_mode=ParseMode.HTML
            )
            return

    args = ctx.args or []
    if not args:
        await update.message.reply_text(
            "❌ آدرس هدف وارد نشده.\n\n"
            "استفاده:\n<code>/search TRX_ADDRESS [passphrase]</code>",
            parse_mode=ParseMode.HTML
        )
        return

    target = args[0].strip()
    if len(target) != 34 or not target.startswith("T"):
        await update.message.reply_text(
            "❌ آدرس ترون نامعتبر.\nباید ۳۴ کاراکتر و با <code>T</code> شروع شود.",
            parse_mode=ParseMode.HTML
        )
        return

    passphrase = " ".join(args[1:]) if len(args) > 1 else ""

    chat_id = update.effective_chat.id
    _reset_status_msg()
    _do_start(target, passphrase, resume=False, chat_id=chat_id)

    await update.message.reply_text(
        f"🚀 <b>جستجو شروع شد!</b>\n\n"
        f"🎯 هدف: <code>{target}</code>\n"
        f"🔑 Passphrase: {'✅ دارد' if passphrase else '❌ ندارد'}\n\n"
        f"⚙️ گروه ۱۲ کلمه‌ای: <b>{NUM_WORKERS_12}</b> worker\n"
        f"⚙️ گروه ۲۴ کلمه‌ای: <b>{NUM_WORKERS_24}</b> worker\n\n"
        f"هنگام بهبود score، همان پیام ویرایش می‌شود 🔔",
        parse_mode=ParseMode.HTML
    )


# ─── /stop ───────────────────────────────────────────────────────
async def cmd_stop(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _allowed(update): return
    _do_stop()
    await update.message.reply_text(
        "⏹ <b>جستجو متوقف شد.</b>\nپیشرفت ذخیره شد.",
        parse_mode=ParseMode.HTML
    )


# ─── /status ─────────────────────────────────────────────────────
async def cmd_status(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _allowed(update): return

    with _lock:
        s = state.copy()

    total   = s["total_steps_ever"] + s["steps"]
    elapsed = time.time() - s["start_time"] if s["running"] and s["start_time"] else 0
    elapsed_str = (
        f"{int(elapsed//3600)}h {int((elapsed%3600)//60)}m {int(elapsed%60)}s"
        if elapsed else "—"
    )
    icon = "⚡" if s["running"] else ("🎉" if s["found"] else "⏹")
    length_tag = f" ({s['best_length']} کلمه‌ای)" if s["best_length"] else ""

    text = (
        f"{icon} <b>وضعیت جستجو</b>\n\n"
        f"🎯 هدف: <code>{s['target_address'] or '—'}</code>\n"
        f"📊 Prefix: <b>{s['best_score']}/34</b>  |  Total: <b>{s['best_total']}/34</b>{length_tag}\n"
        f"🔢 تلاش‌ها: <code>{_fmt(total)}</code>\n"
        f"⚡ سرعت: <code>{_fmt(s['attempts_per_sec'])}/s</code>\n"
        f"👷 Workers فعال: <code>{s['active_workers']}/{NUM_WORKERS_12+NUM_WORKERS_24}</code>\n"
        f"🔍 Counter 12: <code>{_fmt(s['counter_12'])}</code>  |  "
        f"Counter 24: <code>{_fmt(s['counter_24'])}</code>\n"
        f"⏱ مدت: <code>{elapsed_str}</code>\n"
    )
    if s["best_address"]:
        text += f"\n📍 بهترین آدرس:\n<code>{s['best_address']}</code>\n"
    if s["best_mnemonic"]:
        text += f"\n📄 Mnemonic:\n<code>{s['best_mnemonic']}</code>"

    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


# ─── /resume ─────────────────────────────────────────────────────
async def cmd_resume(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _allowed(update): return

    with _lock:
        if state["running"]:
            await update.message.reply_text("⚠️ جستجو الان در حال اجراست.")
            return
        target      = state["target_address"]
        passphrase  = state["passphrase"]
        prev_total  = state["total_steps_ever"]
        prev_score  = state["best_score"]
        prev_c12    = state["counter_12"]
        prev_c24    = state["counter_24"]

    if not target:
        await update.message.reply_text("❌ هیچ پیشرفت قبلی‌ای وجود نداره.\nبا /search شروع کن.")
        return

    chat_id = update.effective_chat.id
    _reset_status_msg()
    _do_start(target, passphrase, resume=True, chat_id=chat_id)

    await update.message.reply_text(
        f"↺ <b>جستجو ادامه یافت</b>\n\n"
        f"🎯 هدف: <code>{target}</code>\n"
        f"📊 بهترین قبلی: <b>{prev_score}/34</b>\n"
        f"🔢 از تلاش: <code>{_fmt(prev_total)}</code>\n"
        f"🔍 Counter 12: <code>{_fmt(prev_c12)}</code>  |  "
        f"Counter 24: <code>{_fmt(prev_c24)}</code>",
        parse_mode=ParseMode.HTML
    )


# ─── /clear ──────────────────────────────────────────────────────
async def cmd_clear(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not _allowed(update): return
    with _lock:
        if state["running"]:
            await update.message.reply_text("⚠️ ابتدا جستجو را با /stop متوقف کن.")
            return
        state.update(
            best_score=0, best_total=0, best_mnemonic="", best_address="",
            best_length=0, history=[], total_steps_ever=0, steps=0,
            target_address="", passphrase="",
            counter_12=0, counter_24=0,
        )
        if SAVE_FILE.exists():
            SAVE_FILE.unlink()
    _reset_status_msg()
    await update.message.reply_text("🗑 تمام پیشرفت پاک شد.")


# ─── Main ─────────────────────────────────────────────────────────
def main():
    global _bot_loop, _bot_app

    mp.freeze_support()
    print(f"[*] Backend : {'coincurve (fast)' if _HAS_COINCURVE else 'bip32utils (slow)'}")
    print(f"[*] Workers : {NUM_WORKERS_12} (12-word) + {NUM_WORKERS_24} (24-word) = {NUM_WORKERS_12+NUM_WORKERS_24} total")
    print(f"[*] Progress: {SAVE_FILE.absolute()}")
    print(f"[*] Starting bot...")

    if BOT_TOKEN == "YOUR_TOKEN_HERE":
        print("[ERROR] BOT_TOKEN تنظیم نشده!\n"
              "        export BOT_TOKEN='توکن_شما'  را اجرا کن.")
        sys.exit(1)

    app = Application.builder().token(BOT_TOKEN).build()
    _bot_app = app

    app.add_handler(CommandHandler("start",  cmd_start))
    app.add_handler(CommandHandler("help",   cmd_help))
    app.add_handler(CommandHandler("search", cmd_search))
    app.add_handler(CommandHandler("stop",   cmd_stop))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("resume", cmd_resume))
    app.add_handler(CommandHandler("clear",  cmd_clear))

    async def _capture_loop(app):
        global _bot_loop
        _bot_loop = asyncio.get_running_loop()

    app.post_init = _capture_loop

    print("[*] Bot is running. Press Ctrl+C to stop.")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
