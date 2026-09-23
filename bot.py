#!/usr/bin/env python3
# ============================================================
# LKCN BOT v13 FINAL — FARM + TELE FIX + LOG ON/OFF
# Owner @UnknownGuy9876 | @SGCodexs
# ============================================================
import socket, struct, sys, hashlib, hmac, json, time, random, threading, os, re
from collections import deque

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "cryptography"])
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ============ CONFIG ============
HOST = "45.119.215.15"
PORT = 9000
CV = "2.2.0"
UI_REFRESH = 1.0

# Auto eat
AUTO_EAT_ENABLED = True
BUFF_ITEMS_PRIORITY = ["luong_kho_3", "luong_kho_2", "luong_kho_1"]
AUTO_EAT_CHECK_EVERY = 5
AUTO_EAT_AFTER_EXPIRE_DELAY = 5
AUTO_EAT_RETRY_DELAY = 3
BUFF_PREFIX = "luong_kho"

# Timing
HEARTBEAT_INTERVAL = 30
STALL_TIMEOUT = 90
RING_SIZE = 300

# Auto hunt — [FIX] max = 100 theo AutoSettingsDto.MAX_HUNT_RANGE_PCT
HUNT_RANGE_PCT = 100

USERNAME = ""
PASSWORD = ""

LOG_DIR = "/storage/emulated/0/Apktool_M"
LOG_FILE = os.path.join(LOG_DIR, "bot.log")
PKT_FILE = os.path.join(LOG_DIR, "packets.log")

# ============ LOG ============
def _write(path, msg):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except Exception:
        pass

def logline(msg):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    _write(LOG_FILE, f"[{ts}] {msg}")

# ============ RING BUFFER ============
_RING = deque(maxlen=RING_SIZE)

def ring_push(direction, op, size, body):
    _RING.append((time.time(), direction, op, size, body))

def ring_dump(reason=""):
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(PKT_FILE, "a", encoding="utf-8") as f:
            f.write("\n" + "=" * 70 + "\n")
            f.write(f"[OFF @ {time.strftime('%Y-%m-%d %H:%M:%S')}] LÝ DO: {reason}\n")
            f.write(f"[RING DUMP: {len(_RING)} packets cuối]\n")
            f.write("=" * 70 + "\n")
            for ts, d, op, ln, body in _RING:
                tstr = time.strftime('%H:%M:%S', time.localtime(ts))
                f.write(f"[{tstr}] {d:<4} op=0x{op:02X} len={ln:<5} | {body}\n")
            f.write("=" * 70 + "\n\n")
    except Exception as e:
        logline(f"ring_dump fail: {e!r}")

# ============ CRYPTO ============
def hkdf(sh, i):
    prk = hmac.new(b"\x00" * 32, sh, hashlib.sha256).digest()
    return hmac.new(prk, i.encode() + b"\x01", hashlib.sha256).digest()[:32]

def nonce(c):
    return b"\x00" * 4 + struct.pack(">Q", c)

def frame(p):
    return struct.pack(">I", len(p)) + p

# ============ STATE ============
class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.connected = False
        self.logged_in = False
        self.level = 0
        self.exp = 0
        self.exp_into = 0
        self.exp_for_next = 0
        self.hp = 0; self.max_hp = 0
        self.mp = 0; self.max_mp = 0
        self.map_id = 0
        self.map_name = "?"
        self.auto_running = False
        self.target_monster = None
        self.exp_per_min = 0
        self.status = "Starting..."
        self.start_time = time.time()
        self.exp_history = []
        self.total_died = 0
        self.buff_item = None
        self.buff_remain_ms = 0
        self.buff_total_ms = 0
        self.buff_hp_per_sec = 0
        self.buff_mp_per_sec = 0
        self.eat_count = 0
        self.last_buff_seen = 0
        self.last_eat_time = 0
        self.tried_items = []
        self.char_name = "?"
        self.last_recv_time = 0
        self.last_ping_time = 0
        self.kick_reason = ""
        self.kick_time = 0
        self.total_recv = 0
        self.total_sent = 0
        self.last_data_time = time.time()
        self.last_op_seen = 0
        # [v13] Server settings debug
        self.server_vip = None
        self.server_settings = None

STATE = State()

# ============ BOT ============
class Bot:
    def __init__(self):
        self.s = None; self.kc = None; self.ks = None
        self.ce = 0; self.cf = 0
        self.session = None
        self.running = False
        self.dead = False
        self.io_lock = threading.Lock()
        self.connect_time = 0
        self.auto_on_time = 0
        self.stop_reason = ""

    def set_status(self, s):
        with STATE.lock:
            STATE.status = s

    def _rx(self, n, to=8):
        self.s.settimeout(to); d = b""
        while len(d) < n:
            x = self.s.recv(n - len(d))
            if not x: raise Exception("connection closed by server")
            d += x
        return d

    def _rf(self, to=8):
        h = self._rx(4, to)
        ln = struct.unpack(">I", h)[0]
        if ln <= 0 or ln > (1 << 20): raise Exception(f"bad frame length: {ln}")
        return self._rx(ln, to)

    def connect(self):
        if self.s:
            try: self.s.close()
            except: pass
        self.session = None
        self.s = socket.create_connection((HOST, PORT), timeout=4)
        priv = ec.generate_private_key(ec.SECP256R1())
        der = priv.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        self.s.sendall(frame(bytes([0xE0]) + der))
        body = self._rf()
        if body[0] != 0xE1: raise Exception("handshake failed")
        srv = serialization.load_der_public_key(body[1:])
        sh = priv.exchange(ec.ECDH(), srv)
        self.kc = hkdf(sh, "linhkhi-v1-c2s")
        self.ks = hkdf(sh, "linhkhi-v1-s2c")
        self.ce = 0; self.cf = 0
        self.connect_time = time.time()
        with STATE.lock:
            STATE.connected = True
            STATE.last_recv_time = time.time()
            STATE.last_ping_time = time.time()
            STATE.last_data_time = time.time()
            STATE.total_recv = 0
            STATE.total_sent = 0
        logline("CONNECTED — handshake OK")

    def send(self, op, payload=b""):
        with self.io_lock:
            if isinstance(payload, (dict, list)):
                payload = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
            ct = AESGCM(self.kc).encrypt(nonce(self.ce), bytes([op]) + payload, None)
            self.ce += 1
            self.s.sendall(frame(bytes([0xE2]) + ct))
            with STATE.lock:
                STATE.total_sent += 1
            try:
                txt = payload.decode("utf-8", errors="ignore")
                body = txt[:300] if txt.startswith(("{", "[")) else payload[:80].hex()
            except Exception:
                body = payload[:80].hex()
            ring_push("SEND", op, len(payload), body)

    def recv(self, to=8):
        with self.io_lock:
            body = self._rf(to)
            op = body[0]; data = body[1:]
            if op == 0xE2:
                pt = AESGCM(self.ks).decrypt(nonce(self.cf), data, None)
                self.cf += 1
                inner_op = pt[0]
                inner_data = pt[1:]
                with STATE.lock:
                    STATE.total_recv += 1
                    STATE.last_data_time = time.time()
                    STATE.last_op_seen = inner_op
                try:
                    txt = inner_data.decode("utf-8", errors="ignore")
                    ibody = txt[:300] if txt.startswith(("{", "[")) else inner_data[:80].hex()
                except Exception:
                    ibody = inner_data[:80].hex()
                ring_push("RECV", inner_op, len(inner_data), ibody)
                return inner_op, inner_data
            with STATE.lock:
                STATE.total_recv += 1
                STATE.last_data_time = time.time()
                STATE.last_op_seen = op
            ring_push("RECV", op, len(data), data[:80].hex())
            return op, data

    def login(self):
        logline(f"LOGIN attempt user={USERNAME!r} pass_len={len(PASSWORD)}")
        login_payload = {
            "username": USERNAME, "password": PASSWORD,
            "clientVersion": CV, "rememberToken": "",
            "protocolVersion": 23,
            # [MÒ] Thử ép VIP
            "vipLevel": 15,
            "isVip": True,
            "vip": True,
        }
        self.send(0x0A, login_payload)
        op, data = self.recv(to=10)
        try:
            raw = data.decode(errors="ignore")
        except Exception:
            raw = data.hex()
        print(f"\n[DEBUG] LOGIN RESPONSE op=0x{op:02X}")
        print(f"[DEBUG] Raw: {raw[:500]}")

        try:
            r = json.loads(data.decode())
        except Exception:
            raise Exception(f"Login response not JSON: {raw[:200]!r}")

        if not r.get("success"):
            print(f"\n[DEBUG] LOGIN FAIL — full JSON:")
            print(json.dumps(r, indent=2, ensure_ascii=False))
            logline(f"LOGIN FAIL: {r}")
            raise Exception(str(r.get("message", "login fail")))

        self.session = r["sessionToken"]
        st = r.get("stats", {})
        with STATE.lock:
            STATE.logged_in = True
            STATE.level = st.get("level", 0)
            STATE.exp = st.get("exp", 0)
            STATE.exp_into = st.get("expIntoLevel", 0)
            STATE.exp_for_next = st.get("expForLevelUp", 0)
            STATE.hp = st.get("hp", 0); STATE.max_hp = st.get("maxHp", 0)
            STATE.mp = st.get("mp", 0); STATE.max_mp = st.get("maxMp", 0)
            STATE.char_name = r.get("characterName", "?")
            STATE.exp_history = [(time.time(), STATE.exp)]
        logline(f"LOGIN OK char={STATE.char_name} lv={STATE.level}")
        return r

    def enter_world(self, zone=0):
        self.send(0x1F, {"sessionToken": self.session, "zoneIndex": zone})
        op, data = self.recv(to=10)
        try:
            obj = json.loads(data.decode())
        except Exception:
            print(f"[DEBUG] ENTER_WORLD raw: {data.decode(errors='ignore')[:300]}")
            raise
        mid = obj.get("mapId")
        with STATE.lock:
            STATE.map_id = mid
            STATE.map_name = obj.get("mapName", "?")
        logline(f"ENTER_WORLD map={STATE.map_name} id={mid}")
        return obj

    def _auto_settings(self):
        # [v13] huntRangePct = 100 + ép autoTeleport = True + vipLevel
        return {"enabled": True, "huntRangePct": HUNT_RANGE_PCT,
                "autoPickup": True, "pickupPham": True, "pickupLuong": True,
                "pickupLinh": True, "pickupBao": True, "pickupTien": True,
                "autoTeleport": True, "autoGoback": True,
                "khongNhatNguyenLieu": False, "khongNhatTrangBi": False,
                "linhThachTuCap": 0,
                # [MÒ] Thử ép VIP
                "vipLevel": 15,
                "isVip": True,
                "vip": True,
                "canTeleport": True,
                "teleportEnabled": True,
                "allowTeleport": True}

    def request_auto_settings(self):
        """[v13b] 0x07 AUTO_SETTINGS_REQUEST — chỉ sessionToken."""
        self.send(0x07, {"sessionToken": self.session})
        print("[>] Sent 0x07 AUTO_SETTINGS_REQUEST")

    def auto_on(self):
        self.send(0x09, {"sessionToken": self.session, "settings": self._auto_settings()})
        self.auto_on_time = time.time()
        with STATE.lock:
            STATE.auto_running = True

    def revive(self):
        self.send(0x16, {"sessionToken": self.session,
                         "operationId": "",
                         "expectedInventoryRevision": -1})

    def use_item(self, code, qty=1):
        self.send(0x44, {"sessionToken": self.session,
                         "itemCode": code, "quantity": qty})
        with STATE.lock:
            STATE.eat_count += 1

    def ping(self):
        try:
            self.send(0x09, {"sessionToken": self.session, "settings": self._auto_settings()})
            with STATE.lock:
                STATE.last_ping_time = time.time()
            return True
        except Exception as e:
            logline(f"PING FAIL: {e!r}")
            return False

    def handle(self, op, data):
        try:
            txt = data.decode("utf-8", errors="ignore")
            obj = json.loads(txt) if txt.startswith(("{", "[")) else None
        except: obj = None

        with STATE.lock:
            STATE.last_recv_time = time.time()

        # [v13 DEBUG] Server trả auto settings + VIP level
        if op == 0x08 and obj:
            settings = obj.get("settings", {})
            vip = obj.get("vipLevel", 0)
            with STATE.lock:
                STATE.server_vip = vip
                STATE.server_settings = settings
            logline(f"AUTO_SETTINGS_RESPONSE vip={vip} settings={settings}")
            print(f"\n[DEBUG] ═══ SERVER AUTO SETTINGS ═══")
            print(f"[DEBUG] VIP level:  {vip}")
            print(f"[DEBUG] autoTeleport: {settings.get('autoTeleport')}  ← KEY!")
            print(f"[DEBUG] enabled:      {settings.get('enabled')}")
            print(f"[DEBUG] Full: {settings}")
            print(f"[DEBUG] ═════════════════════════════\n")
            return

        if op == 0x63 and obj:
            code = obj.get("code", "?")
            msg = obj.get("message", "")
            raise Exception(f"SERVER_ERROR code={code} msg={msg}")

        if op == 0x12 and obj:
            running = obj.get("running", False)
            reason = obj.get("reason") or ""
            target = obj.get("targetMonsterId")
            # [v13b] Debug 0x12
            print(f"[<] 0x12 AUTO_STATE running={running} reason={reason!r} target={target}")
            logline(f"AUTO_STATE running={running} reason={reason!r} target={target}")
            with STATE.lock:
                STATE.auto_running = running
                STATE.target_monster = target
            if not running:
                if any(k in reason.lower() for k in ("death", "die", "revive", "dead")):
                    self.dead = True
                elif reason:
                    time.sleep(1)
                    try: self.auto_on()
                    except: pass
            return

        if op == 0x58 and obj:
            effects = obj.get("effects", [])
            with STATE.lock:
                best = None
                for e in effects:
                    code = e.get("itemCode", "")
                    if code.startswith(BUFF_PREFIX):
                        remain = e.get("remainingMs", 0)
                        if best is None or remain > best[1]:
                            best = (code, remain, e)
                if best:
                    code, remain, e = best
                    STATE.buff_item = code
                    STATE.buff_remain_ms = remain
                    STATE.buff_total_ms = e.get("totalMs", 0)
                    STATE.buff_hp_per_sec = e.get("hpPerSec", 0)
                    STATE.buff_mp_per_sec = e.get("mpPerSec", 0)
                    STATE.last_buff_seen = time.time()
                    STATE.tried_items = []
                else:
                    if STATE.buff_item is not None:
                        STATE.buff_item = None
                        STATE.buff_remain_ms = 0
                        STATE.buff_total_ms = 0
                        STATE.buff_hp_per_sec = 0
                        STATE.buff_mp_per_sec = 0
            return

        if op == 0x31 and obj:
            st = obj.get("stats", {})
            if isinstance(st, dict):
                with STATE.lock:
                    if "hp" in st: STATE.hp = st["hp"]
                    if "maxHp" in st: STATE.max_hp = st["maxHp"]
                    if "mp" in st: STATE.mp = st["mp"]
                    if "maxMp" in st: STATE.max_mp = st["maxMp"]
                    if "exp" in st: STATE.exp = st["exp"]
                    if "expIntoLevel" in st: STATE.exp_into = st["expIntoLevel"]
                    if "expForLevelUp" in st: STATE.exp_for_next = st["expForLevelUp"]
                    if "level" in st: STATE.level = st["level"]
                    now = time.time()
                    STATE.exp_history.append((now, STATE.exp))
                    cutoff = now - 600
                    STATE.exp_history = [e for e in STATE.exp_history if e[0] > cutoff]
                    if len(STATE.exp_history) >= 2:
                        t0, e0 = STATE.exp_history[0]
                        t1, e1 = STATE.exp_history[-1]
                        dt = t1 - t0
                        if dt > 10:
                            STATE.exp_per_min = int((e1 - e0) * 60 / dt)
            return

        if op == 0x1E:
            raise KeyboardInterrupt

    def close(self):
        self.running = False
        try: self.s.close()
        except: pass

# ============ WATCHDOG ============
class Watchdog(threading.Thread):
    def __init__(self, b):
        super().__init__(daemon=True); self.b = b
        self.last_eat_check = time.time()

    def run(self):
        while self.b.running:
            try:
                if self.b.dead:
                    with STATE.lock:
                        STATE.total_died += 1
                    time.sleep(3)
                    try: self.b.revive()
                    except: pass
                    self.b.dead = False
                    time.sleep(2)
                    try: self.b.auto_on()
                    except: pass

                if AUTO_EAT_ENABLED and (time.time() - self.last_eat_check > AUTO_EAT_CHECK_EVERY):
                    self.last_eat_check = time.time()
                    with STATE.lock:
                        has_buff = STATE.buff_item is not None
                        last_buff_seen = STATE.last_buff_seen
                        last_eat = STATE.last_eat_time
                        tried = list(STATE.tried_items)

                    now = time.time()
                    should_eat = False
                    item_to_eat = None

                    if not has_buff:
                        if last_buff_seen > 0 and (now - last_buff_seen) < AUTO_EAT_AFTER_EXPIRE_DELAY:
                            pass
                        else:
                            for item in BUFF_ITEMS_PRIORITY:
                                if item not in tried:
                                    if (now - last_eat) > AUTO_EAT_RETRY_DELAY:
                                        should_eat = True
                                        item_to_eat = item
                                    break
                            if not should_eat and len(tried) >= len(BUFF_ITEMS_PRIORITY):
                                with STATE.lock:
                                    STATE.tried_items = []

                    if should_eat and item_to_eat:
                        try:
                            self.b.use_item(item_to_eat, 1)
                            with STATE.lock:
                                STATE.last_eat_time = now
                                if item_to_eat not in STATE.tried_items:
                                    STATE.tried_items.append(item_to_eat)
                            time.sleep(1)
                        except: pass

                time.sleep(2)
            except Exception:
                break

# ============ STOP / KICK ============
def _stop_bot(bot, reason):
    bot.stop_reason = reason
    uptime = time.time() - bot.connect_time if bot.connect_time else 0
    start_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(bot.connect_time)) if bot.connect_time else "?"
    stop_str = time.strftime('%Y-%m-%d %H:%M:%S')

    with STATE.lock:
        STATE.kick_reason = reason
        STATE.kick_time = time.time()
        STATE.connected = False
        STATE.logged_in = False
        STATE.auto_running = False
        STATE.status = f"OFF: {reason}"
        total_recv = STATE.total_recv
        total_sent = STATE.total_sent
        last_op = STATE.last_op_seen
        char = STATE.char_name
        lv = STATE.level
        vip = STATE.server_vip

    logline("=" * 60)
    logline(f"💀 BOT OFF — LÝ DO: {reason}")
    logline(f"  Bắt đầu:  {start_str}")
    logline(f"  Kết thúc: {stop_str}")
    logline(f"  Uptime:   {uptime:.0f}s ({uptime/60:.1f} phút)")
    logline(f"  Char:     {char} (Lv {lv}) VIP={vip}")
    logline(f"  Traffic:  RECV={total_recv} SENT={total_sent}")
    logline(f"  Last op:  0x{last_op:02X}")
    logline("=" * 60)

    ring_dump(reason)

    print(f"\n{'='*66}")
    print(f"💀 BOT OFF")
    print(f"   Lý do:    {reason}")
    print(f"   Bắt đầu:  {start_str}")
    print(f"   Kết thúc: {stop_str}")
    print(f"   Uptime:   {uptime:.0f}s ({uptime/60:.1f} phút)")
    print(f"   Char:     {char} (Lv {lv}) VIP={vip}")
    print(f"   Traffic:  RECV={total_recv}  SENT={total_sent}")
    print(f"   Last op:  0x{last_op:02X}")
    print(f"   Log:      {LOG_FILE}")
    print(f"   Packets:  {PKT_FILE}")
    print(f"{'='*66}\n")

    bot.running = False
    try: bot.close()
    except: pass

def _log_kick(bot, reason):
    logline(f"KICK DETECTED: {reason}")

# ============ UI ============
def clear_screen():
    os.system('clear')

def bar(pct, width=30, fill='█', empty='░'):
    pct = max(0, min(100, pct))
    n = int(width * pct / 100)
    return fill * n + empty * (width - n)

def fmt_time(ms):
    s = int(ms / 1000)
    return f"{s//60:02d}:{s%60:02d}"

def render_ui():
    C = {"R":"\033[91m","G":"\033[92m","Y":"\033[93m","B":"\033[94m","M":"\033[95m",
         "C":"\033[96m","W":"\033[97m","X":"\033[0m","BOLD":"\033[1m","DIM":"\033[2m"}
    while True:
        with STATE.lock:
            s = {
                "conn": STATE.connected, "login": STATE.logged_in,
                "lv": STATE.level, "exp": STATE.exp,
                "exp_into": STATE.exp_into, "exp_next": STATE.exp_for_next,
                "hp": STATE.hp, "max_hp": STATE.max_hp,
                "mp": STATE.mp, "max_mp": STATE.max_mp,
                "map_id": STATE.map_id, "map_name": STATE.map_name,
                "auto": STATE.auto_running,
                "dead": STATE.total_died,
                "target": STATE.target_monster,
                "epm": STATE.exp_per_min,
                "status": STATE.status,
                "uptime": time.time() - STATE.start_time,
                "buff_item": STATE.buff_item,
                "buff_remain": STATE.buff_remain_ms,
                "buff_total": STATE.buff_total_ms,
                "tried": list(STATE.tried_items),
                "eat": STATE.eat_count,
                "char": STATE.char_name,
                "kick_reason": STATE.kick_reason,
                "kick_time": STATE.kick_time,
                "total_recv": STATE.total_recv,
                "total_sent": STATE.total_sent,
                "last_op": STATE.last_op_seen,
                "silent": time.time() - STATE.last_data_time,
                "vip": STATE.server_vip,
            }
        clear_screen()
        print(f"{C['C']}{C['BOLD']}╔══════════════════════════════════════════════════════════════╗{C['X']}")
        print(f"{C['C']}{C['BOLD']}║  💀 DEVILS WILL RISE — LKCN BOT v13 FINAL                     ║{C['X']}")
        print(f"{C['C']}{C['BOLD']}║  Owner @UnknownGuy9876  |  Channel @SGCodexs                 ║{C['X']}")
        print(f"{C['C']}{C['BOLD']}╚══════════════════════════════════════════════════════════════╝{C['X']}")
        print()
        conn_icon = f"{C['G']}●{C['X']} Online" if s["conn"] else f"{C['R']}●{C['X']} Offline"
        login_icon = f"{C['G']}●{C['X']} Yes" if s["login"] else f"{C['Y']}●{C['X']} No"
        auto_icon = f"{C['G']}●{C['X']} ON" if s["auto"] else f"{C['R']}●{C['X']} OFF"
        print(f"  {C['BOLD']}Status:{C['X']}      {conn_icon}   Login: {login_icon}   Auto: {auto_icon}")
        print(f"  {C['BOLD']}Account:{C['X']}     {C['Y']}{USERNAME}{C['X']} — {C['M']}{s['char']}{C['X']}  VIP: {s['vip']}")
        print(f"  {C['BOLD']}Uptime:{C['X']}      {int(s['uptime']//3600):02d}:{int((s['uptime']%3600)//60):02d}:{int(s['uptime']%60):02d}")
        print(f"  {C['BOLD']}Deaths:{C['X']}      {C['R']}{s['dead']}{C['X']}  |  Eats: {C['G']}{s['eat']}{C['X']}")
        print(f"  {C['BOLD']}Traffic:{C['X']}     ↓{s['total_recv']} ↑{s['total_sent']}  |  Last op: 0x{s['last_op']:02X}  |  Silent: {s['silent']:.0f}s")
        print()
        print(f"  {C['C']}{C['BOLD']}┌─ CHARACTER ──────────────────────────────────────────────────┐{C['X']}")
        print(f"  {C['C']}│{C['X']}  Level:      {C['Y']}{C['BOLD']}Lv {s['lv']}{C['X']}")
        pct = 100 * s["exp_into"] / s["exp_next"] if s["exp_next"] else 0
        print(f"  {C['C']}│{C['X']}  Exp:        {bar(pct,30,C['M']+'█'+C['X'],C['DIM']+'░'+C['X'])} {pct:5.2f}%")
        print(f"  {C['C']}│{C['X']}  Exp total:  {s['exp']:,}")
        epm_c = "G" if s["epm"]>10000 else ("Y" if s["epm"]>1000 else "R")
        print(f"  {C['C']}│{C['X']}  Exp/min:    {C[epm_c]}{s['epm']:,}{C['X']}")
        hp_p = 100*s["hp"]/s["max_hp"] if s["max_hp"] else 0
        mp_p = 100*s["mp"]/s["max_mp"] if s["max_mp"] else 0
        hp_c = "G" if hp_p>50 else ("Y" if hp_p>20 else "R")
        print(f"  {C['C']}│{C['X']}  HP:         {bar(hp_p,30,C[hp_c]+'█'+C['X'],C['DIM']+'░'+C['X'])} {s['hp']}/{s['max_hp']}")
        print(f"  {C['C']}│{C['X']}  MP:         {bar(mp_p,30,C['B']+'█'+C['X'],C['DIM']+'░'+C['X'])} {s['mp']}/{s['max_mp']}")
        if s["buff_item"]:
            remain_min = s["buff_remain"] / 60000
            color = "G" if remain_min > 10 else ("Y" if remain_min > 2 else "R")
            pct_buff = 100 * s["buff_remain"] / s["buff_total"] if s["buff_total"] else 0
            time_str = fmt_time(s["buff_remain"])
            print(f"  {C['C']}│{C['X']}  Buff:       {bar(pct_buff,25,C[color]+'█'+C['X'],C['DIM']+'░'+C['X'])} {C[color]}{time_str}{C['X']} {C['DIM']}{s['buff_item']}{C['X']}")
        else:
            print(f"  {C['C']}│{C['X']}  Buff:       {C['R']}khong co{C['X']}")
        print(f"  {C['C']}└──────────────────────────────────────────────────────────────┘{C['X']}")
        print()
        print(f"  {C['C']}{C['BOLD']}┌─ MAP ────────────────────────────────────────────────────────┐{C['X']}")
        print(f"  {C['C']}│{C['X']}  Map:        {C['BOLD']}{s['map_name']}{C['X']} (id={s['map_id']})")
        print(f"  {C['C']}│{C['X']}  Target:     {C['Y']}{s['target'] or '(none)'}{C['X']}")
        print(f"  {C['C']}│{C['X']}  Hunt range: {C['Y']}{HUNT_RANGE_PCT}%{C['X']} {C['DIM']}(max 100){C['X']}")
        print(f"  {C['C']}└──────────────────────────────────────────────────────────────┘{C['X']}")
        print()
        print(f"  {C['BOLD']}Status:{C['X']}  {C['Y']}{s['status']}{C['X']}")
        if s["kick_reason"]:
            print()
            print(f"  {C['R']}{C['BOLD']}┌─ 💀 LÝ DO OFF ────────────────────────────────────────────────┐{C['X']}")
            print(f"  {C['R']}│{C['X']}  {C['Y']}{s['kick_reason']}{C['X']}")
            if s["kick_time"]:
                tstr = time.strftime('%H:%M:%S', time.localtime(s["kick_time"]))
                print(f"  {C['R']}│{C['X']}  {C['DIM']}Off lúc {tstr}{C['X']}")
            print(f"  {C['R']}│{C['X']}  {C['DIM']}Log: {LOG_FILE}{C['X']}")
            print(f"  {C['R']}│{C['X']}  {C['DIM']}Pkt: {PKT_FILE}{C['X']}")
            print(f"  {C['R']}└──────────────────────────────────────────────────────────────┘{C['X']}")
        print()
        print(f"  {C['DIM']}Ctrl+C to stop{C['X']}")
        time.sleep(UI_REFRESH)

# ============ LOGIN SCREEN ============
def login_screen():
    os.system('clear')
    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║  💀 DEVILS WILL RISE — LKCN BOT v13 FINAL    ║")
    print("  ║  Owner @UnknownGuy9876 | @SGCodexs           ║")
    print("  ╚══════════════════════════════════════════════╝")
    print()
    print("  ──────────────────────────────────────────────")
    print("              ĐĂNG NHẬP TÀI KHOẢN")
    print("  ──────────────────────────────────────────────")
    print()
    raw = input("  Username: ").strip()
    # [v13] Clean username — chỉ giữ a-z A-Z 0-9 _ - . @
    user = re.sub(r'[^A-Za-z0-9_.@-]', '', raw)
    if user != raw:
        print(f"  [CLEAN] '{raw}' → '{user}'")
    if not user:
        print("\n  [!] Chưa nhập username"); time.sleep(2); return None

    pw = input("  Password: ")
    if not pw:
        print("\n  [!] Chưa nhập password"); time.sleep(2); return None

    print(f"\n  [DEBUG] Username: {user!r}")
    print(f"  [DEBUG] Password: {pw!r} (len={len(pw)})")
    print(f"\n  [*] Đang đăng nhập: {user}\n  [*] Kết nối server...")
    time.sleep(2)
    return user, pw

# ============ MAIN LOOP ============
def run_bot():
    bot = Bot()
    try:
        bot.set_status("Connecting...")
        bot.connect()
        bot.set_status("Logging in...")
        bot.login()
        bot.set_status("Entering world...")
        bot.enter_world(zone=0)
        time.sleep(0.5)
        # [v13b] Gửi 0x07 TRƯỚC để lấy setting hiện tại
        bot.request_auto_settings()
        time.sleep(1.5)
        # Rồi gửi 0x09 update
        bot.auto_on(); time.sleep(1)
        bot.auto_on(); time.sleep(1)
        bot.auto_on()
        bot.set_status("Running")
        bot.running = True
        Watchdog(bot).start()

        start_str = time.strftime('%Y-%m-%d %H:%M:%S')
        with STATE.lock:
            STATE.connected = True
            char = STATE.char_name
            lv = STATE.level
        logline("=" * 60)
        logline(f"🚀 BOT START — {start_str}")
        logline(f"  Char: {char} (Lv {lv})")
        logline(f"  Server: {HOST}:{PORT}")
        logline(f"  Hunt range: {HUNT_RANGE_PCT}%")
        logline("=" * 60)
        print(f"\n🚀 BOT START — {start_str} | {char} Lv{lv}")
        print(f"   Hunt range: {HUNT_RANGE_PCT}%")
        print(f"   Log: {LOG_FILE}")
        print(f"   Packets: {PKT_FILE} (chỉ ghi khi OFF)\n")

        while bot.running:
            try:
                op, data = bot.recv(to=2)
                bot.handle(op, data)
            except socket.timeout:
                with STATE.lock:
                    silent = time.time() - STATE.last_data_time
                if silent > STALL_TIMEOUT:
                    reason = f"SERVER IM LẶNG {silent:.0f}s (>{STALL_TIMEOUT}s)"
                    _log_kick(bot, reason)
                    _stop_bot(bot, reason)
                    return
            except KeyboardInterrupt:
                reason = "SERVER KICK (opcode 0x1E)"
                _log_kick(bot, reason)
                _stop_bot(bot, reason)
                return
            except Exception as e:
                r = str(e)
                low = r.lower()
                if "closed" in low or "reset" in low or "broken pipe" in low or "abort" in low:
                    reason = "SERVER ĐÓNG SOCKET (mạng/Doze)"
                elif "bad frame" in low:
                    reason = f"FRAME LỖI: {r}"
                elif "server_error" in low:
                    reason = f"SERVER ERROR: {r}"
                elif "decrypt" in low or "tag" in low or "mac" in low:
                    reason = f"DECRYPT FAIL: {r}"
                elif "timed out" in low:
                    reason = "RECV TIMEOUT"
                else:
                    reason = f"EXCEPTION: {r}"
                _log_kick(bot, reason)
                _stop_bot(bot, reason)
                return

            with STATE.lock:
                last_ping = STATE.last_ping_time
            if time.time() - last_ping > HEARTBEAT_INTERVAL:
                if not bot.ping():
                    reason = "HEARTBEAT FAIL"
                    _log_kick(bot, reason)
                    _stop_bot(bot, reason)
                    return
    except KeyboardInterrupt:
        _stop_bot(bot, "USER STOP (Ctrl+C)")
        return
    except Exception as e:
        reason = f"FATAL: {e!r}"
        _log_kick(bot, reason)
        _stop_bot(bot, reason)
        return

# ============ ENTRY ============
if __name__ == "__main__":
    while True:
        creds = login_screen()
        if creds:
            USERNAME, PASSWORD = creds
            break
    print("  [*] Khởi động bot...")
    time.sleep(1)
    t = threading.Thread(target=run_bot, daemon=True)
    t.start()
    try:
        render_ui()
    except KeyboardInterrupt:
        print("\n\n  Stopping...")
        sys.exit(0)