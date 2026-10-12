"""
SMART GUEST HOUSE EZVIZ - Cloud Multi-Tenant System
Aplikasi Manajemen Kos & Smartlock Cloud Deployment
"""
import os, re, json, sqlite3, secrets, socket, time
from datetime import datetime, timedelta, timezone
from functools import wraps
from zoneinfo import ZoneInfo

import requests
from urllib.parse import urlparse
try:
    from dotenv import load_dotenv
except ImportError:  # python-dotenv belum terpasang: lanjut tanpa .env
    def load_dotenv(*_a, **_k):
        return False
from flask import Flask, g, jsonify, request, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))
DB_PATH = os.path.join(BASE_DIR, "guesthouse.db")

DEFAULT_DOMAIN = "https://isgpopen.ezvizlife.com"
APP_VERSION = "2026.10.10-cloud-ready"

MASTER_PHONE = "085242306022"
SAMPLE_OWNER_PHONE = "085128066022"
DEFAULT_PASSWORD = "gringary"

P_TOKEN = "/api/lapp/token/get"
P_OTAP_ACTION = "/api/v3/device/otap/action"
P_DEVICE_INFO = "/api/lapp/device/info"
P_KEYLOCK_OPEN = "/api/v3/keylock/open/list"  # Query Door Lock Open Records (GET)
P_KEYLOCK_USERS = "/api/v3/keylock/user/list"  # Get Lock User List (GET)

ROOMS = [str(f * 100 + n) for f in range(1, 3) for n in range(1, 11)]

app = Flask(__name__)

def env(k, d=""):
    return (os.getenv(k) or d).strip()

def tz():
    try:
        return ZoneInfo(env("APP_TIMEZONE", "Asia/Makassar"))
    except Exception:  # Windows tanpa paket tzdata -> pakai WITA tetap (+08:00)
        return timezone(timedelta(hours=8))

def now():
    return datetime.now(tz()).strftime("%Y-%m-%d %H:%M:%S")

def base():
    u = urlparse(env("EZVIZ_AREA_DOMAIN", DEFAULT_DOMAIN))
    return f"{u.scheme}://{u.netloc}" if u.scheme and u.netloc else DEFAULT_DOMAIN

def api_base():
    """Host untuk panggilan API setelah token. Prioritas: EZVIZ_AREA_DOMAIN (.env) > areaDomain dari
    respons token (sesuai dokumentasi) > domain bawaan."""
    if env("EZVIZ_AREA_DOMAIN"):
        return base()
    a = (_tok.get("area") or "").strip().rstrip("/")
    if a:
        if not a.startswith("http"):
            a = "https://" + a
        u = urlparse(a)
        if u.netloc:
            return f"{u.scheme}://{u.netloc}"
    return base()

def to_int(v, default=0):
    try:
        return int(float(str(v).replace(",", "").strip() or 0))
    except (ValueError, TypeError):
        return default

def net_hint(exc, url=""):
    host = urlparse(url or base()).hostname or (url or base())
    t = str(exc)
    if "NameResolutionError" in t or "getaddrinfo" in t or "Name or service not known" in t:
        return (f"Komputer/server tidak dapat menemukan alamat host {host} (masalah DNS/jaringan, bukan kesalahan kode). "
                f"Coba: 'nslookup {host}' di CMD; ganti DNS ke 8.8.8.8 / 1.1.1.1; matikan atau nyalakan VPN; "
                f"coba jaringan/hotspot lain; pastikan firewall/ISP tidak memblokir. Detail: {t[:180]}")
    if "Timeout" in t or "timed out" in t:
        return f"Koneksi ke {host} timeout (>15 detik). Periksa internet/firewall."
    return f"Gagal terhubung ke host {host}: {t[:220]}"

def live():
    return env("EZVIZ_LIVE_ENABLED", "false").lower() == "true"

def mask(v):
    return f"{v[:4]}••••{v[-4:]}" if len(v) >= 8 else ("•" * len(v))

def scrub(s):
    s = str(s)
    for sec in (env("EZVIZ_APP_SECRET"), env("EZVIZ_ACCESS_TOKEN"), _tok.get("value") or ""):
        if sec:
            s = s.replace(sec, "***")
    return re.sub(r"at\.[A-Za-z0-9\-_]{20,}", "at.***", s)

# ------------------------------------------------------------------ DATABASE SETUP
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()

def q(sql, a=()):
    return [dict(r) for r in db().execute(sql, a).fetchall()]

def q1(sql, a=()):
    r = q(sql, a)
    return r[0] if r else None

def ex(sql, a=()):
    c = db().execute(sql, a)
    db().commit()
    return c.lastrowid

SCHEMA = """
CREATE TABLE IF NOT EXISTS owners(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    kos_name TEXT NOT NULL,
    is_master INTEGER DEFAULT 0,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS rooms(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    room_number TEXT NOT NULL,
    price INTEGER DEFAULT 0,
    status TEXT DEFAULT 'KOSONG',
    UNIQUE(owner_id, room_number)
);

CREATE TABLE IF NOT EXISTS smartlock_settings(
    room_id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    serial_number TEXT DEFAULT '',
    verification_code TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS tenants(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    name TEXT,
    phone TEXT,
    email TEXT NOT NULL,
    room_id INTEGER,
    start_datetime TEXT,
    end_datetime TEXT,
    price INTEGER DEFAULT 0,
    notes TEXT DEFAULT '',
    status TEXT DEFAULT 'AKTIF',
    ezviz_password_id TEXT DEFAULT '',
    ezviz_sync_status TEXT DEFAULT 'BELUM TERSINKRON',
    ezviz_message TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS payments(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    tenant_id INTEGER,
    room_id INTEGER,
    start_date TEXT,
    end_date TEXT,
    amount INTEGER DEFAULT 0,
    status TEXT DEFAULT 'BELUM',
    paid_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER DEFAULT 0,
    timestamp TEXT,
    user TEXT,
    action TEXT,
    room TEXT,
    result TEXT,
    message TEXT
);

CREATE TABLE IF NOT EXISTS door_open_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    room_id INTEGER NOT NULL,
    open_time INTEGER NOT NULL,
    timestamp TEXT,
    user_name TEXT DEFAULT '',
    open_type TEXT DEFAULT '',
    open_label TEXT DEFAULT '',
    UNIQUE(room_id, open_time, user_name, open_type)
);

CREATE TABLE IF NOT EXISTS lock_user_names(
    room_id INTEGER NOT NULL,
    user_name TEXT NOT NULL,
    remark TEXT DEFAULT '',
    PRIMARY KEY(room_id, user_name)
);

CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
"""

def create_owner_rooms(owner_id):
    for rn in ROOMS:
        ex("INSERT OR IGNORE INTO rooms(owner_id, room_number) VALUES(?,?)", (owner_id, rn))
        rid = q1("SELECT id FROM rooms WHERE owner_id=? AND room_number=?", (owner_id, rn))["id"]
        ex("INSERT OR IGNORE INTO smartlock_settings(room_id, owner_id) VALUES(?,?)", (rid, owner_id))

def init_db():
    c = sqlite3.connect(DB_PATH)
    c.executescript(SCHEMA)

    pwd_hash = generate_password_hash(DEFAULT_PASSWORD, method="pbkdf2:sha256")

    if not c.execute("SELECT 1 FROM owners WHERE phone=?", (MASTER_PHONE,)).fetchone():
        c.execute(
            "INSERT INTO owners(phone, password_hash, name, kos_name, is_master, created_at) VALUES(?,?,?,?,1,?)",
            (MASTER_PHONE, pwd_hash, "Master Administrator", "Pusat Master Kos", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )

    sample = c.execute("SELECT id FROM owners WHERE phone=?", (SAMPLE_OWNER_PHONE,)).fetchone()
    if not sample:
        c.execute(
            "INSERT INTO owners(phone, password_hash, name, kos_name, is_master, created_at) VALUES(?,?,?,?,0,?)",
            (SAMPLE_OWNER_PHONE, pwd_hash, "Pemilik Kos Sampel 1", "Kos Melati Utama", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        sample_id = c.execute("SELECT id FROM owners WHERE phone=?", (SAMPLE_OWNER_PHONE,)).fetchone()[0]
        for rn in ROOMS:
            c.execute("INSERT OR IGNORE INTO rooms(owner_id, room_number) VALUES(?,?)", (sample_id, rn))
            rid_row = c.execute("SELECT id FROM rooms WHERE owner_id=? AND room_number=?", (sample_id, rn)).fetchone()
            if rid_row:
                c.execute("INSERT OR IGNORE INTO smartlock_settings(room_id, owner_id) VALUES(?,?)", (rid_row[0], sample_id))

    if not c.execute("SELECT 1 FROM settings WHERE key='secret_key'").fetchone():
        c.execute("INSERT INTO settings VALUES('secret_key',?)", (secrets.token_hex(32),))

    c.commit()
    sk = c.execute("SELECT value FROM settings WHERE key='secret_key'").fetchone()[0]
    c.close()
    return sk

_sk = init_db()
app.secret_key = env("SECRET_KEY") or _sk
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=env("COOKIE_SECURE", "false").lower() == "true")

def audit(action, room="", result="OK", message=""):
    owner_id = session.get("owner_id", 0)
    phone = session.get("phone", "-")
    ex("INSERT INTO audit_logs(owner_id,timestamp,user,action,room,result,message) VALUES(?,?,?,?,?,?,?)",
       (owner_id, now(), phone, action, room, result, scrub(message)[:500]))

# ------------------------------------------------------------------ AUTHENTICATION
def login_required(master_only=False):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if not session.get("owner_id"):
                return jsonify(ok=False, message="Silakan login terlebih dahulu."), 401
            if master_only and not session.get("is_master"):
                return jsonify(ok=False, message="Akses khusus Akun Master Administrator."), 403
            return f(*a, **k)
        return w
    return deco

def is_master():
    return bool(session.get("is_master"))

def can_owner(owner_id):
    return is_master() or owner_id == session.get("owner_id")

def room_ok(rid):
    """Baris kamar bila boleh diakses akun yang login (Master: semua, Pemilik: miliknya)."""
    r = q1("SELECT * FROM rooms WHERE id=?", (rid,))
    return r if r and can_owner(r["owner_id"]) else None

def tenant_ok(tid):
    t = q1("SELECT t.*, r.room_number FROM tenants t JOIN rooms r ON r.id=t.room_id WHERE t.id=?", (tid,))
    return t if t and can_owner(t["owner_id"]) else None

@app.get("/")
def index():
    # Boleh ditaruh di folder templates/ atau sejajar dengan app.py
    tpl = os.path.join(BASE_DIR, "templates")
    if os.path.exists(os.path.join(tpl, "index.html")):
        return send_from_directory(tpl, "index.html")
    return send_from_directory(BASE_DIR, "index.html")

@app.get("/api/me")
def me():
    if not session.get("owner_id"):
        return jsonify(authenticated=False)
    return jsonify(
        authenticated=True,
        owner_id=session.get("owner_id"),
        phone=session.get("phone"),
        name=session.get("name"),
        kos_name=session.get("kos_name"),
        is_master=bool(session.get("is_master"))
    )

@app.post("/api/login")
def login():
    d = request.json or {}
    phone = re.sub(r"[^\d]", "", str(d.get("phone", "")).strip())
    password = str(d.get("password", "")).strip()

    if not phone or not password:
        return jsonify(ok=False, message="Nomor telepon dan password wajib diisi."), 400

    time.sleep(0.2)

    owner = q1("SELECT * FROM owners WHERE phone=?", (phone,))
    if not owner or not check_password_hash(owner["password_hash"], password):
        audit("Login GAGAL", result="GAGAL", message=f"No HP: {phone}")
        return jsonify(ok=False, message="Nomor telepon atau password salah."), 401

    session.clear()
    session["owner_id"] = owner["id"]
    session["phone"] = owner["phone"]
    session["name"] = owner["name"]
    session["kos_name"] = owner["kos_name"]
    session["is_master"] = owner["is_master"]

    audit("Login", result="OK")
    return jsonify(ok=True, name=owner["name"], kos_name=owner["kos_name"], phone=owner["phone"], is_master=bool(owner["is_master"]))

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)

# ------------------------------------------------------------------ TOKEN & EZVIZ API
_tok = {"value": None, "exp": 0, "err": None, "area": ""}

def is_token_expired():
    if not _tok["value"]:
        return True
    return time.time() >= (_tok["exp"] - 60)

def get_token(force=False):
    key, sec = env("EZVIZ_APP_KEY"), env("EZVIZ_APP_SECRET")
    if not (key and sec):
        return None, {"code": "-", "msg": "AppKey belum diatur di .env"}
    if not force and not is_token_expired():
        return _tok["value"], None

    try:
        r = requests.post(base() + P_TOKEN, data={"appKey": key, "appSecret": sec}, timeout=15)
    except requests.exceptions.RequestException as e:
        return None, {"code": "NET", "msg": net_hint(e, base() + P_TOKEN)}
    try:
        j = r.json()
    except ValueError:
        return None, {"code": str(r.status_code), "msg": f"Respons token bukan JSON (HTTP {r.status_code}). Periksa EZVIZ_AREA_DOMAIN."}

    data = j.get("data") or {}
    if str(j.get("code")) == "200" and data.get("accessToken"):
        _tok["value"] = data["accessToken"]
        et = float(data.get("expireTime") or 0)
        if et <= 0:
            _tok["exp"] = time.time() + 6 * 86400
        else:
            _tok["exp"] = (et / 1000) if et > 1e11 else (time.time() + et)
        _tok["area"] = str(data.get("areaDomain") or "").strip()
        _tok["err"] = None
        return _tok["value"], None

    code = str(j.get("code"))
    p = parse_ezviz_code(code, j.get("msg"))
    _tok["err"] = {"code": code, "msg": f"[{code}] {p['detail']} (server: {j.get('msg') or '-'})"}
    return None, _tok["err"]

def otap_hdr(sn, domain, kind, ident):
    return {"deviceSerial": sn, "resourceCategory": "DoorLock", "localIndex": "0",
            "domainIdentifier": domain, kind: ident, "Content-Type": "application/json"}

def lock_cfg(room_id, owner_id):
    return q1("SELECT r.room_number, s.* FROM rooms r JOIN smartlock_settings s ON s.room_id=r.id WHERE r.id=? AND r.owner_id=?", (room_id, owner_id))

def iso(s):
    return datetime.strptime(s[:16], "%Y-%m-%d %H:%M").replace(tzinfo=tz()).isoformat(timespec="milliseconds")

def parse_ezviz_code(code_str, raw_msg=""):
    """
    Penerjemah Kode Error Resmi EZVIZ Dokumen V3
    """
    code = str(code_str)
    explanations = {
        "200": ("SUKSES", "Perintah berhasil dieksekusi oleh server EZVIZ."),
        "10001": ("PARAMETER_ERROR", "Format parameter request tidak valid. Periksa apakah deviceSerial, email/telepon, atau format ISO datetime sesuai spec."),
        "10002": ("TOKEN_INVALID", "AccessToken expired atau tidak valid. Sistem akan merefresh token secara otomatis."),
        "10005": ("APPKEY_FROZEN", "appKey dibekukan/dinonaktifkan di EZVIZ Open Platform."),
        "10017": ("APPKEY_NOT_EXIST", "appKey tidak ditemukan. Periksa EZVIZ_APP_KEY di .env."),
        "10030": ("APPKEY_SECRET_MISMATCH", "appKey dan appSecret tidak cocok. Periksa EZVIZ_APP_SECRET di .env."),
        "10031": ("NO_PERMISSION", "Akun pengembang (appKey) tidak memiliki izin (CONFIG/UPDATE) pada perangkat ini."),
        "20002": ("DEVICE_NOT_EXIST", "Serial Number perangkat tidak terdaftar atau tidak ditemukan di akun cloud EZVIZ ini."),
        "20007": ("DEVICE_OFFLINE", "Perangkat Smartlock / Hub Gateway dalam kondisi OFFLINE (terputus dari WiFi/Server)."),
        "20008": ("DEVICE_TIMEOUT", "Perangkat tidak merespons perintah dalam batas waktu. Silakan coba beberapa saat lagi."),
        "20018": ("NOT_DEVICE_OWNER", "Perangkat dimiliki oleh akun EZVIZ master lain (Bukan akun milik appKey ini)."),
        "20608": ("USER_NOT_EXIST", "ID atau Pengguna Smartlock tidak ditemukan pada perangkat."),
        "50000": ("SERVER_ERROR", "Server Cloud EZVIZ mengalami gangguan internal.")
    }

    status_name, detail = explanations.get(code, ("UNKNOWN_ERROR", f"Pesan Server: {raw_msg or 'Error tidak terdokumentasi'}"))
    return {
        "code": code,
        "type": status_name,
        "detail": detail
    }

def ezviz_http(method, path, **kw):
    """Panggil API EZVIZ pada api_base(); bila host areaDomain tak terjangkau, ulangi ke domain dasar."""
    primary = api_base()
    try:
        return requests.request(method, primary + path, timeout=15, **kw), primary
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        fb = base()
        if fb != primary:
            return requests.request(method, fb + path, timeout=15, **kw), fb
        raise

def manage_hint(text):
    if "manage failed" in str(text).lower():
        return (" Kemungkinan penyebab: slot password temporer penuh (maks. 10; bersihkan lewat menu Password Pintu), "
                "waktu mulai sudah lewat, nama password tidak diterima, atau model kunci bukan CS-DL05-R201-WBCP-GR.")
    return ""

def v3(method, path, hdr=None, body=None, _retry=True, params=None):
    if not live():
        return {"ok": False, "code": "-", "msg": "EZVIZ Live Mode Nonaktif di .env", "parsed": {"type": "SIMULATION", "detail": "Aplikasi berjalan dalam mode simulasi lokal."}}

    tok, err = get_token()
    if not tok:
        return {"ok": False, "code": err.get("code"), "msg": err.get("msg"), "parsed": {"type": "TOKEN_ERROR", "detail": err.get("msg")}}

    h = {"accessToken": tok, **(hdr or {})}
    try:
        r, used = ezviz_http(method, path, headers=h, json=body, params=params)
    except requests.exceptions.RequestException as e:
        return {"ok": False, "code": "NET", "msg": str(e)[:200], "parsed": {"type": "NETWORK_ERROR", "detail": net_hint(e, api_base() + path)}}

    try:
        j = r.json()
    except ValueError:
        return {"ok": False, "code": str(r.status_code), "msg": r.text[:150],
                "parsed": {"type": "NON_JSON_RESPONSE", "detail": f"Server membalas HTTP {r.status_code} (bukan JSON) dari {used}{path}. Periksa EZVIZ_AREA_DOMAIN di .env."}}

    meta = j.get("meta") or {}
    code = str(meta.get("code") or j.get("code") or "50000")
    msg = meta.get("message") or j.get("msg") or ""

    if code in ("10002", "100010") and _retry:
        get_token(force=True)
        return v3(method, path, hdr, body, _retry=False, params=params)

    dm = (meta.get("moreInfo") or {}).get("deviceMeta") or {}
    dcode, dmsg = dm.get("code"), str(dm.get("errorMsg") or "")

    # Cloud menjawab 200 tetapi perangkat menolak perintah
    if code == "200" and dcode and str(dcode).lower() not in ("0x00000000", "0", "0x0"):
        return {"ok": False, "code": str(dcode), "msg": dmsg, "data": j.get("data"), "domain": used,
                "parsed": {"type": "DEVICE_ERROR", "detail": f"Perangkat menolak perintah: {dmsg or '-'} (kode {dcode})." + manage_hint(dmsg)}}

    parsed_info = parse_ezviz_code(code, msg)
    if code != "200":
        extra = manage_hint(msg + " " + dmsg)
        if dmsg and dmsg not in msg:
            extra = f" Pesan perangkat: {dmsg}." + extra
        parsed_info["detail"] = parsed_info["detail"] + extra
    return {"ok": code == "200", "code": code, "msg": msg, "data": j.get("data"), "parsed": parsed_info, "domain": used}

# ------------------------------------------------------------------ HELPER PASSWORD SEMENTARA DI PINTU
def pw_name(name):
    n = re.sub(r"[^A-Za-z0-9 ]", "", name or "").strip()[:20]
    return n or "Tamu"

def err_text(r):
    p = r.get("parsed") or {}
    return f"[{r.get('code')}] {p.get('type')}: {p.get('detail')}" + (f" (server: {r['msg']})" if r.get("msg") else "")

def lock_call(sn, ident, body):
    return v3("PUT", P_OTAP_ACTION, hdr=otap_hdr(sn, "TemporaryPassword", "actionIdentifier", ident), body=body)

def lock_list(sn):
    r = lock_call(sn, "QueryTemporaryPassword", {"enabled": True})
    items = r.get("data") if r.get("ok") and isinstance(r.get("data"), list) else []
    return r, items

def lock_delete(sn, pid):
    return lock_call(sn, "DeleteTemporaryPassword", {"passwordID": int(pid), "opType": 0})

def lock_find_id(sn, name):
    """API Add tidak mengembalikan passwordID, jadi dicari dari daftar (ID terbesar dengan nama yang sama)."""
    _r, items = lock_list(sn)
    ids = [to_int(p.get("passwordID")) for p in items if p.get("passwordName") == name]
    return str(max(ids)) if ids else ""

def lock_add(sn, name, email, start_iso, end_iso, times=-1):
    return lock_call(sn, "AddTemporaryPassword", {"usageTimes": times, "passwordName": name, "type": 0,
                                                  "account": email, "startTimeStr": start_iso, "endTimeStr": end_iso})

def retryable(r):
    return (not r["ok"]) and (r.get("parsed") or {}).get("type") in ("DEVICE_ERROR", "UNKNOWN_ERROR", "PARAMETER_ERROR")

def push_tenant_password(tenant_name, email, start, end, sn):
    """Kirim password temporer penyewa. Return (r, passwordID, catatan)."""
    name = pw_name(tenant_name)
    r = lock_add(sn, name, email, iso(start), iso(end))
    note = ""
    if retryable(r):
        # Sebagian perangkat menolak waktu mulai yang sudah lewat/sama dengan sekarang -> coba sekali lagi
        now_dt = datetime.now(tz())
        st = datetime.strptime(start[:16], "%Y-%m-%d %H:%M").replace(tzinfo=tz())
        en = datetime.strptime(end[:16], "%Y-%m-%d %H:%M").replace(tzinfo=tz())
        if st <= now_dt + timedelta(minutes=1) and now_dt + timedelta(minutes=2) < en:
            st2 = now_dt + timedelta(minutes=2)
            r2 = lock_add(sn, name, email, st2.isoformat(timespec="milliseconds"), iso(end))
            if r2["ok"]:
                r = r2
                note = f" (waktu mulai digeser ke {st2.strftime('%Y-%m-%d %H:%M')} karena perangkat menolak waktu mulai yang sudah lewat)"
    pid = lock_find_id(sn, name) if r["ok"] else ""
    return r, pid, note

def room_serial(rid):
    row = q1("SELECT serial_number FROM smartlock_settings WHERE room_id=?", (rid,))
    return str((row or {}).get("serial_number") or "").strip().upper()

def parse_ez_time(txt):
    try:
        return datetime.fromisoformat(str(txt))
    except (ValueError, TypeError):
        try:
            return datetime.strptime(str(txt)[:16].replace("T", " "), "%Y-%m-%d %H:%M").replace(tzinfo=tz())
        except (ValueError, TypeError):
            return None

def classify_passwords(rid, items):
    """Kategori tiap password di pintu: AKTIF / KADALUARSA / CHECKOUT / TIDAK TERPAKAI."""
    now_dt = datetime.now(tz())
    tenants = q("SELECT * FROM tenants WHERE room_id=?", (rid,))
    active = [t for t in tenants if t["status"] == "AKTIF"]
    done = [t for t in tenants if t["status"] != "AKTIF"]
    out = []
    for p in items:
        pid = str(p.get("passwordID"))
        nm = p.get("passwordName") or ""
        end = parse_ez_time(p.get("endTimeStr"))
        expired = bool(end and end.tzinfo and end < now_dt)
        match = next((t for t in active if str(t["ezviz_password_id"] or "") == pid or
                      (not t["ezviz_password_id"] and pw_name(t["name"]) == nm)), None)
        cat, who = "TIDAK TERPAKAI", ""
        if match:
            cat, who = ("KADALUARSA" if expired else "AKTIF"), match["name"]
        else:
            gone = next((t for t in done if pw_name(t["name"]) == nm), None)
            if gone:
                cat, who = "CHECKOUT", gone["name"]
            elif expired:
                cat = "KADALUARSA"
        out.append({"passwordID": p.get("passwordID"), "passwordName": nm, "account": p.get("account", ""),
                    "startTimeStr": p.get("startTimeStr", ""), "endTimeStr": p.get("endTimeStr", ""),
                    "availableTimes": p.get("availableTimes"), "category": cat, "tenant": who})
    return out

def delete_lock_ids(rid, sn, ids):
    deleted, failed = [], []
    for pid in ids:
        r = lock_delete(sn, pid)
        if r["ok"]:
            deleted.append(pid)
            ex("UPDATE tenants SET ezviz_sync_status=CASE WHEN status='AKTIF' THEN 'BELUM TERSINKRON' ELSE ezviz_sync_status END, "
               "ezviz_password_id='' WHERE room_id=? AND ezviz_password_id=?", (rid, str(pid)))
        else:
            failed.append({"passwordID": pid, "error": err_text(r)})
            if r["code"] in ("NET", "20007", "-"):
                break
    return deleted, failed

def cleanup_room(rid, mode="auto"):
    """auto = hapus KADALUARSA / TIDAK TERPAKAI / CHECKOUT (penyewa aktif aman). all = hapus semuanya."""
    room = q1("SELECT * FROM rooms WHERE id=?", (rid,))
    sn = room_serial(rid)
    base_res = {"ok": False, "deleted": 0, "failed": 0, "kept": 0}
    if not live():
        return {**base_res, "message": f"Kamar {room['room_number']}: Live Mode OFF (.env), tidak ada yang dihapus."}
    if not sn:
        return {**base_res, "message": f"Kamar {room['room_number']}: Serial Number belum diisi."}
    r, items = lock_list(sn)
    if not r["ok"]:
        return {**base_res, "message": f"Kamar {room['room_number']}: gagal membaca daftar password. {err_text(r)}"}
    items = classify_passwords(rid, items)
    targets = [p["passwordID"] for p in items if mode == "all" or p["category"] != "AKTIF"]
    deleted, failed = delete_lock_ids(rid, sn, targets)
    kept = len(items) - len(targets)
    msg = f"Kamar {room['room_number']}: {len(deleted)} dihapus, {kept} dipertahankan (aktif), {len(failed)} gagal."
    if failed:
        msg += " Gagal: " + "; ".join(f"ID {f['passwordID']} {f['error']}" for f in failed[:3])
    audit("Bersihkan Password Pintu" + (" (semua)" if mode == "all" else ""), room["room_number"],
          "OK" if not failed else "GAGAL", msg)
    return {"ok": not failed, "message": msg, "deleted": len(deleted), "failed": len(failed), "kept": kept}

# ------------------------------------------------------------------ UJI SINKRONISASI PADA COMMISSIONING
@app.post("/api/admin/test-sync/<int:rid>")
@login_required()
def test_sync_room(rid):
    room = room_ok(rid)
    if not room:
        return jsonify(ok=False, message="Kamar tidak ditemukan."), 404

    sn = room_serial(rid)
    if not sn:
        return jsonify(ok=False, message=f"Serial Number untuk Kamar {room['room_number']} belum dikonfigurasi di Setting Smartlock."), 400

    now_dt = datetime.now(tz())
    end_dt = now_dt + timedelta(hours=1)
    email = "test@guesthouse.id"

    r = lock_add(sn, "TestSync", email, now_dt.isoformat(timespec="milliseconds"), end_dt.isoformat(timespec="milliseconds"), times=1)
    note = ""
    if retryable(r):
        r2 = lock_add(sn, "TestSync", email, (now_dt + timedelta(minutes=2)).isoformat(timespec="milliseconds"),
                      end_dt.isoformat(timespec="milliseconds"), times=1)
        if r2["ok"]:
            r = r2
            note = (" CATATAN: perangkat menolak waktu mulai = sekarang tetapi menerima waktu mulai +2 menit; "
                    "aplikasi otomatis menggeser waktu mulai saat check-in/sync.")
    if r["ok"]:
        pid = lock_find_id(sn, "TestSync")
        if pid:
            d = lock_delete(sn, pid)
            note += " Password uji sudah dihapus kembali dari pintu." if d["ok"] else f" PERINGATAN: password uji ID {pid} belum terhapus, hapus lewat menu Password Pintu."
        else:
            note += " Password uji tidak ditemukan di daftar; periksa menu Password Pintu."

    return jsonify(
        ok=r["ok"],
        domain=r.get("domain") or api_base(),
        serial_number=sn,
        code=r["code"],
        raw_message=r["msg"],
        error_type=r["parsed"]["type"],
        explanation=(r["parsed"]["detail"] + note)
    )

# ------------------------------------------------------------------ ENDPOINTS APPLICATION
@app.get("/api/master/owners")
@login_required(master_only=True)
def master_owners_list():
    return jsonify(q("SELECT id, phone, name, kos_name, is_master, created_at FROM owners ORDER BY id DESC"))

@app.post("/api/master/owners")
@login_required(master_only=True)
def master_owner_add():
    d = request.json or {}
    phone = re.sub(r"[^\d]", "", str(d.get("phone", "")).strip())
    name = str(d.get("name", "")).strip()
    kos_name = str(d.get("kos_name", "")).strip() or f"Kos {name}"
    password = str(d.get("password", "")).strip() or DEFAULT_PASSWORD

    if len(phone) < 9 or not name:
        return jsonify(ok=False, message="Nama dan Nomor Telepon (min 9 digit) wajib diisi."), 400

    if q1("SELECT 1 FROM owners WHERE phone=?", (phone,)):
        return jsonify(ok=False, message="Nomor telepon sudah terdaftar."), 400

    pwd_hash = generate_password_hash(password, method="pbkdf2:sha256")
    oid = ex("INSERT INTO owners(phone, password_hash, name, kos_name, is_master, created_at) VALUES(?,?,?,?,0,?)",
             (phone, pwd_hash, name, kos_name, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    create_owner_rooms(oid)
    audit("Tambah Kos", result="OK", message=f"Kos: {kos_name}, HP: {phone}")
    return jsonify(ok=True, message=f"Kos '{kos_name}' ({name}) berhasil ditambahkan dengan 20 kamar default.")

@app.put("/api/master/owners/<int:oid>")
@login_required(master_only=True)
def master_owner_edit(oid):
    d = request.json or {}
    name = str(d.get("name", "")).strip()
    kos_name = str(d.get("kos_name", "")).strip()
    phone = re.sub(r"[^\d]", "", str(d.get("phone", "")).strip())

    if not name or not kos_name or len(phone) < 9:
        return jsonify(ok=False, message="Data nama, nama kos, dan nomor telepon tidak valid."), 400

    if not q1("SELECT 1 FROM owners WHERE id=?", (oid,)):
        return jsonify(ok=False, message="Data kos tidak ditemukan."), 404
    if q1("SELECT 1 FROM owners WHERE phone=? AND id<>?", (phone, oid)):
        return jsonify(ok=False, message="Nomor telepon sudah dipakai akun lain."), 400
    ex("UPDATE owners SET name=?, kos_name=?, phone=? WHERE id=?", (name, kos_name, phone, oid))
    audit("Edit Kos", result="OK", message=f"ID: {oid}, Kos: {kos_name}")
    return jsonify(ok=True, message="Data Kos berhasil diperbarui.")

@app.delete("/api/master/owners/<int:oid>")
@login_required(master_only=True)
def master_owner_delete(oid):
    target = q1("SELECT * FROM owners WHERE id=?", (oid,))
    if not target or target["is_master"]:
        return jsonify(ok=False, message="Akun Master tidak dapat dihapus."), 400

    ex("DELETE FROM door_open_logs WHERE owner_id=?", (oid,))
    ex("DELETE FROM lock_user_names WHERE room_id IN (SELECT id FROM rooms WHERE owner_id=?)", (oid,))
    ex("DELETE FROM smartlock_settings WHERE owner_id=?", (oid,))
    ex("DELETE FROM rooms WHERE owner_id=?", (oid,))
    ex("DELETE FROM tenants WHERE owner_id=?", (oid,))
    ex("DELETE FROM payments WHERE owner_id=?", (oid,))
    ex("DELETE FROM audit_logs WHERE owner_id=?", (oid,))
    ex("DELETE FROM owners WHERE id=?", (oid,))

    audit("Hapus Kos", result="OK", message=f"ID: {oid}")
    return jsonify(ok=True, message="Data Kos beserta seluruh kamarnya berhasil dihapus.")

@app.post("/api/rooms")
@login_required(master_only=True)
def room_add():
    d = request.json or {}
    owner_id = to_int(d.get("owner_id")) or session["owner_id"]
    if not q1("SELECT 1 FROM owners WHERE id=?", (owner_id,)):
        return jsonify(ok=False, message="Data kos tidak ditemukan."), 404
    room_number = str(d.get("room_number", "")).strip()
    price = to_int(d.get("price"))

    if not room_number:
        return jsonify(ok=False, message="Nomor kamar wajib diisi."), 400

    if q1("SELECT 1 FROM rooms WHERE owner_id=? AND room_number=?", (owner_id, room_number)):
        return jsonify(ok=False, message="Nomor kamar sudah ada pada kos ini."), 400

    rid = ex("INSERT INTO rooms(owner_id, room_number, price) VALUES(?,?,?)", (owner_id, room_number, price))
    ex("INSERT INTO smartlock_settings(room_id, owner_id) VALUES(?,?)", (rid, owner_id))
    audit("Tambah Kamar", room=room_number, result="OK")
    return jsonify(ok=True, message=f"Kamar {room_number} berhasil ditambahkan.")

@app.put("/api/rooms/<int:rid>")
@login_required()
def room_edit(rid):
    d = request.json or {}
    room_number = str(d.get("room_number", "")).strip()
    price = to_int(d.get("price"))

    if not room_number:
        return jsonify(ok=False, message="Nomor kamar tidak boleh kosong."), 400

    room = room_ok(rid)
    if not room:
        return jsonify(ok=False, message="Kamar tidak ditemukan."), 404
    if q1("SELECT 1 FROM rooms WHERE owner_id=? AND room_number=? AND id<>?", (room["owner_id"], room_number, rid)):
        return jsonify(ok=False, message="Nomor kamar sudah ada pada kos ini."), 400
    ex("UPDATE rooms SET room_number=?, price=? WHERE id=?", (room_number, price, rid))
    audit("Edit Kamar", room=room_number, result="OK")
    return jsonify(ok=True, message="Data kamar diperbarui.")

@app.delete("/api/rooms/<int:rid>")
@login_required(master_only=True)
def room_delete(rid):
    room = room_ok(rid)
    if not room:
        return jsonify(ok=False, message="Kamar tidak ditemukan."), 404

    if room["status"] == "TERISI":
        return jsonify(ok=False, message="Kamar terisi! Lakukan check-out penyewa dulu."), 400

    ex("DELETE FROM door_open_logs WHERE room_id=?", (rid,))
    ex("DELETE FROM lock_user_names WHERE room_id=?", (rid,))
    ex("DELETE FROM smartlock_settings WHERE room_id=?", (rid,))
    ex("DELETE FROM rooms WHERE id=?", (rid,))
    audit("Hapus Kamar", room=room["room_number"], result="OK")
    return jsonify(ok=True, message=f"Kamar {room['room_number']} berhasil dihapus.")

@app.post("/api/smartlock/<int:rid>/verify")
@login_required()
def verify_smartlock(rid):
    cfg = q1("SELECT r.room_number, s.* FROM rooms r JOIN smartlock_settings s ON s.room_id=r.id WHERE r.id=?", (rid,)) if room_ok(rid) else None
    if not cfg:
        return jsonify(ok=False, status="ERROR", title="Error Sistem", message="Data kamar tidak ditemukan.")

    sn = str(cfg["serial_number"] or "").strip().upper()
    vc = str(cfg["verification_code"] or "").strip()

    if not sn:
        return jsonify(ok=False, status="WARNING", title="Serial Number Kosong", message=f"Serial Number belum diisi untuk Kamar {cfg['room_number']}. Silakan isi di menu Setting Smartlock.")

    if not live():
        return jsonify(ok=True, status="SIMULATION", title="Mode Simulasi (Live Mode OFF)", message=f"Perangkat Kamar {cfg['room_number']} tersimpan di DB.\nSN: {sn}\nStatus: Mode Live OFF (.env).")

    tok, err = get_token()
    if not tok:
        return jsonify(ok=False, status="ERROR", title="Gagal Dapatkan Token EZVIZ", message=f"AppKey / AppSecret salah atau terblokir: {err.get('msg')}")

    try:
        r, _used = ezviz_http("POST", P_DEVICE_INFO, data={"accessToken": tok, "deviceSerial": sn})
        j = r.json()
        code = str(j.get("code"))

        if code == "200":
            data = j.get("data", {})
            is_online = str(data.get("status")) == "1"
            status_str = "ONLINE" if is_online else "OFFLINE"
            msg = f"Perangkat Kamar {cfg['room_number']} Terhubung!\nStatus Perangkat: {status_str}\nSN: {sn}"
            if not is_online:
                msg += "\n\nPeringatan: Perangkat dalam keadaan mati/terputus dari internet."
            if not vc:
                msg += "\nCatatan: Kode Verifikasi belum diisi."
            return jsonify(ok=is_online, status=status_str, title=f"Device {status_str}", message=msg)

        parsed = parse_ezviz_code(code, j.get("msg"))
        return jsonify(ok=False, status=parsed["type"], title=f"Error {parsed['type']}", message=f"Pesan Server: {parsed['detail']}\nDomain: {api_base()}")
    except Exception as e:
        return jsonify(ok=False, status="NET_ERROR", title="Koneksi Terputus", message=f"Gagal menghubungi server EZVIZ: {net_hint(e, base())}")

@app.post("/api/tenants/<int:tid>/sync")
@login_required()
def sync_tenant(tid):
    t = tenant_ok(tid)
    if not t or t["status"] != "AKTIF":
        return jsonify(ok=False, warning=False, message="Data penghuni aktif tidak ditemukan.")

    sn = room_serial(t["room_id"])

    if not sn:
        ex("UPDATE tenants SET ezviz_sync_status='BELUM TERSINKRON', ezviz_message='Serial Number belum diset' WHERE id=?", (tid,))
        return jsonify(ok=False, warning=True, message=f"Gagal Sinkronisasi:\nSerial Number Smartlock untuk Kamar {t['room_number']} belum diisi di menu Setting Smartlock.")

    if not live():
        ex("UPDATE tenants SET ezviz_sync_status='BELUM TERSINKRON', ezviz_message='Live Mode OFF' WHERE id=?", (tid,))
        return jsonify(ok=False, warning=True, message=f"Gagal Sinkronisasi:\nSistem saat ini berada dalam Mode Simulasi (Live Mode OFF).")

    # Hapus password lama milik penyewa ini (bila ada) agar slot (maks. 10) tidak menumpuk
    if t["ezviz_password_id"]:
        lock_delete(sn, t["ezviz_password_id"])

    r, pid, note = push_tenant_password(t["name"], t["email"], t["start_datetime"], t["end_datetime"], sn)

    if r["ok"]:
        ex("UPDATE tenants SET ezviz_sync_status='TEMP PASSWORD TERSINKRON', ezviz_message=?, ezviz_password_id=? WHERE id=?",
           ("Terkirim ke email" + note, pid, tid))
        audit("Sync Smartlock", t["room_number"], "OK", f"Sinkronisasi ulang berhasil untuk {t['name']}{note}")
        return jsonify(ok=True, warning=False, message=f"Sinkronisasi Berhasil!\nKode akses sementara untuk {t['name']} berhasil dikirimkan ulang ke email: {t['email']}{note}")
    else:
        ex("UPDATE tenants SET ezviz_sync_status='ERROR', ezviz_message=?, ezviz_password_id='' WHERE id=?", (err_text(r)[:300], tid))
        audit("Sync Smartlock GAGAL", t["room_number"], "GAGAL", err_text(r))
        return jsonify(ok=False, warning=True, message=f"Gagal Sinkronisasi ke EZVIZ Cloud (Kode {r['code']}):\nJenis: {r['parsed']['type']}\nPenjelasan: {r['parsed']['detail']}")

@app.get("/api/dashboard")
@login_required()
def dashboard():
    filter_oid = request.args.get("owner_id")
    is_m = session.get("is_master")
    m = now()[:7]

    if is_m and not filter_oid:
        occ = q1("SELECT COUNT(*) c FROM rooms WHERE status='TERISI'")["c"]
        total = q1("SELECT COUNT(*) c FROM rooms")["c"]
        paid = q1("SELECT COALESCE(SUM(amount),0) s FROM payments WHERE status='LUNAS' AND substr(paid_at,1,7)=?", (m,))["s"]
        unpaid = q1("SELECT COALESCE(SUM(amount),0) s FROM payments WHERE status='BELUM'")["s"]
        paid_all = q1("SELECT COALESCE(SUM(amount),0) s FROM payments WHERE status='LUNAS'")["s"]
        chart = q("SELECT substr(paid_at,1,7) m, SUM(amount) s FROM payments WHERE status='LUNAS' AND paid_at!='' GROUP BY m ORDER BY m DESC LIMIT 12")[::-1]
        aktif_t = q1("SELECT COUNT(*) c FROM tenants WHERE status='AKTIF'")["c"]
    else:
        oid = int(filter_oid) if (is_m and filter_oid) else session["owner_id"]
        occ = q1("SELECT COUNT(*) c FROM rooms WHERE owner_id=? AND status='TERISI'", (oid,))["c"]
        total = q1("SELECT COUNT(*) c FROM rooms WHERE owner_id=?", (oid,))["c"]
        paid = q1("SELECT COALESCE(SUM(amount),0) s FROM payments WHERE owner_id=? AND status='LUNAS' AND substr(paid_at,1,7)=?", (oid, m))["s"]
        unpaid = q1("SELECT COALESCE(SUM(amount),0) s FROM payments WHERE owner_id=? AND status='BELUM'", (oid,))["s"]
        paid_all = q1("SELECT COALESCE(SUM(amount),0) s FROM payments WHERE owner_id=? AND status='LUNAS'", (oid,))["s"]
        chart = q("SELECT substr(paid_at,1,7) m, SUM(amount) s FROM payments WHERE owner_id=? AND status='LUNAS' AND paid_at!='' GROUP BY m ORDER BY m DESC LIMIT 12", (oid,))[::-1]
        aktif_t = q1("SELECT COUNT(*) c FROM tenants WHERE owner_id=? AND status='AKTIF'", (oid,))["c"]

    return jsonify(total=total, kosong=total - occ, terisi=occ, aktif=aktif_t, pendapatan=paid, belum=unpaid, lunas=paid_all, chart=chart)

@app.get("/api/rooms")
@login_required()
def rooms():
    filter_oid = request.args.get("owner_id")
    if session.get("is_master"):
        if filter_oid:
            return jsonify(q("""SELECT r.id, r.owner_id, r.room_number, r.price, r.status, o.kos_name, t.name tenant, t.email, t.start_datetime, t.end_datetime
                FROM rooms r LEFT JOIN owners o ON o.id=r.owner_id LEFT JOIN tenants t ON t.room_id=r.id AND t.status='AKTIF' WHERE r.owner_id=? ORDER BY r.id""", (filter_oid,)))
        return jsonify(q("""SELECT r.id, r.owner_id, r.room_number, r.price, r.status, o.kos_name, t.name tenant, t.email, t.start_datetime, t.end_datetime
            FROM rooms r LEFT JOIN owners o ON o.id=r.owner_id LEFT JOIN tenants t ON t.room_id=r.id AND t.status='AKTIF' ORDER BY o.id, r.id"""))

    oid = session["owner_id"]
    return jsonify(q("""SELECT r.id, r.owner_id, r.room_number, r.price, r.status, t.name tenant, t.email, t.start_datetime, t.end_datetime
        FROM rooms r LEFT JOIN tenants t ON t.room_id=r.id AND t.status='AKTIF' WHERE r.owner_id=? ORDER BY r.id""", (oid,)))

@app.get("/api/tenants")
@login_required()
def tenants():
    if session.get("is_master"):
        return jsonify(q("""SELECT t.*, r.room_number, o.kos_name FROM tenants t JOIN rooms r ON r.id=t.room_id LEFT JOIN owners o ON o.id=t.owner_id ORDER BY (t.status='AKTIF') DESC, t.id DESC"""))
    
    oid = session["owner_id"]
    return jsonify(q("""SELECT t.*, r.room_number FROM tenants t JOIN rooms r ON r.id=t.room_id WHERE t.owner_id=? ORDER BY (t.status='AKTIF') DESC, t.id DESC""", (oid,)))

@app.post("/api/checkin")
@login_required()
def checkin():
    d = request.json or {}
    email = str(d.get("email", "")).strip()

    if not email or "@" not in email or "." not in email:
        return jsonify(ok=False, warning=False, message="Email wajib diisi dengan format yang valid (contoh: penyewa@email.com)."), 400

    try:
        rid = int(d["room_id"])
        name = str(d.get("name", "")).strip()
        price = to_int(d.get("price"))
        start = f"{d['start_date']} {(d.get('start_time') or '00:00')}"
        end = f"{d['end_date']} {(d.get('end_time') or '00:00')}"
        
        if not name:
            return jsonify(ok=False, warning=False, message="Nama penghuni wajib diisi."), 400
        if start >= end:
            return jsonify(ok=False, warning=False, message="Tanggal sewa tidak valid. Waktu selesai sewa harus setelah waktu mulai."), 400
    except Exception:
        return jsonify(ok=False, warning=False, message="Format data tanggal atau harga sewa tidak valid."), 400

    room = room_ok(rid)
    if not room:
        return jsonify(ok=False, warning=False, message="Data unit kamar tidak ditemukan."), 404
        
    oid = room["owner_id"]

    if q1("SELECT 1 FROM tenants WHERE room_id=? AND status='AKTIF'", (rid,)):
        return jsonify(ok=False, warning=False, message=f"Kamar {room['room_number']} saat ini masih terisi oleh penyewa aktif. Lakukan Check-Out terlebih dahulu."), 400

    cfg = lock_cfg(rid, oid)

    tid = ex("INSERT INTO tenants(owner_id,name,phone,email,room_id,start_datetime,end_datetime,price,notes) VALUES(?,?,?,?,?,?,?,?,?)",
             (oid, name, d.get("phone", ""), email, rid, start, end, price, d.get("notes", "")))
    ex("UPDATE rooms SET status='TERISI' WHERE id=?", (rid,))
    ex("INSERT INTO payments(owner_id,tenant_id,room_id,start_date,end_date,amount) VALUES(?,?,?,?,?,?)",
       (oid, tid, rid, start[:10], end[:10], price))

    audit("Check-in", cfg["room_number"] if cfg else f"ID {rid}", "OK", f"Penyewa {name} ({email}) terdaftar.")

    sn = room_serial(rid)
    
    if not sn:
        ex("UPDATE tenants SET ezviz_sync_status='BELUM TERSINKRON', ezviz_message='Serial Number belum diset' WHERE id=?", (tid,))
        return jsonify(ok=True, warning=True, message=f"Check-in untuk {name} di Kamar {room['room_number']} BERHASIL disimpan di database.\n\nPeringatan:\nSerial Number perangkat Smartlock belum diatur di menu Setting Smartlock. Kode akses pintu belum dikirim.")

    if not live():
        ex("UPDATE tenants SET ezviz_sync_status='BELUM TERSINKRON', ezviz_message='Live Mode OFF' WHERE id=?", (tid,))
        return jsonify(ok=True, warning=True, message=f"Check-in untuk {name} di Kamar {room['room_number']} BERHASIL disimpan di database.\n\nPeringatan:\nSistem saat ini dalam Mode Simulasi (Live Mode OFF). Data tidak dikirim ke perangkat fisik EZVIZ.")

    r, pid, note = push_tenant_password(name, email, start, end, sn)

    if r["ok"]:
        ex("UPDATE tenants SET ezviz_sync_status='TEMP PASSWORD TERSINKRON', ezviz_message=?, ezviz_password_id=? WHERE id=?",
           ("Terkirim ke email" + note, pid, tid))
        audit("Sync Smartlock", room["room_number"], "OK", f"Password temporer {name} terkirim{note}")
        return jsonify(ok=True, warning=False, message=f"Check-in SUKSES!\n\nData penyewa berhasil disimpan dan kode akses Smartlock otomatis dikirim ke email: {email}{note}")
    else:
        ex("UPDATE tenants SET ezviz_sync_status='ERROR', ezviz_message=? WHERE id=?", (err_text(r)[:300], tid))
        audit("Sync Smartlock GAGAL", room["room_number"], "GAGAL", err_text(r))
        return jsonify(ok=True, warning=True, message=f"Check-in berhasil disimpan di database lokal.\n\nPeringatan Sinkronisasi (Kode {r['code']}):\nJenis: {r['parsed']['type']}\nPenjelasan: {r['parsed']['detail']}\n\nSetelah masalah diperbaiki, tekan tombol Sync pada menu Penghuni.")

@app.post("/api/tenants/<int:tid>/checkout")
@login_required()
def checkout(tid):
    t = tenant_ok(tid)
    if not t or t["status"] != "AKTIF":
        return jsonify(ok=False, message="Data penyewa tidak ditemukan."), 404

    note, warn = "", False
    sn = room_serial(t["room_id"])
    if sn and live():
        pid = str(t["ezviz_password_id"] or "")
        if not pid and t["ezviz_sync_status"] == "TEMP PASSWORD TERSINKRON":
            pid = lock_find_id(sn, pw_name(t["name"]))
        if pid:
            d = lock_delete(sn, pid)
            if d["ok"]:
                note = " Password temporer penyewa di pintu sudah dihapus."
            else:
                warn = True
                note = (f" PERINGATAN: password di pintu belum terhapus ({err_text(d)}). "
                        f"Hapus lewat menu Password Pintu.")

    ex("UPDATE tenants SET status='SELESAI', ezviz_password_id='' WHERE id=?", (tid,))
    ex("UPDATE rooms SET status='KOSONG' WHERE id=?", (t["room_id"],))
    audit("Check-out", t["room_number"], "GAGAL" if warn else "OK", f"Check-out {t['name']}.{note}")
    return jsonify(ok=True, warning=warn, message="Proses Check-out berhasil diselesaikan." + note)

@app.get("/api/payments")
@login_required()
def payments():
    if session.get("is_master"):
        return jsonify(q("""SELECT p.*, t.name tenant, r.room_number, o.kos_name FROM payments p LEFT JOIN tenants t ON t.id=p.tenant_id JOIN rooms r ON r.id=p.room_id LEFT JOIN owners o ON o.id=p.owner_id ORDER BY p.id DESC"""))
    
    oid = session["owner_id"]
    return jsonify(q("""SELECT p.*, t.name tenant, r.room_number FROM payments p LEFT JOIN tenants t ON t.id=p.tenant_id JOIN rooms r ON r.id=p.room_id WHERE p.owner_id=? ORDER BY p.id DESC""", (oid,)))

@app.put("/api/payments/<int:pid>")
@login_required()
def pay_edit(pid):
    d = request.json or {}
    st = "LUNAS" if d.get("status") == "LUNAS" else "BELUM"
    paid_at = now() if st == "LUNAS" else ""
    p = q1("SELECT owner_id FROM payments WHERE id=?", (pid,))
    if not p or not can_owner(p["owner_id"]):
        return jsonify(ok=False, message="Tagihan tidak ditemukan."), 404
    ex("UPDATE payments SET status=?, paid_at=? WHERE id=?", (st, paid_at, pid))
    return jsonify(ok=True)

@app.get("/api/smartlock")
@login_required()
def sl_list():
    filter_oid = request.args.get("owner_id")
    if session.get("is_master"):
        if filter_oid:
            return jsonify(q("SELECT r.id, r.room_number, o.kos_name, s.serial_number, s.verification_code FROM rooms r JOIN smartlock_settings s ON s.room_id=r.id LEFT JOIN owners o ON o.id=r.owner_id WHERE r.owner_id=? ORDER BY r.id", (filter_oid,)))
        return jsonify(q("SELECT r.id, r.room_number, o.kos_name, s.serial_number, s.verification_code FROM rooms r JOIN smartlock_settings s ON s.room_id=r.id LEFT JOIN owners o ON o.id=r.owner_id ORDER BY o.id, r.id"))
    
    oid = session["owner_id"]
    return jsonify(q("SELECT r.id, r.room_number, s.serial_number, s.verification_code FROM rooms r JOIN smartlock_settings s ON s.room_id=r.id WHERE r.owner_id=? ORDER BY r.id", (oid,)))

@app.put("/api/smartlock/<int:rid>")
@login_required()
def sl_edit(rid):
    d = request.json or {}
    sn = str(d.get("serial_number", "")).strip().upper()
    vc = str(d.get("verification_code", "")).strip()
    room = room_ok(rid)
    if not room:
        return jsonify(ok=False, message="Kamar tidak ditemukan."), 404
    ex("INSERT INTO smartlock_settings(room_id, owner_id, serial_number, verification_code) VALUES(?,?,?,?) "
       "ON CONFLICT(room_id) DO UPDATE SET serial_number=excluded.serial_number, verification_code=excluded.verification_code",
       (rid, room["owner_id"], sn, vc))
    audit("Setting Smartlock", room["room_number"], "OK", f"SN {sn}")
    return jsonify(ok=True)

@app.post("/api/admin/commissioning")
@login_required()
def run_commissioning():
    results = []

    def add(test, status, detail):
        results.append({"test": test, "status": status, "detail": scrub(detail)})

    try:
        row_c = q1("SELECT COUNT(*) c FROM rooms")["c"]
        add("1. Database Query", "OK", f"Database OK. Total Unit Terdaftar: {row_c}")
    except Exception as e:
        add("1. Database Query", "FAIL", str(e))

    key, sec = env("EZVIZ_APP_KEY"), env("EZVIZ_APP_SECRET")
    if key and sec:
        add("2. Konfigurasi EZVIZ API", "OK", f"AppKey: {mask(key)}")
    else:
        add("2. Konfigurasi EZVIZ API", "WARN", "AppKey/Secret belum diset di .env")

    add("3. Live Mode", "OK" if live() else "WARN",
        "Aktif: perintah dikirim ke perangkat EZVIZ." if live() else "OFF (EZVIZ_LIVE_ENABLED bukan true): aplikasi hanya simulasi.")

    host = urlparse(base()).hostname
    dns_ok = True
    try:
        ips = sorted({a[4][0] for a in socket.getaddrinfo(host, 443)})
        add(f"4. DNS {host}", "OK", "Terselesaikan ke " + ", ".join(ips[:3]))
    except OSError as e:
        dns_ok = False
        add(f"4. DNS {host}", "FAIL", f"Host tidak bisa di-resolve ({e}). Ini masalah DNS/jaringan komputer, bukan kode. "
                                      f"Coba DNS 8.8.8.8, cek VPN/firewall/ISP.")

    tok, err = get_token(force=True)
    if tok:
        add("5. Perolehan Token EZVIZ", "OK", f"Token API EZVIZ Aktif & Valid. areaDomain: {_tok.get('area') or '-'}")
    else:
        add("5. Perolehan Token EZVIZ", "FAIL", f"Error Token: {err.get('msg')}")

    if is_master():
        rows = q("SELECT r.room_number, s.serial_number FROM rooms r JOIN smartlock_settings s ON s.room_id=r.id WHERE s.serial_number<>'' ORDER BY r.id LIMIT 10")
    else:
        rows = q("SELECT r.room_number, s.serial_number FROM rooms r JOIN smartlock_settings s ON s.room_id=r.id WHERE s.serial_number<>'' AND r.owner_id=? ORDER BY r.id LIMIT 10", (session["owner_id"],))
    if not rows:
        add("6. Perangkat Smartlock", "WARN", "Belum ada Serial Number terdaftar.")
    for row in rows:
        label = f"6. Kamar {row['room_number']} ({row['serial_number']})"
        if not (tok and dns_ok):
            add(label, "WARN", "Dilewati (token/DNS belum siap).")
            continue
        try:
            resp, _u = ezviz_http("POST", P_DEVICE_INFO, data={"accessToken": tok, "deviceSerial": row["serial_number"]})
            j = resp.json()
            code = str(j.get("code"))
            if code == "200":
                online = str((j.get("data") or {}).get("status")) == "1"
                add(label, "OK" if online else "WARN", "Online." if online else "Terdaftar tetapi OFFLINE.")
            else:
                add(label, "FAIL", f"[{code}] {parse_ezviz_code(code, j.get('msg'))['detail']}")
        except Exception as e:
            add(label, "FAIL", net_hint(e, base()))

    return jsonify(ok=all(x["status"] != "FAIL" for x in results), timestamp=now(), results=results)

@app.get("/api/audit")
@login_required()
def audit_list():
    """Log aktivitas = audit aplikasi (200 terbaru) + riwayat buka pintu (200 terbaru), digabung terbaru di atas."""
    cols_a = "id, owner_id, timestamp, user, action, room, result, message, 'audit' AS source"
    cols_d = ("d.id, d.owner_id, datetime(d.open_time/1000 + {off}, 'unixepoch') AS timestamp, "
              "COALESCE(NULLIF(u.remark,''), d.user_name) AS user, 'Buka Pintu' AS action, r.room_number AS room, "
              "'OK' AS result, ('Metode: ' || d.open_label) AS message, 'pintu' AS source").format(off=door_offset_sec())
    join_d = ("FROM door_open_logs d JOIN rooms r ON r.id=d.room_id "
              "LEFT JOIN lock_user_names u ON u.room_id=d.room_id AND u.user_name=d.user_name ")
    if session.get("is_master"):
        rows = q(f"SELECT * FROM (SELECT * FROM (SELECT {cols_a} FROM audit_logs ORDER BY id DESC LIMIT 200) "
                 f"UNION ALL SELECT * FROM (SELECT {cols_d} {join_d} ORDER BY d.open_time DESC LIMIT 200)) "
                 f"ORDER BY timestamp DESC, id DESC")
    else:
        oid = session["owner_id"]
        rows = q(f"SELECT * FROM (SELECT * FROM (SELECT {cols_a} FROM audit_logs WHERE owner_id=? ORDER BY id DESC LIMIT 200) "
                 f"UNION ALL SELECT * FROM (SELECT {cols_d} {join_d} WHERE d.owner_id=? ORDER BY d.open_time DESC LIMIT 200)) "
                 f"ORDER BY timestamp DESC, id DESC", (oid, oid))
    return jsonify(rows)

# ------------------------------------------------------------------ RIWAYAT BUKA PINTU (Query Door Lock Open Records)
_open_range_idx = {}  # indeks variasi rentang tanggal yang terbukti diterima server
_open_sync_ts = {}   # room_id -> waktu sinkron terakhir (cegah panggilan API berulang)

def door_shift_hours():
    """Koreksi jam riwayat pintu (jam), diatur lewat EZVIZ_TIME_SHIFT_HOURS di .env. Bawaan 0."""
    try:
        return float(env("EZVIZ_TIME_SHIFT_HOURS", "0") or 0)
    except ValueError:
        return 0.0

def door_offset_sec():
    """Detik yang ditambahkan pada openTime EZVIZ untuk mendapat jam tampil.
    Mode bawaan 'local': openTime dari EZVIZ sudah berupa jam lokal perangkat (WITA) yang dikodekan seperti UTC,
    jadi tidak ditambah selisih zona lagi (hanya koreksi manual EZVIZ_TIME_SHIFT_HOURS bila perlu).
    Mode 'utc' (EZVIZ_OPENTIME_MODE=utc): openTime adalah epoch UTC asli -> ditambah selisih zona APP_TIMEZONE."""
    off = 0
    if env("EZVIZ_OPENTIME_MODE", "local").lower() == "utc":
        off = (tz().utcoffset(datetime.now(tz())) or timedelta(0)).total_seconds()
    return int(off + door_shift_hours() * 3600)

def door_wall(ot_ms):
    """openTime (ms) -> teks jam tampil 'YYYY-MM-DD HH:MM:SS'."""
    return (datetime.fromtimestamp(ot_ms / 1000, timezone.utc) + timedelta(seconds=door_offset_sec())).strftime("%Y-%m-%d %H:%M:%S")

def open_type_label(t):
    s = str(t or "").strip().lower()
    for key, label in (("temp", "Password Sementara"), ("pass", "Password"), ("pwd", "Password"),
                       ("finger", "Sidik Jari"), ("card", "Kartu"), ("face", "Wajah"),
                       ("vein", "Telapak Tangan"), ("key", "Kunci Mekanik"),
                       ("remote", "Remote (Aplikasi)"), ("blue", "Bluetooth"), ("app", "Remote (Aplikasi)")):
        if key in s:
            return label
    return str(t or "-")

def open_attempts(rid):
    """Variasi rentang tanggal. Server EZVIZ kadang menolak 'end' (10001) karena beda zona waktu, dan rentang
    tanggal bisa memotong kejadian terbaru; maka semua variasi yang diterima dijalankan dan hasilnya digabung."""
    today = datetime.now(tz()).date()
    utc_today = datetime.now(timezone.utc).date()
    start_d = today - timedelta(days=59)          # API hanya menyimpan 60 hari terakhir
    last = q1("SELECT MAX(open_time) m FROM door_open_logs WHERE room_id=?", (rid,))
    if last and last["m"]:
        start_d = max(start_d, datetime.fromtimestamp(last["m"] / 1000, tz()).date() - timedelta(days=2))
    return [("lokal", start_d, today), ("utc", min(start_d, utc_today), utc_today), ("default", None, None)]

_open_bad = set()   # nama variasi rentang yang pernah ditolak server (10001)

def sync_lock_user_names(rid, sn):
    """Nama catatan (remark) pengguna kunci, supaya sama dengan yang tampil di aplikasi HP EZVIZ."""
    r = v3("GET", P_KEYLOCK_USERS, params={"deviceSerial": sn})
    if not r["ok"] or not isinstance(r.get("data"), list):
        return
    for u in r["data"]:
        nm = str(u.get("lockUserName") or "").strip()
        if nm:
            db().execute("INSERT INTO lock_user_names(room_id,user_name,remark) VALUES(?,?,?) "
                         "ON CONFLICT(room_id,user_name) DO UPDATE SET remark=excluded.remark",
                         (rid, nm, str(u.get("lockRemarkName") or "").strip()))
    db().commit()

def sync_open_logs(rid, full=False):
    """Ambil riwayat buka pintu dari EZVIZ (GET /api/v3/keylock/open/list) dan simpan ke door_open_logs."""
    room = q1("SELECT * FROM rooms WHERE id=?", (rid,))
    res = {"ok": False, "new": 0, "message": ""}
    if not room:
        return {**res, "message": "Kamar tidak ditemukan."}
    label = f"Kamar {room['room_number']}"
    sn = room_serial(rid)
    if not live():
        return {**res, "message": f"{label}: Live Mode OFF (.env)."}
    if not sn:
        return {**res, "message": f"{label}: Serial Number belum diisi."}

    sync_lock_user_names(rid, sn)
    new, any_ok, last_err = 0, False, None
    for name, sd, ed in open_attempts(rid):
        if name in _open_bad:
            continue
        page = 0
        while page < 20:                           # maks 20 halaman x 50 = 1000 catatan per variasi
            prm = {"deviceSerial": sn, "pageStart": page, "pageSize": 50}
            if sd and ed:
                prm.update(start=sd.isoformat(), end=ed.isoformat())
            r = v3("GET", P_KEYLOCK_OPEN, params=prm)
            if not r["ok"]:
                if page == 0 and str(r.get("code")) == "10001":
                    _open_bad.add(name)            # variasi ini ditolak server, lewati
                    last_err = r
                    break
                return {**res, "new": new, "message": f"{label}: gagal membaca riwayat buka pintu. {err_text(r)}", "code": r.get("code")}
            any_ok = True
            items = r.get("data") if isinstance(r.get("data"), list) else []
            for it in items:
                ot = to_int(it.get("openTime"))
                if not ot:
                    continue
                otype = str(it.get("openType") or "")
                cur = db().execute(
                    "INSERT OR IGNORE INTO door_open_logs(owner_id,room_id,open_time,timestamp,user_name,open_type,open_label) VALUES(?,?,?,?,?,?,?)",
                    (room["owner_id"], rid, ot, door_wall(ot),
                     str(it.get("lockUserName") or "").strip(), otype, open_type_label(otype)))
                new += cur.rowcount
            db().commit()
            if len(items) < 50:
                break
            page += 1
    if not any_ok:
        return {**res, "message": f"{label}: semua variasi rentang tanggal ditolak server. {err_text(last_err) if last_err else ''}", "code": (last_err or {}).get("code")}
    _open_sync_ts[rid] = time.time()
    return {"ok": True, "new": new, "message": f"{label}: {new} riwayat buka pintu baru."}

def _open_logs_raw(rid):
    room = room_ok(rid)
    if not room:
        return jsonify(ok=False, message="Kamar tidak ditemukan. Gunakan ID kamar (angka internal), bukan nomor kamar; "
                                         "atau pakai /api/locks/nomor/<nomor kamar>/open-logs/raw"), 404
    sn = room_serial(rid)
    if not sn or not live():
        return jsonify(ok=False, message="Serial Number kosong atau Live Mode OFF.")
    fmt = lambda ot, z: datetime.fromtimestamp(ot / 1000, z).strftime("%Y-%m-%d %H:%M:%S")
    out = []
    for name, sd, ed in open_attempts(rid):
        items, r, page = [], None, 0
        while page < 20:
            prm = {"deviceSerial": sn, "pageStart": page, "pageSize": 50}
            if sd and ed:
                prm.update(start=sd.isoformat(), end=ed.isoformat())
            r = v3("GET", P_KEYLOCK_OPEN, params=prm)
            if not r["ok"]:
                break
            got = r.get("data") if isinstance(r.get("data"), list) else []
            items += got
            if len(got) < 50:
                break
            page += 1
        rows = sorted([{"lockUserName": it.get("lockUserName"), "openType": it.get("openType"), "openTime_raw": it.get("openTime"),
                        "ot": to_int(it.get("openTime"))} for it in items if to_int(it.get("openTime"))], key=lambda x: -x["ot"])
        for x in rows:
            x["utc"], x["app_tz"] = fmt(x["ot"], timezone.utc), door_wall(x["ot"])
        out.append({"variasi": name, "params": {"start": sd.isoformat() if sd else None, "end": ed.isoformat() if ed else None},
                    "ok": r["ok"] if r else False, "code": (r or {}).get("code"), "pesan": (r or {}).get("msg"),
                    "jumlah": len(rows), "terlama_utc": rows[-1]["utc"] if rows else None, "terbaru_utc": rows[0]["utc"] if rows else None,
                    "data": rows[:10]})
    db_row = q1("SELECT COUNT(*) c, MAX(open_time) m FROM door_open_logs WHERE room_id=?", (rid,))
    return jsonify(ok=True, server_utc_now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                   app_tz_now=datetime.now(tz()).strftime("%Y-%m-%d %H:%M:%S"), koreksi_jam=door_shift_hours(),
                   tersimpan_di_db=db_row["c"], terbaru_di_db_utc=fmt(db_row["m"], timezone.utc) if db_row["m"] else None, hasil=out)

@app.get("/api/locks/<int:rid>/open-logs/raw")
@login_required()
def open_logs_raw(rid):
    """Diagnosis: seluruh data mentah EZVIZ per variasi rentang (10 terbaru ditampilkan) + konversi waktu UTC & zona aplikasi."""
    return _open_logs_raw(rid)

@app.get("/api/locks/nomor/<room_number>/open-logs/raw")
@login_required()
def open_logs_raw_by_number(room_number):
    """Sama seperti di atas, tetapi memakai nomor kamar (mis. 101). Akun Master: kamar pertama yang cocok."""
    if is_master():
        row = q1("SELECT id FROM rooms WHERE room_number=? ORDER BY id", (room_number,))
    else:
        row = q1("SELECT id FROM rooms WHERE room_number=? AND owner_id=?", (room_number, session["owner_id"]))
    return _open_logs_raw(row["id"]) if row else (jsonify(ok=False, message="Kamar tidak ditemukan."), 404)

@app.post("/api/locks/open-logs/sync")
@login_required()
def open_logs_sync():
    force = bool((request.get_json(silent=True) or {}).get("force"))
    if is_master():
        rows = q("SELECT r.id FROM rooms r JOIN smartlock_settings s ON s.room_id=r.id WHERE s.serial_number<>'' ORDER BY r.id")
    else:
        rows = q("SELECT r.id FROM rooms r JOIN smartlock_settings s ON s.room_id=r.id WHERE s.serial_number<>'' AND r.owner_id=? ORDER BY r.id", (session["owner_id"],))
    if not rows:
        return jsonify(ok=False, new=0, failed=0, message="Belum ada kamar dengan Serial Number smartlock.")
    if not live():
        return jsonify(ok=False, new=0, failed=0, message="Live Mode OFF (.env). Aktifkan EZVIZ_LIVE_ENABLED=true untuk membaca riwayat pintu.")
    tot_new, failed, lines, skipped = 0, 0, [], 0
    for row in rows:
        if not force and time.time() - _open_sync_ts.get(row["id"], 0) < 30:
            skipped += 1
            continue
        res = sync_open_logs(row["id"])
        tot_new += res["new"]
        if not res["ok"]:
            failed += 1
            lines.append(res["message"])
            if str(res.get("code")) in ("NET", "-"):
                break  # jaringan/token bermasalah: hentikan agar tidak menunggu timeout berulang
    msg = f"Selesai: {tot_new} riwayat buka pintu baru, {failed} kamar gagal."
    if skipped:
        msg += f" ({skipped} kamar dilewati: baru disinkronkan <30 detik lalu)"
    if lines:
        msg += "\n" + "\n".join(lines[:5])
    if force:
        audit("Sync Riwayat Pintu", "", "OK" if not failed else "GAGAL", msg)
    return jsonify(ok=failed == 0, new=tot_new, failed=failed, message=msg)

@app.get("/api/door-logs")
@login_required()
def door_logs():
    """Riwayat masuk pintu: waktu, user, kamar, status, detail, metode buka."""
    oid = request.args.get("owner_id")
    sql = (f"SELECT d.id, d.room_id, datetime(d.open_time/1000 + {door_offset_sec()}, 'unixepoch') AS timestamp, d.user_name, u.remark, d.open_type, d.open_label, r.room_number, o.kos_name "
           "FROM door_open_logs d JOIN rooms r ON r.id=d.room_id LEFT JOIN owners o ON o.id=d.owner_id "
           "LEFT JOIN lock_user_names u ON u.room_id=d.room_id AND u.user_name=d.user_name ")
    if is_master():
        rows = q(sql + ("WHERE d.owner_id=? " if oid else "") + "ORDER BY d.open_time DESC LIMIT 500", (oid,) if oid else ())
    else:
        rows = q(sql + "WHERE d.owner_id=? ORDER BY d.open_time DESC LIMIT 500", (session["owner_id"],))
    out = [{"id": r["id"], "timestamp": r["timestamp"] or "", "user": (r.get("remark") or r["user_name"] or "-"),
            "room": r["room_number"], "kos_name": r.get("kos_name") or "", "status": "BERHASIL", "method": r["open_label"]}
           for r in rows]
    return jsonify(out)

# ------------------------------------------------------------------ PASSWORD SEMENTARA DI PINTU (DAFTAR & BERSIHKAN)
@app.get("/api/locks/<int:rid>/passwords")
@login_required()
def lock_passwords(rid):
    if not room_ok(rid):
        return jsonify(ok=False, message="Kamar tidak ditemukan."), 404
    if not live():
        return jsonify(ok=False, message="Live Mode OFF (.env). Aktifkan EZVIZ_LIVE_ENABLED=true untuk membaca isi pintu.")
    sn = room_serial(rid)
    if not sn:
        return jsonify(ok=False, message="Serial Number kamar ini belum diisi.")
    r, items = lock_list(sn)
    if not r["ok"]:
        return jsonify(ok=False, message=err_text(r))
    return jsonify(ok=True, serial_number=sn, items=classify_passwords(rid, items))

@app.delete("/api/locks/<int:rid>/passwords/<int:pid>")
@login_required()
def lock_password_delete(rid, pid):
    room = room_ok(rid)
    if not room:
        return jsonify(ok=False, message="Kamar tidak ditemukan."), 404
    if not live():
        return jsonify(ok=False, message="Live Mode OFF (.env).")
    sn = room_serial(rid)
    if not sn:
        return jsonify(ok=False, message="Serial Number kamar ini belum diisi.")
    deleted, failed = delete_lock_ids(rid, sn, [pid])
    if failed:
        return jsonify(ok=False, message=failed[0]["error"])
    audit("Hapus Password Pintu", room["room_number"], "OK", f"passwordID {pid}")
    return jsonify(ok=True, message=f"Password ID {pid} dihapus dari pintu.")

@app.post("/api/locks/<int:rid>/cleanup")
@login_required()
def lock_cleanup(rid):
    if not room_ok(rid):
        return jsonify(ok=False, message="Kamar tidak ditemukan."), 404
    mode = "all" if (request.get_json(silent=True) or {}).get("mode") == "all" else "auto"
    return jsonify(cleanup_room(rid, mode))

@app.post("/api/locks/cleanup-all")
@login_required()
def lock_cleanup_all():
    if is_master():
        rows = q("SELECT r.id FROM rooms r JOIN smartlock_settings s ON s.room_id=r.id WHERE s.serial_number<>'' ORDER BY r.id")
    else:
        rows = q("SELECT r.id FROM rooms r JOIN smartlock_settings s ON s.room_id=r.id WHERE s.serial_number<>'' AND r.owner_id=? ORDER BY r.id", (session["owner_id"],))
    if not rows:
        return jsonify(ok=False, message="Belum ada kamar dengan Serial Number smartlock.")
    lines, tot_del, tot_fail = [], 0, 0
    for row in rows:
        res = cleanup_room(row["id"], "auto")
        tot_del += res["deleted"]
        tot_fail += res["failed"]
        lines.append(res["message"])
        if not res["ok"] and res["deleted"] == 0 and "gagal membaca" in res["message"] and "NET" in res["message"]:
            break  # jaringan putus: hentikan agar tidak menunggu timeout berulang
    return jsonify(ok=tot_fail == 0, deleted=tot_del, failed=tot_fail,
                   message=f"Selesai: {tot_del} password dihapus, {tot_fail} gagal.\n" + "\n".join(lines))

if __name__ == "__main__":
    app.run(host=env("HOST", "0.0.0.0"), port=int(env("PORT", "5000")), debug=False)