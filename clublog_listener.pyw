"""
Club Log Universal Listener
---------------------------
Riceve i QSO via UDP da DXLog, QARTest, WSJT-X, JTDX e MSHV e li carica in
tempo reale su Club Log tramite https://clublog.org/realtime.php.

Formati UDP supportati (riconosciuti automaticamente su ogni porta):
  * Protocollo binario WSJT-X (QDataStream, magic 0xADBCCBDA):
      - tipo 5  "QSO Logged"
      - tipo 12 "Logged ADIF"
    usato da WSJT-X, JTDX e MSHV.
  * XML N1MM <contactinfo>/<contactreplace>/<contactdelete>
    usato da QARTest e da DXLog (opzione "Use N1MM QSO format").
  * Testo ADIF semplice (es. "secondary UDP server" di WSJT-X/JTDX).
"""

import base64
import datetime as dt
import ipaddress
import json
import os
import queue
import re
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

try:  # icona nella tray bar (pip install pystray pillow)
    import pystray
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    pystray = None

APP_NAME = "Club Log Universal Listener"
APP_VERSION = "1.0"
REALTIME_URL = "https://clublog.org/realtime.php"

BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0] if getattr(sys, "frozen", False) else __file__))
CONFIG_FILE = os.path.join(BASE_DIR, "clublog_listener.json")
QUEUE_FILE = os.path.join(BASE_DIR, "clublog_listener_coda.json")
BACKUP_ADIF = os.path.join(BASE_DIR, "qso_ricevuti.adi")
REJECTED_ADIF = os.path.join(BASE_DIR, "qso_rifiutati.adi")
# File ADIF importati: restano qui finché Club Log non li accetta, poi vengono spostati
JOBS_DIR = os.path.join(BASE_DIR, "caricamenti_in_attesa")
JOBS_DONE_DIR = os.path.join(BASE_DIR, "caricamenti_inviati")
# Ultimo momento in cui ogni programma era in ascolto: al riavvio si cercano nel suo log i QSO
# registrati nel frattempo
STATE_FILE = os.path.join(BASE_DIR, "clublog_listener_stato.json")

# Programmi e porte di default. JTDX e MSHV usano di default la 2237 come
# WSJT-X: qui si propongono porte diverse per farli convivere.
DEFAULT_LISTENERS = [
    {"name": "DXLog", "enabled": True, "ip": "0.0.0.0", "port": 12061, "mcast": ""},
    {"name": "QARTest", "enabled": True, "ip": "0.0.0.0", "port": 12060, "mcast": ""},
    {"name": "WSJT-X", "enabled": True, "ip": "0.0.0.0", "port": 2237, "mcast": ""},
    {"name": "JTDX", "enabled": True, "ip": "0.0.0.0", "port": 2238, "mcast": ""},
    {"name": "MSHV", "enabled": True, "ip": "0.0.0.0", "port": 2239, "mcast": ""},
]

DEDUP_WINDOW_S = 30 * 60
HOLD_QSO_LOGGED_S = 3  # attesa del Logged ADIF dopo un QSO Logged di WSJT-X/JTDX
ALIVE_EVERY_S = 60     # ogni quanto si salva l'ultimo momento in ascolto (copre spegnimenti e crash)
GAP_MARGIN_S = 300     # margine prima dell'ultimo momento in ascolto: i doppioni vengono scartati
PUTLOGS_URL = "https://clublog.org/putlogs.php"
# Club Log non pubblica limiti numerici: chiede un ritmo "normale" per realtime.php,
# putlogs.php per gli arretrati e nessun invio a blocchi ripetuto e ravvicinato.
DEFAULT_INTERVAL_S = 5        # pausa minima tra due QSO inviati con realtime.php
DEFAULT_BATCH_THRESHOLD = 20  # da quanti QSO in coda si passa all'invio a blocchi (0 = mai)
BATCH_MIN_INTERVAL_S = 300    # pausa minima tra due invii a blocchi
BATCH_MAX_QSO = 5000
# Errori temporanei del server per cui realtime.php viene ritentato più tardi;
# per ogni altro codice diverso da 200 gli invii si fermano
RETRYABLE_HTTP = (500, 502, 503, 504)


# --------------------------------------------------------------------------
# Cifratura credenziali (DPAPI di Windows, legata all'utente corrente)
# --------------------------------------------------------------------------

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32
    _proto = [ctypes.POINTER(_DATA_BLOB), ctypes.c_void_p, ctypes.POINTER(_DATA_BLOB),
              ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DATA_BLOB)]
    _crypt32.CryptProtectData.argtypes = _proto
    _crypt32.CryptUnprotectData.argtypes = _proto
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]

    def _dpapi(data, protect):
        buf = ctypes.create_string_buffer(data, len(data))
        blob_in = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
        blob_out = _DATA_BLOB()
        fn = _crypt32.CryptProtectData if protect else _crypt32.CryptUnprotectData
        if not fn(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
            raise ctypes.WinError()
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            _kernel32.LocalFree(ctypes.cast(blob_out.pbData, ctypes.c_void_p))


def protect_secret(text):
    if not text:
        return ""
    if os.name == "nt":
        return "dpapi:" + base64.b64encode(_dpapi(text.encode("utf-8"), True)).decode("ascii")
    return "plain:" + text


def unprotect_secret(value):
    if not value:
        return ""
    try:
        if value.startswith("dpapi:") and os.name == "nt":
            return _dpapi(base64.b64decode(value[6:]), False).decode("utf-8")
        if value.startswith("plain:"):
            return value[6:]
    except Exception:
        pass
    return ""


# --------------------------------------------------------------------------
# API key integrata (facoltativa)
# --------------------------------------------------------------------------
# Il codice pubblico non contiene nessuna chiave. Chi vuole una versione con la
# chiave integrata esegue imposta_chiave_api.py, che crea chiave_api.py (escluso
# da git) e poi crea_exe.bat. L'offuscamento evita solo la lettura a colpo
# d'occhio: non è una protezione crittografica, perciò l'eseguibile va
# distribuito solo all'interno del gruppo.

_KEY_SALT = b"ClubLogUniversalListener"


def obfuscate_key(key):
    data = bytes(b ^ _KEY_SALT[i % len(_KEY_SALT)] ^ (i * 7 & 0xFF) for i, b in enumerate(key.encode("utf-8")))
    return base64.b64encode(data).decode("ascii")[::-1]


def reveal_key(value):
    data = base64.b64decode(value[::-1])
    return bytes(b ^ _KEY_SALT[i % len(_KEY_SALT)] ^ (i * 7 & 0xFF) for i, b in enumerate(data)).decode("utf-8")


def load_builtin_api_key():
    try:
        import chiave_api
        return reveal_key(chiave_api.CHIAVE).strip()
    except Exception:
        return ""


BUILTIN_API_KEY = load_builtin_api_key()


# --------------------------------------------------------------------------
# ADIF
# --------------------------------------------------------------------------

BANDS = [
    (0.1357, 0.1378, "2190m"), (0.472, 0.479, "630m"), (1.8, 2.0, "160m"),
    (3.5, 4.0, "80m"), (5.06, 5.45, "60m"), (7.0, 7.3, "40m"), (10.1, 10.15, "30m"),
    (14.0, 14.35, "20m"), (18.068, 18.168, "17m"), (21.0, 21.45, "15m"),
    (24.89, 24.99, "12m"), (28.0, 29.7, "10m"), (40.0, 45.0, "8m"), (50.0, 54.0, "6m"),
    (54.000001, 69.9, "5m"), (70.0, 71.0, "4m"), (144.0, 148.0, "2m"),
    (222.0, 225.0, "1.25m"), (420.0, 450.0, "70cm"), (902.0, 928.0, "33cm"),
    (1240.0, 1300.0, "23cm"), (2300.0, 2450.0, "13cm"), (3300.0, 3500.0, "9cm"),
    (5650.0, 5925.0, "6cm"), (10000.0, 10500.0, "3cm"), (24000.0, 24250.0, "1.25cm"),
    (47000.0, 47200.0, "6mm"), (75500.0, 81000.0, "4mm"),
]

# Valori del campo <band> N1MM (MHz) e QARTest (metri)
N1MM_BAND_MHZ = {"1.8": "160m", "3.5": "80m", "5": "60m", "7": "40m", "10": "30m",
                 "14": "20m", "18": "17m", "21": "15m", "24": "12m", "28": "10m",
                 "50": "6m", "70": "4m", "144": "2m", "222": "1.25m", "420": "70cm",
                 "432": "70cm", "902": "33cm", "1240": "23cm", "1296": "23cm"}
METER_BANDS = {"160", "80", "60", "40", "30", "20", "17", "15", "12", "10", "6", "4", "2"}

# Modi che in ADIF 3 sono submode di MFSK / SSB
MFSK_SUBMODES = {"FT4", "JS8", "Q65"}
SSB_SUBMODES = {"USB", "LSB"}

UPLOAD_FIELDS = ["call", "qso_date", "time_on", "qso_date_off", "time_off", "band", "band_rx",
                 "freq", "freq_rx", "mode", "submode", "rst_sent", "rst_rcvd",
                 "station_callsign", "operator", "gridsquare", "my_gridsquare",
                 "prop_mode", "sat_name"]


def freq_to_band(mhz):
    for lo, hi, band in BANDS:
        if lo <= mhz <= hi:
            return band
    return ""


_ADIF_TAG = re.compile(r"<([A-Za-z0-9_]+)(?::(\d+)(?::[A-Za-z])?)?>")


_ADIF_TAG_B = re.compile(rb"<([A-Za-z0-9_]+)(?::(\d+)(?::[A-Za-z])?)?>")


def _decode_value(raw):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def parse_adif(text):
    """Restituisce la lista dei record (dict con chiavi minuscole).
    Accetta str oppure bytes: per i file conviene bytes, perché in ADIF
    le lunghezze dei campi sono in byte."""
    is_bytes = isinstance(text, bytes)
    tag_re = _ADIF_TAG_B if is_bytes else _ADIF_TAG
    records, current = [], {}
    pos = 0
    # Salta l'header se presente
    m = re.search(rb"<eoh>" if is_bytes else r"<eoh>", text, re.IGNORECASE)
    if m:
        pos = m.end()
    while True:
        m = tag_re.search(text, pos)
        if not m:
            break
        name = m.group(1).lower()
        if is_bytes:
            name = name.decode("ascii")
        if name == "eor":
            if current:
                records.append(current)
            current = {}
            pos = m.end()
            continue
        if m.group(2) is None:
            pos = m.end()
            continue
        length = int(m.group(2))
        value = text[m.end():m.end() + length]
        current[name] = _decode_value(value) if is_bytes else value
        pos = m.end() + length
    return records


def analyze_adif_import(records, callsign, include_freq, include_missing=False,
                        date_from="", date_to=""):
    """Filtra i record di un log pregresso: tiene solo quelli con STATION_CALLSIGN
    uguale al nominativo della spedizione (ed eventualmente nell'intervallo di date)."""
    callsign = callsign.strip().upper()
    res = {"total": len(records), "selected": [], "others": {}, "missing": 0,
           "invalid": 0, "out_of_range": 0, "first": "", "last": ""}
    for raw in records:
        station = raw.get("station_callsign", "").strip().upper()
        if not station:
            res["missing"] += 1
            if not include_missing:
                continue
        elif station != callsign:
            res["others"][station] = res["others"].get(station, 0) + 1
            continue
        rec, err = normalize_record(raw, include_freq)
        if err:
            res["invalid"] += 1
            continue
        if (date_from and rec["qso_date"] < date_from) or (date_to and rec["qso_date"] > date_to):
            res["out_of_range"] += 1
            continue
        rec["station_callsign"] = callsign
        res["selected"].append(rec)
        stamp = rec["qso_date"] + rec["time_on"]
        if not res["first"] or stamp < res["first"]:
            res["first"] = stamp
        if not res["last"] or stamp > res["last"]:
            res["last"] = stamp
    return res


def create_import_job(records, source_path):
    """Salva i QSO filtrati in caricamenti_in_attesa: il thread di invio li manda a Club Log."""
    os.makedirs(JOBS_DIR, exist_ok=True)
    base = re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.splitext(os.path.basename(source_path))[0])[:40]
    path = os.path.join(JOBS_DIR, "%s_%s.adi" % (time.strftime("%Y%m%d-%H%M%S"), base))
    text = "Log importato da %s\n<ADIF_VER:5>3.1.4<PROGRAMID:%d>%s<EOH>\n%s\n" % (
        os.path.basename(source_path), len(APP_NAME), APP_NAME,
        "\n".join(build_adif(r) for r in records))
    tmp = path + ".tmp"  # estensione diversa: il thread di invio non lo vede finché non è completo
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    return path


def format_stamp(stamp):
    return "%s-%s-%s %s:%sZ" % (stamp[0:4], stamp[4:6], stamp[6:8], stamp[8:10], stamp[10:12])


def build_adif(record):
    parts = []
    for key in UPLOAD_FIELDS:
        value = record.get(key, "")
        if value:
            parts.append("<%s:%d>%s" % (key.upper(), len(value), value))
    return "".join(parts) + "<EOR>"


def use_end_time(r):
    """Usa la fine del QSO come data/ora del QSO, se c'è TIME_OFF.

    Senza QSO_DATE_OFF, una fine prima dell'inizio vuol dire che il QSO è passato
    a cavallo della mezzanotte UTC: la data di fine è il giorno dopo l'inizio."""
    t_off = r.get("time_off", "")
    if len(t_off) < 4:
        return
    date_off = r.get("qso_date_off", "")
    if len(date_off) != 8:
        date_on, t_on = r.get("qso_date", ""), r.get("time_on", "")
        try:
            day = dt.datetime.strptime(date_on, "%Y%m%d")
        except ValueError:
            return
        if len(t_on) >= 4 and t_off.ljust(6, "0") < t_on.ljust(6, "0"):
            day += dt.timedelta(days=1)
        date_off = day.strftime("%Y%m%d")
    r["qso_date"] = r["qso_date_off"] = date_off
    r["time_on"] = t_off


def normalize_record(rec, include_freq):
    """Pulisce un record per Club Log. Restituisce (record, errore)."""
    r = {k.lower(): str(v).strip() for k, v in rec.items() if v is not None and str(v).strip()}
    r["call"] = r.get("call", "").upper()
    for key in ("station_callsign", "operator", "gridsquare", "my_gridsquare"):
        if key in r:
            r[key] = r[key].upper()

    for key in ("qso_date", "qso_date_off"):
        if key in r:
            r[key] = re.sub(r"\D", "", r[key])
    for key in ("time_on", "time_off"):
        if key in r:
            r[key] = re.sub(r"\D", "", r[key])[:6]
    use_end_time(r)

    freq = None
    if r.get("freq"):
        try:
            freq = float(r["freq"])
        except ValueError:
            freq = None
    if not r.get("band") and freq:
        r["band"] = freq_to_band(freq)
    if r.get("band"):
        r["band"] = r["band"].lower()
    if r.get("freq_rx") and not r.get("band_rx"):
        try:
            r["band_rx"] = freq_to_band(float(r["freq_rx"]))
        except ValueError:
            pass

    mode = r.get("mode", "").upper()
    if mode in MFSK_SUBMODES:
        r["mode"], r["submode"] = "MFSK", mode
    elif mode in SSB_SUBMODES:
        r["mode"], r["submode"] = "SSB", mode
    elif mode:
        r["mode"] = mode

    if not include_freq:
        r.pop("freq", None)
        r.pop("freq_rx", None)

    missing = [k for k in ("call", "qso_date", "time_on", "band", "mode") if not r.get(k)]
    if missing:
        return None, "campi mancanti: " + ", ".join(missing)
    if len(r["qso_date"]) != 8 or len(r["time_on"]) < 4:
        return None, "data/ora non valida (%s %s)" % (r["qso_date"], r["time_on"])
    return r, None


def describe(rec):
    mode = rec.get("submode") or rec.get("mode", "")
    t = rec.get("time_on", "")
    return "%s  %s %s  %s-%s-%s %s:%sZ" % (
        rec.get("call", "?"), rec.get("band", "?"), mode,
        rec.get("qso_date", "")[0:4], rec.get("qso_date", "")[4:6], rec.get("qso_date", "")[6:8],
        t[0:2], t[2:4])


# --------------------------------------------------------------------------
# Protocollo WSJT-X (WSJT-X, JTDX, MSHV)
# --------------------------------------------------------------------------

WSJTX_MAGIC = 0xADBCCBDA
WSJTX_TYPES = {0: "Heartbeat", 1: "Status", 2: "Decode", 3: "Clear", 4: "Reply",
               5: "QSO Logged", 6: "Close", 7: "Replay", 8: "Halt Tx", 9: "Free Text",
               10: "WSPR Decode", 11: "Location", 12: "Logged ADIF",
               13: "Highlight Callsign", 14: "Switch Configuration", 15: "Configure"}


class _Reader:
    def __init__(self, data, pos=0):
        self.data, self.pos = data, pos

    def _take(self, fmt):
        size = struct.calcsize(fmt)
        if self.pos + size > len(self.data):
            raise ValueError("pacchetto troncato")
        val = struct.unpack_from(fmt, self.data, self.pos)
        self.pos += size
        return val[0]

    def u8(self): return self._take(">B")
    def u32(self): return self._take(">I")
    def i32(self): return self._take(">i")
    def u64(self): return self._take(">Q")
    def i64(self): return self._take(">q")

    def utf8(self):
        n = self.u32()
        if n == 0xFFFFFFFF:
            return ""
        if self.pos + n > len(self.data):
            raise ValueError("pacchetto troncato")
        s = self.data[self.pos:self.pos + n].decode("utf-8", "replace")
        self.pos += n
        return s

    def qstring(self):
        # QString: quint32 byte length + UTF-16BE
        n = self.u32()
        if n == 0xFFFFFFFF:
            return ""
        s = self.data[self.pos:self.pos + n].decode("utf-16-be", "replace")
        self.pos += n
        return s

    def qdatetime(self, stored_utc=False, local_is_utc=False):
        # stored_utc: schema 1 (Qt 5.0) scrive sempre l'ora UTC, qualunque sia il timespec.
        # local_is_utc: JTDX (finestra Log QSO) e MSHV prima della 2.68 marcano come ora locale
        # le cifre dell'ora UTC
        jd = self.i64()
        ms = self.u32()
        spec = self.u8()
        offset = 0
        if spec == 2:
            offset = self.i32()
        elif spec == 3:
            self.qstring()  # id del fuso orario
        if jd <= 0 or ms == 0xFFFFFFFF:
            return None
        base = dt.datetime.fromordinal(jd - 1721425) + dt.timedelta(milliseconds=ms)
        if stored_utc:
            return base
        if spec == 0 and not local_is_utc:
            base = base.astimezone(dt.timezone.utc).replace(tzinfo=None)
        elif spec == 2:
            base -= dt.timedelta(seconds=offset)
        return base


def parse_wsjtx(data):
    """Restituisce (nome_messaggio, id_client, record_list)."""
    r = _Reader(data)
    if r.u32() != WSJTX_MAGIC:
        raise ValueError("magic errato")
    schema = r.u32()
    mtype = r.u32()
    client_id = r.utf8()
    name = WSJTX_TYPES.get(mtype, "tipo %d" % mtype)
    records = []
    if mtype == 12:
        records = parse_adif(r.utf8())
    elif mtype == 5:
        utc_digits = client_id.upper().startswith(("JTDX", "MSHV"))
        off = r.qdatetime(schema == 1, utc_digits)
        rec = {"call": r.utf8(), "gridsquare": r.utf8()}
        hz = r.u64()
        rec["mode"] = r.utf8()
        rec["rst_sent"] = r.utf8()
        rec["rst_rcvd"] = r.utf8()
        r.utf8()  # tx power
        r.utf8()  # comments
        r.utf8()  # name
        on = r.qdatetime(schema == 1, utc_digits)
        try:
            rec["operator"] = r.utf8()
            rec["station_callsign"] = r.utf8()
            rec["my_gridsquare"] = r.utf8()
        except ValueError:
            pass  # versioni vecchie senza questi campi
        start = on or off
        if start:
            rec["qso_date"] = start.strftime("%Y%m%d")
            rec["time_on"] = start.strftime("%H%M%S")
        if off:
            rec["qso_date_off"] = off.strftime("%Y%m%d")
            rec["time_off"] = off.strftime("%H%M%S")
        if hz:
            rec["freq"] = "%.6f" % (hz / 1e6)
        records = [rec]
    return name, client_id, records


# --------------------------------------------------------------------------
# XML N1MM (QARTest, DXLog)
# --------------------------------------------------------------------------

def parse_n1mm_xml(text):
    """Restituisce (nome_messaggio, programma, record_list)."""
    root = ET.fromstring(text)
    tag = root.tag.lower()

    def get(name):
        for child in root:
            if child.tag.lower() == name:
                return (child.text or "").strip()
        return ""

    program = get("app") or get("logger") or "?"
    if tag not in ("contactinfo", "contactreplace"):
        return tag, program, []

    rec = {"call": get("call"), "mode": get("mode"), "rst_sent": get("snt"),
           "rst_rcvd": get("rcv"), "station_callsign": get("mycall"),
           "operator": get("operator"), "gridsquare": get("gridsquare")}

    ts = get("timestamp")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            t = dt.datetime.strptime(ts, fmt)
            rec["qso_date"] = t.strftime("%Y%m%d")
            rec["time_on"] = t.strftime("%H%M%S")
            break
        except ValueError:
            continue

    # Frequenze N1MM in unità di 10 Hz
    for src, dst in (("txfreq", "freq"), ("rxfreq", "freq_rx")):
        val = get(src)
        if val:
            try:
                mhz = float(val) / 100000.0
                if mhz > 0:
                    rec[dst] = "%.6f" % mhz
            except ValueError:
                pass
    if "freq" not in rec and "freq_rx" in rec:
        rec["freq"] = rec.pop("freq_rx")

    band = get("band")
    if band and "freq" not in rec:
        if "qartest" in program.lower() and band in METER_BANDS:
            rec["band"] = band + "m"
        elif band in N1MM_BAND_MHZ:
            rec["band"] = N1MM_BAND_MHZ[band]
        elif band.lower().endswith(("m", "cm", "mm")):
            rec["band"] = band.lower()
    return tag, program, [rec]


def parse_packet(data):
    """Riconosce il formato. Restituisce (protocollo, messaggio, info, record_list)."""
    if len(data) >= 4 and struct.unpack_from(">I", data)[0] == WSJTX_MAGIC:
        msg, client_id, recs = parse_wsjtx(data)
        return "WSJT-X", msg, client_id, recs
    text = data.decode("utf-8", "replace").replace("\x00", "").strip()
    if text.startswith("<?xml") or re.match(r"<contact\w+>", text, re.IGNORECASE) or text.lower().startswith("<"):
        if re.search(r"<eor>", text, re.IGNORECASE):
            return "ADIF", "record ADIF", "", parse_adif(text)
        msg, program, recs = parse_n1mm_xml(text)
        return "N1MM-XML", msg, program, recs
    if re.search(r"<eor>", text, re.IGNORECASE):
        return "ADIF", "record ADIF", "", parse_adif(text)
    raise ValueError("formato sconosciuto")


# --------------------------------------------------------------------------
# Log dei programmi: QSO registrati mentre il listener non ascoltava
# --------------------------------------------------------------------------

# WSJT-X e JTDX scrivono sempre wsjtx_log.adi nella loro cartella dati (non configurabile);
# con --rig-name=XXX la cartella è "<programma> - XXX". MSHV usa <cartella di MSHV>\log\mshvlog.edim.
LOG_PROGRAMS = ("WSJT-X", "JTDX", "MSHV")

# Codici dei modi nel log di MSHV (HvLogW::SaveEDI)
MSHV_MODES = {"0": "NON", "1": "SSB", "2": "CW", "6": "FM", "10": "JTMS", "11": "FSK441",
              "12": "ISCAT-A", "13": "ISCAT-B", "14": "JT6M", "15": "FSK315", "17": "MSK144",
              "18": "JT65A", "19": "JT65B", "20": "JT65C", "21": "PI4", "22": "FT8", "23": "MSKMS",
              "24": "FT4", "25": "Q65A", "26": "Q65B", "27": "Q65C", "28": "Q65D", "29": "FT2"}


def mshv_dirs():
    """Cartelle di installazione di MSHV, dalle voci di disinstallazione di Windows."""
    dirs = []
    try:
        import winreg
    except ImportError:
        return dirs
    for root, path in ((winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                       (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                       (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")):
        try:
            key = winreg.OpenKey(root, path)
        except OSError:
            continue
        with key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    with winreg.OpenKey(key, winreg.EnumKey(key, i)) as sub:
                        if not str(winreg.QueryValueEx(sub, "DisplayName")[0]).upper().startswith("MSHV"):
                            continue
                        uninstall = str(winreg.QueryValueEx(sub, "UninstallString")[0]).strip().strip('"')
                except OSError:
                    continue
                folder = os.path.dirname(uninstall)
                if folder and folder.lower() not in [d.lower() for d in dirs]:
                    dirs.append(folder)
    return dirs


def find_program_logs(program):
    """File di log del programma su questo PC: lista di (percorso, tipo) con tipo "adif" o "mshv"."""
    found = []
    if program in ("WSJT-X", "JTDX"):
        base = os.environ.get("LOCALAPPDATA", "")
        try:
            names = sorted(os.listdir(base))
        except OSError:
            names = []
        for name in names:
            if name.lower() == program.lower() or name.lower().startswith(program.lower() + " - "):
                path = os.path.join(base, name, "wsjtx_log.adi")
                if os.path.isfile(path):
                    found.append((path, "adif"))
    elif program == "MSHV":
        # Con "Use Save QSOs In ADIF Log" (attiva di default) MSHV aggiunge ogni QSO a mshvlog.adi con il
        # nominativo usato in quel momento: è la fonte migliore. Altrimenti si legge mshvlog.edim.
        for folder in mshv_dirs():
            adif = os.path.join(folder, "log", "mshvlog.adi")
            edim = os.path.join(folder, "log", "mshvlog.edim")
            if mshv_adif_enabled(folder) and os.path.isfile(adif):
                found.append((adif, "adif"))
            elif os.path.isfile(edim):
                found.append((edim, "mshv"))
    return found


def mshv_adif_enabled(folder):
    """Stato di "Use Save QSOs In ADIF Log" in settings\\ms_settings (se manca: attiva, come in MSHV)."""
    try:
        with open(os.path.join(folder, "settings", "ms_settings"), encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("def_use_adif_save="):
                    return line.split("=", 1)[1].strip() != "0"
    except OSError:
        pass
    return True


def _mshv_freq(digits, mhz):
    """Il log di MSHV salva la frequenza senza punto decimale: lo rimette dove la frequenza cade
    nella banda indicata (es. 70154 con banda 70 MHz -> 70.154)."""
    digits = digits.lstrip("0")
    if not digits.isdigit():
        return ""
    candidates = ["0." + digits] + [digits[:k] + "." + digits[k:] for k in range(1, len(digits) + 1)]
    for c in candidates:
        v = float(c)
        if abs(v - mhz) <= mhz * 0.15 and freq_to_band(v):
            return "%.6f" % v
    return ""


def mshv_callsign(log_path):
    """Nominativo impostato in MSHV (settings\\ms_macros, salvato appena si conferma la modifica)."""
    try:
        with open(os.path.join(os.path.dirname(os.path.dirname(log_path)), "settings", "ms_macros"),
                  encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("macr_my_call="):
                    return line.split("=", 1)[1].strip().upper()
    except OSError:
        pass
    return ""


def read_mshv_log(path):
    """Record ADIF dal log di MSHV (mshvlog.edim), con gli stessi campi dell'ADIF di MSHV.
    Il log non ha il nominativo di ogni QSO: si usa quello impostato in MSHV, come fa MSHV."""
    mycall = mshv_callsign(path)
    records, in_qsos = [], False
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if line.upper().startswith("[END;"):
                in_qsos = False
            if in_qsos and line:
                p = line.split(";") + [""] * 29
                sec_on = p[18] or "00"
                sec_off = p[20] or sec_on
                rec = {"call": p[4], "qso_date": p[0], "time_on": p[1] + sec_on, "qso_date_off": p[2],
                       "time_off": p[3] + sec_off, "rst_sent": p[6], "rst_rcvd": p[7], "gridsquare": p[8]}
                mode = MSHV_MODES.get(p[5], p[5])
                if mode in ("FT2", "FT4") or mode.startswith("Q65"):
                    rec["mode"], rec["submode"] = "MFSK", mode
                elif mode.startswith("ISCAT"):
                    rec["mode"], rec["submode"] = "ISCAT", mode
                elif mode.startswith("JT65"):
                    rec["mode"], rec["submode"] = "JT65", mode
                else:
                    rec["mode"] = mode
                m = re.match(r"([\d.]+)\s*([kMG])", p[9], re.IGNORECASE)
                if m:
                    mhz = float(m.group(1)) * {"K": 0.001, "M": 1.0, "G": 1000.0}[m.group(2).upper()]
                    freq = _mshv_freq(p[10], mhz)
                    if freq:
                        rec["freq"] = freq
                        rec["band"] = freq_to_band(float(freq))
                    else:
                        near = [b for lo, hi, b in BANDS if lo * 0.9 <= mhz <= hi * 1.1]
                        rec["band"] = near[0] if near else ""
                if p[12]:
                    rec["prop_mode"] = p[12]
                if p[22]:
                    rec["sat_name"] = p[22]
                if mycall:
                    rec["station_callsign"] = mycall
                records.append(rec)
            if line.upper().startswith("[QSORECORDS;"):
                in_qsos = True
    return records


def read_program_log(path, kind):
    if kind == "mshv":
        return read_mshv_log(path)
    with open(path, "rb") as f:
        return parse_adif(f.read())


def qso_timestamp(rec):
    """Momento della registrazione del QSO (fine QSO, o inizio se manca), in secondi UTC."""
    date, t = rec.get("qso_date_off", ""), rec.get("time_off", "")
    if len(date) != 8 or len(t) < 4:
        date, t = rec.get("qso_date", ""), rec.get("time_on", "")
    try:
        return dt.datetime.strptime(date + t[:6].ljust(6, "0"), "%Y%m%d%H%M%S").replace(
            tzinfo=dt.timezone.utc).timestamp()
    except ValueError:
        return None


def qso_key(rec):
    """Chiave dei doppioni: stesso nominativo, data, ora (al minuto), banda e modo."""
    return "|".join((rec["call"], rec["qso_date"], rec["time_on"][:4], rec["band"],
                     rec.get("submode") or rec["mode"]))


def load_state():
    """(ultimo momento in ascolto per programma, nominativo di MSHV in quel momento per log)."""
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}, {}
    try:
        times = {k: float(v) for k, v in data.get("ultimo_ascolto", {}).items()}
    except (AttributeError, TypeError, ValueError):
        times = {}
    try:
        calls = {k: str(v) for k, v in data.get("nominativo_mshv", {}).items()}
    except (AttributeError, TypeError):
        calls = {}
    return times, calls


def save_state(times, calls):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"ultimo_ascolto": times, "nominativo_mshv": calls}, f, indent=2)
    os.replace(tmp, STATE_FILE)


# --------------------------------------------------------------------------
# Thread di ascolto UDP
# --------------------------------------------------------------------------

class Listener(threading.Thread):
    def __init__(self, idx, cfg, on_qso, emit, on_alive=None):
        super().__init__(daemon=True)
        self.idx, self.cfg, self.on_qso, self.emit = idx, cfg, on_qso, emit
        self.on_alive = on_alive or (lambda name: None)
        self.stop_event = threading.Event()
        self.sock = None
        # QSO Logged in attesa del Logged ADIF dello stesso QSO: (scadenza, chiave, rec, proto, ip)
        self.held = []

    def status(self, text, level="info"):
        self.emit(("lstatus", self.idx, text, level))

    def log(self, level, text):
        self.emit(("log", level, "[%s] %s" % (self.cfg["name"], text)))

    def run(self):
        ip, port, mcast = self.cfg["ip"], self.cfg["port"], self.cfg["mcast"]
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            if mcast:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((ip, port))
            if mcast:
                mreq = socket.inet_aton(mcast) + socket.inet_aton(ip)
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            self.sock.settimeout(0.5)
        except OSError as e:
            self.status("ERRORE: %s" % e.strerror if e.strerror else str(e), "err")
            self.log("err", "impossibile ascoltare su %s:%d%s - %s" % (
                ip, port, " (multicast %s)" % mcast if mcast else "", e))
            return
        where = "%s:%d" % (ip, port) + (" + multicast %s" % mcast if mcast else "")
        self.status("In ascolto su %s - nessun pacchetto" % where, "ok")
        self.log("info", "in ascolto su %s" % where)
        self.on_alive(self.cfg["name"])
        alive_at = time.time()

        while not self.stop_event.is_set():
            self._release_held()
            if time.time() - alive_at >= ALIVE_EVERY_S:
                self.on_alive(self.cfg["name"])
                alive_at = time.time()
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                if self.stop_event.is_set():
                    break
                continue
            stamp = time.strftime("%H:%M:%S")
            try:
                proto, msg, info, recs = parse_packet(data)
            except Exception as e:
                self.status("%s  pacchetto non riconosciuto da %s" % (stamp, addr[0]), "warn")
                self.log("warn", "pacchetto non riconosciuto da %s:%d (%d byte): %s" % (
                    addr[0], addr[1], len(data), e))
                continue
            label = "%s %s" % (proto, msg) + (" (%s)" % info if info else "")
            self.status("%s  ultimo: %s da %s" % (stamp, label, addr[0]), "ok")
            if proto == "N1MM-XML" and msg == "contactdelete":
                self.log("warn", "cancellazione QSO ricevuta: va eliminato a mano su Club Log")
            for rec in recs:
                key = (addr[0], info, (rec.get("call") or "").upper())
                if proto == "WSJT-X" and msg == "QSO Logged":
                    # WSJT-X/JTDX mandano subito dopo lo stesso QSO in ADIF, che ha l'orario UTC
                    # esplicito: se arriva si usa quello (JTDX può dare un orario sbagliato qui)
                    self.held.append((time.time() + HOLD_QSO_LOGGED_S, key, rec, "%s %s" % (proto, msg),
                                      addr[0]))
                    continue
                if proto == "WSJT-X" and msg == "Logged ADIF":
                    self.held = [h for h in self.held if h[1] != key]
                self.on_qso(rec, self.cfg["name"], "%s %s" % (proto, msg), addr[0])

        self._release_held(force=True)
        self.on_alive(self.cfg["name"])
        try:
            self.sock.close()
        except OSError:
            pass
        self.status("Fermo", "info")

    def _release_held(self, force=False):
        now = time.time()
        due = [h for h in self.held if force or h[0] <= now]
        self.held = [h for h in self.held if not (force or h[0] <= now)]
        for _, _, rec, proto, ip in due:
            self.on_qso(rec, self.cfg["name"], proto, ip)

    def stop(self):
        self.stop_event.set()


# --------------------------------------------------------------------------
# Thread di invio a Club Log
# --------------------------------------------------------------------------

class Uploader(threading.Thread):
    def __init__(self, emit, stats):
        super().__init__(daemon=True)
        self.emit, self.stats = emit, stats
        self.lock = threading.Lock()
        self.items = self._load()
        self.wake = threading.Event()
        self.stop_event = threading.Event()
        self.paused = False
        self.creds = {}
        self.dry_run = True
        self.interval = DEFAULT_INTERVAL_S
        self.batch_threshold = DEFAULT_BATCH_THRESHOLD
        self.next_try = 0.0
        self.last_batch = 0.0
        self.batch_wait_logged = False
        self.job_state = {"attempts": 0}

    def log(self, level, text):
        self.emit(("log", level, text))

    def _load(self):
        try:
            with open(QUEUE_FILE, "r", encoding="utf-8") as f:
                items = json.load(f)
            if not isinstance(items, list):
                raise ValueError("contenuto non valido")
            return items
        except FileNotFoundError:
            return []
        except (OSError, ValueError) as e:
            # Non sovrascrivere mai una coda illeggibile: la si mette da parte
            bad = QUEUE_FILE + time.strftime(".illeggibile-%Y%m%d-%H%M%S")
            try:
                os.replace(QUEUE_FILE, bad)
            except OSError:
                pass
            self.log("err", "coda illeggibile (%s), salvata come %s. I QSO sono comunque in %s." % (
                e, os.path.basename(bad), os.path.basename(BACKUP_ADIF)))
            return []

    def _save(self):
        # Scrittura atomica e forzata su disco: la coda sopravvive a crash e mancanza di corrente
        tmp = QUEUE_FILE + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.items, f, indent=1)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, QUEUE_FILE)
        except OSError as e:
            self.log("err", "impossibile salvare la coda: %s" % e)

    def pending(self):
        with self.lock:
            return len(self.items)

    def configure(self, settings, dry_run):
        self.creds = {k: settings.get(k, "") for k in ("email", "password", "callsign", "api")}
        self.dry_run = dry_run
        self.interval = max(1.0, float(settings.get("interval", DEFAULT_INTERVAL_S)))
        self.batch_threshold = int(settings.get("batch", DEFAULT_BATCH_THRESHOLD))

    def add(self, adif, desc, source):
        with self.lock:
            self.items.append({"adif": adif, "desc": desc, "source": source, "attempts": 0})
            self._save()
        self.wake.set()

    def resume(self):
        self.paused = False
        self.next_try = 0.0
        self.wake.set()

    def stop(self):
        self.stop_event.set()
        self.wake.set()

    def _drop_first(self):
        with self.lock:
            if self.items:
                self.items.pop(0)
            self._save()

    def _http(self, url, body, content_type, timeout):
        req = urllib.request.Request(url, data=body, method="POST", headers={
            "Content-Type": content_type,
            "User-Agent": "%s/%s" % (APP_NAME.replace(" ", ""), APP_VERSION)})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode("utf-8", "replace").strip()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace").strip()

    def _post(self, adif):
        """Un solo QSO con realtime.php."""
        body = urllib.parse.urlencode(dict(self.creds, adif=adif)).encode("ascii")
        return self._http(REALTIME_URL, body, "application/x-www-form-urlencoded", 20)

    def _post_batch(self, adif_file, filename="coda.adi"):
        """Un file ADIF con molti QSO con putlogs.php (clear=0: unisce, non cancella il log)."""
        boundary = "----ClubLogListener%d" % int(time.time() * 1000)
        parts = []
        for key, value in dict(self.creds, clear="0").items():
            parts.append('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n'
                         % (boundary, key, value))
        parts.append('--%s\r\nContent-Disposition: form-data; name="file"; filename="%s"\r\n'
                     'Content-Type: application/octet-stream\r\n\r\n' % (boundary, filename))
        body = ("".join(parts) + adif_file + "\r\n--%s--\r\n" % boundary).encode("utf-8")
        return self._http(PUTLOGS_URL, body, "multipart/form-data; boundary=" + boundary, 120)

    def _retry_later(self, item, reason):
        item["attempts"] = item.get("attempts", 0) + 1
        delay = min(300, 5 * 2 ** min(item["attempts"], 6))
        with self.lock:
            self._save()
        self.log("warn", "%s - nuovo tentativo tra %d s (%d QSO in coda, salvati su disco)" % (
            reason, delay, self.pending()))
        self.next_try = time.time() + delay

    def _pause(self, reason):
        # Club Log chiede di fermarsi dopo un 403 o un errore inatteso, altrimenti blocca l'IP
        self.paused = True
        self.stats["errors"] += 1
        self.log("err", "%s. Invio in pausa: verifica e premi 'Riprova coda'. "
                 "I QSO restano in coda su disco." % reason)

    @staticmethod
    def pending_jobs():
        try:
            return sorted(f for f in os.listdir(JOBS_DIR) if f.lower().endswith(".adi"))
        except OSError:
            return []

    def run(self):
        while not self.stop_event.is_set():
            with self.lock:
                pending = len(self.items)
                item = self.items[0] if pending else None
            jobs = self.pending_jobs()
            now = time.time()
            # In modalità TEST la coda e i file importati restano intatti
            idle = (item is None and not jobs) or self.paused or self.dry_run
            if idle or now < self.next_try:
                self.wake.wait(1.0 if idle else min(1.0, max(0.1, self.next_try - now)))
                self.wake.clear()
                continue
            batch_due = item is not None and 0 < self.batch_threshold <= pending
            if jobs or batch_due:
                wait = self.last_batch + BATCH_MIN_INTERVAL_S - now
                if wait > 0:
                    if item is not None and not batch_due:
                        self._send_one(item)  # il tempo reale continua mentre il file aspetta
                        continue
                    if not self.batch_wait_logged:
                        self.log("info", "Prossimo invio a blocchi tra %d s "
                                 "(Club Log non vuole invii a blocchi ravvicinati)." % wait)
                        self.batch_wait_logged = True
                    self.next_try = now + wait
                    continue
                if jobs:
                    self._send_job(os.path.join(JOBS_DIR, jobs[0]))
                else:
                    self._send_batch(item)
            else:
                self._send_one(item)

    def _send_job(self, path):
        name = os.path.basename(path)
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            self._pause("impossibile leggere il file da caricare %s: %s" % (name, e))
            return
        count = data.upper().count(b"<EOR>")
        self.log("info", "Invio del log importato %s (%d QSO) con putlogs.php..." % (name, count))
        try:
            code, text = self._post_batch(data.decode("utf-8", "replace"), name)
        except Exception as e:  # rete assente, timeout, SSL... il thread non deve mai morire
            self._retry_later(self.job_state, "rete non disponibile (%s) per il file %s" % (
                getattr(e, "reason", e), name))
            return
        self.last_batch = time.time()
        self.batch_wait_logged = False
        short = text.replace("\r", " ").replace("\n", " ")[:160]
        if code == 200:
            self.job_state["attempts"] = 0
            try:
                os.makedirs(JOBS_DONE_DIR, exist_ok=True)
                os.replace(path, os.path.join(JOBS_DONE_DIR, name))
            except OSError as e:
                # Se il file restasse in attesa verrebbe reinviato: meglio fermarsi
                self._pause("file %s accettato ma impossibile spostarlo (%s)" % (name, e))
            self.stats["sent"] += count
            self.log("ok", "Club Log ha accettato il log importato %s (%d QSO), unito al log "
                     "esistente: lo elabora entro circa un minuto [%s]" % (name, count, short))
            self.next_try = time.time() + self.interval
        else:
            self._pause("Club Log ha rifiutato il log importato %s (HTTP %d: %s)" % (name, code, short))

    def _send_batch(self, first):
        with self.lock:
            batch = list(self.items[:BATCH_MAX_QSO])
        adif_file = "Coda di %s\n<ADIF_VER:5>3.1.4<PROGRAMID:%d>%s<EOH>\n%s\n" % (
            APP_NAME, len(APP_NAME), APP_NAME, "\n".join(i["adif"] for i in batch))
        self.log("info", "Invio a blocchi di %d QSO in coda (putlogs.php)..." % len(batch))
        try:
            code, text = self._post_batch(adif_file)
        except Exception as e:  # rete assente, timeout, SSL... il thread non deve mai morire
            self._retry_later(first, "rete non disponibile (%s)" % getattr(e, "reason", e))
            return
        self.last_batch = time.time()
        self.batch_wait_logged = False
        short = text.replace("\r", " ").replace("\n", " ")[:160]
        if code == 200:
            with self.lock:
                del self.items[:len(batch)]
                self._save()
            self.stats["sent"] += len(batch)
            self.log("ok", "Club Log ha accettato il blocco di %d QSO: li elabora entro circa un minuto "
                     "[%s]" % (len(batch), short))
            self.next_try = time.time() + self.interval
        else:
            self._pause("Club Log ha rifiutato l'invio a blocchi (HTTP %d: %s)" % (code, short))

    def _send_one(self, item):
        try:
            code, text = self._post(item["adif"])
        except Exception as e:  # rete assente, timeout, SSL... il thread non deve mai morire
            self._retry_later(item, "rete non disponibile (%s): %s" % (getattr(e, "reason", e), item["desc"]))
            return
        short = text.replace("\r", " ").replace("\n", " ")[:160]
        if code == 200:  # QSO OK / QSO Duplicate / QSO Modified
            self.stats["sent"] += 1
            if re.search(r"dup", text, re.IGNORECASE):
                self.log("ok", "Club Log: già presente (duplicato) - %s" % item["desc"])
            elif re.search(r"modif|updated", text, re.IGNORECASE):
                self.log("warn", "Club Log ha accettato ma modificato %s: %s" % (item["desc"], short))
            else:
                self.log("ok", "Club Log OK: %s  [%s]" % (item["desc"], short))
            self._drop_first()
            self.next_try = time.time() + self.interval
        elif code == 403 or text.startswith("Login rejected"):
            self._pause("Club Log ha rifiutato le credenziali (HTTP %d: %s)" % (code, short))
        elif code == 400:
            self.stats["errors"] += 1
            self.log("err", "Club Log ha rifiutato il QSO %s (HTTP 400: %s) - salvato in %s" % (
                item["desc"], short, os.path.basename(REJECTED_ADIF)))
            try:
                with open(REJECTED_ADIF, "a", encoding="utf-8") as f:
                    f.write(item["adif"] + "\n")
            except OSError:
                pass
            self._drop_first()
            self.next_try = time.time() + self.interval
        elif code in RETRYABLE_HTTP:  # 500 (manutenzione) e simili: Club Log dice di riprovare più tardi
            self._retry_later(item, "Club Log ha risposto HTTP %d (%s)" % (code, short))
        else:  # qualsiasi altro codice: Club Log chiede di fermarsi
            self._pause("Club Log ha risposto HTTP %d (%s)" % (code, short))


# --------------------------------------------------------------------------
# Logica comune (indipendente dalla GUI)
# --------------------------------------------------------------------------

class Engine:
    def __init__(self, emit):
        self.emit = emit
        self.stats = {"received": 0, "sent": 0, "dupes": 0, "errors": 0}
        self.uploader = Uploader(emit, self.stats)
        self.uploader.start()
        self.listeners = []
        self.lock = threading.Lock()
        self.seen = {}
        self.callsign = ""
        self.include_freq = True
        self.dry_run = True
        self.state, self.mshv_calls = load_state()
        self.state_lock = threading.Lock()

    def start(self, settings, listener_cfgs):
        self.callsign = settings["callsign"].upper()
        self.include_freq = settings["include_freq"]
        self.dry_run = settings["dry_run"]
        self.uploader.configure(settings, settings["dry_run"])
        self.uploader.resume()
        # Periodo da controllare nei log: dall'ultimo momento in ascolto a adesso
        now = time.time()
        with self.state_lock:
            gaps = [(cfg["name"], self.state.get(cfg["name"])) for _, cfg in listener_cfgs
                    if cfg["name"] in LOG_PROGRAMS]
            calls_before = dict(self.mshv_calls)  # nominativo di MSHV all'ultimo momento in ascolto
        for idx, cfg in listener_cfgs:
            lst = Listener(idx, cfg, self.handle_qso, self.emit, self.alive)
            lst.start()
            self.listeners.append(lst)
        if gaps:
            threading.Thread(target=self.scan_logs, args=(gaps, now, calls_before), daemon=True).start()

    def alive(self, program):
        calls = {}
        if program == "MSHV":
            for folder in mshv_dirs():
                path = os.path.join(folder, "log", "mshvlog.edim")  # chiave: il log che non ha il nominativo
                call = mshv_callsign(path)
                if call:
                    calls[path] = call
        with self.state_lock:
            self.state[program] = time.time()
            self.mshv_calls.update(calls)
            try:
                save_state(self.state, self.mshv_calls)
            except OSError as e:
                self.emit(("log", "warn", "impossibile salvare %s: %s" % (STATE_FILE, e)))

    def scan_logs(self, gaps, until, calls_before=None):
        """Mette in coda i QSO registrati nei log di WSJT-X/JTDX/MSHV mentre il listener non ascoltava."""
        known = None
        for program, last in gaps:
            if last is None:
                self.emit(("log", "info", "[%s] primo avvio: da ora i QSO registrati a listener spento "
                                          "verranno recuperati dal log del programma" % program))
                continue
            since = last - GAP_MARGIN_S
            period = "%s - %s UTC" % (time.strftime("%Y-%m-%d %H:%M", time.gmtime(last)),
                                      time.strftime("%Y-%m-%d %H:%M", time.gmtime(until)))
            files = find_program_logs(program)
            if not files:
                self.emit(("log", "info", "[%s] log del programma non trovato su questo PC: nessun "
                                          "recupero dei QSO registrati a listener spento" % program))
                continue
            if known is None:
                known = self._received_keys()
            for path, kind in files:
                try:
                    records = read_program_log(path, kind)
                except OSError as e:
                    self.emit(("log", "warn", "[%s] impossibile leggere il log %s: %s" % (program, path, e)))
                    continue
                pending = []
                for raw in records:
                    t = qso_timestamp({k.lower(): str(v).strip() for k, v in raw.items()})
                    if t is None or not since <= t <= until:
                        continue
                    rec, err = normalize_record(raw, self.include_freq)
                    if rec and qso_key(rec) in known:
                        continue  # già ricevuto via UDP prima dello spegnimento
                    pending.append((raw, rec))
                found = len(pending)
                # Il log di MSHV non ha il nominativo di ogni QSO: se in MSHV è stato cambiato mentre il
                # listener non ascoltava, non si sa con quale nominativo è stato fatto ciascun QSO
                before = (calls_before or {}).get(path, "")
                now_call = mshv_callsign(path) if kind == "mshv" else ""
                if pending and before and now_call and before != now_call:
                    self.stats["errors"] += 1
                    self.emit(("log", "err", "[%s] nominativo cambiato in MSHV mentre il listener era spento "
                                             "(%s -> %s): %d QSO del periodo %s NON recuperati, perché non si sa "
                                             "con quale nominativo sono stati fatti. Controllali in MSHV, esportali "
                                             "in ADIF e caricali con \"Importa log ADIF...\":"
                               % (program, before, now_call, found, period)))
                    for raw, rec in pending:
                        self.emit(("log", "err", "        %s" % (describe(rec) if rec else raw)))
                    continue
                for raw, rec in pending:
                    self.handle_qso(raw, program, "log a listener spento", path)
                if found:
                    self.emit(("log", "warn", "[%s] %d QSO registrati a listener spento (%s) recuperati dal log %s"
                               % (program, found, period, path)))
                else:
                    self.emit(("log", "info", "[%s] nessun QSO registrato a listener spento (%s) nel log %s"
                               % (program, period, path)))

    def _received_keys(self):
        """Chiavi dei QSO già ricevuti, dalla copia qso_ricevuti.adi."""
        keys = set()
        try:
            with open(BACKUP_ADIF, "rb") as f:
                data = f.read()
        except OSError:
            return keys
        for raw in parse_adif(data):
            rec, err = normalize_record(raw, True)
            if rec:
                keys.add(qso_key(rec))
        return keys

    def stop(self):
        for lst in self.listeners:
            lst.stop()
        for lst in self.listeners:
            lst.join(timeout=2)
        self.listeners = []
        self.uploader.paused = True

    def shutdown(self):
        self.stop()
        self.uploader.stop()
        self.uploader.join(timeout=3)

    def handle_qso(self, raw, program, proto, sender):
        rec, err = normalize_record(raw, self.include_freq)
        if err:
            self.stats["errors"] += 1
            self.emit(("log", "err", "[%s] QSO scartato (%s): %s" % (program, err, raw)))
            return
        station = rec.get("station_callsign", "")
        if station and self.callsign and station != self.callsign:
            self.stats["errors"] += 1
            self.emit(("log", "err", "[%s] QSO scartato: STATION_CALLSIGN %s diverso dal nominativo DX %s - %s"
                       % (program, station, self.callsign, describe(rec))))
            return
        key = qso_key(rec)
        now = time.time()
        with self.lock:
            self.seen = {k: t for k, t in self.seen.items() if now - t < DEDUP_WINDOW_S}
            if key in self.seen:
                self.stats["dupes"] += 1
                return  # es. WSJT-X invia sia "QSO Logged" sia "Logged ADIF"
            self.seen[key] = now
            self.stats["received"] += 1
            adif = build_adif(rec)
            try:
                with open(BACKUP_ADIF, "a", encoding="utf-8") as f:
                    if f.tell() == 0:
                        f.write("QSO ricevuti da %s\n<ADIF_VER:5>3.1.4<EOH>\n" % APP_NAME)
                    f.write(adif + "\n")
            except OSError as e:
                self.emit(("log", "warn", "impossibile scrivere il backup ADIF: %s" % e))

        desc = describe(rec)
        self.emit(("log", "rx", "[%s] QSO ricevuto da %s (%s): %s" % (program, sender, proto, desc)))
        if self.dry_run:
            self.emit(("log", "ok", "[%s] TEST, non inviato a Club Log: %s" % (program, desc)))
            self.emit(("log", "info", "        ADIF: %s" % adif))
            return
        self.uploader.add(adif, desc, program)


# --------------------------------------------------------------------------
# Configurazione
# --------------------------------------------------------------------------

def load_config():
    cfg = {"callsign": "", "email": "", "password": "", "api": "", "include_freq": False,
           "dry_run": False, "autostart": False, "tray": False,
           "interval": DEFAULT_INTERVAL_S, "batch": DEFAULT_BATCH_THRESHOLD,
           "listeners": [dict(d) for d in DEFAULT_LISTENERS]}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            saved = json.load(f)
    except (OSError, ValueError):
        return cfg
    for key in ("callsign", "email", "include_freq", "dry_run", "autostart", "tray", "interval", "batch"):
        if key in saved:
            cfg[key] = saved[key]
    cfg["password"] = unprotect_secret(saved.get("password", ""))
    cfg["api"] = unprotect_secret(saved.get("api", ""))
    by_name = {l.get("name"): l for l in saved.get("listeners", [])}
    for lst in cfg["listeners"]:
        lst.update({k: v for k, v in by_name.get(lst["name"], {}).items() if k in lst})
    return cfg


def save_config(cfg):
    out = dict(cfg)
    out["password"] = protect_secret(cfg["password"])
    out["api"] = protect_secret(cfg["api"])
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)


def local_ipv4_addresses():
    addrs = {"0.0.0.0", "127.0.0.1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addrs.add(info[4][0])
    except OSError:
        pass
    return sorted(addrs, key=lambda a: (a != "0.0.0.0", a != "127.0.0.1", a))


def monitor_work_area(x, y):
    """Area libera (esclusa la barra delle applicazioni) del monitor che contiene il punto x, y."""
    if os.name == "nt":
        try:
            from ctypes import wintypes

            class MONITORINFO(ctypes.Structure):
                _fields_ = [("cbSize", wintypes.DWORD), ("rcMonitor", wintypes.RECT),
                            ("rcWork", wintypes.RECT), ("dwFlags", wintypes.DWORD)]

            user32 = ctypes.windll.user32
            user32.MonitorFromPoint.restype = wintypes.HMONITOR
            user32.MonitorFromPoint.argtypes = [wintypes.POINT, wintypes.DWORD]
            user32.GetMonitorInfoW.argtypes = [wintypes.HMONITOR, ctypes.POINTER(MONITORINFO)]
            info = MONITORINFO()
            info.cbSize = ctypes.sizeof(MONITORINFO)
            mon = user32.MonitorFromPoint(wintypes.POINT(x, y), 2)  # 2 = il monitor più vicino
            if user32.GetMonitorInfoW(mon, ctypes.byref(info)):
                r = info.rcWork
                return r.left, r.top, r.right - r.left, r.bottom - r.top
        except Exception:
            pass
    return None


# Avvio con Windows: voce in HKCU\...\Run, la stessa per la versione Python e per quella C#, così
# all'accensione parte un solo programma (le porte UDP sono le stesse)
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = APP_NAME
STARTUP_ARG = "--avvio-windows"  # avviato da Windows: si apre ridotto a icona


def startup_target():
    return os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__)


def startup_command():
    if getattr(sys, "frozen", False):
        return '"%s" %s' % (startup_target(), STARTUP_ARG)
    # pythonw: nessuna finestra nera del prompt all'avvio
    exe = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    if not os.path.exists(exe):
        exe = sys.executable
    return '"%s" "%s" %s' % (exe, startup_target(), STARTUP_ARG)


def startup_entry():
    """Comando registrato per l'avvio con Windows ("" se non c'è)."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            return str(winreg.QueryValueEx(key, RUN_VALUE)[0])
    except OSError:
        return ""


def startup_is_mine(command):
    return startup_target().lower() in command.lower()


def set_startup(enabled):
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, RUN_VALUE, 0, winreg.REG_SZ, startup_command())
        elif startup_is_mine(startup_entry()):
            winreg.DeleteValue(key, RUN_VALUE)


def icon_path():
    """icona.ico accanto allo script, o dentro l'exe creato da crea_exe.bat."""
    path = os.path.join(getattr(sys, "_MEIPASS", BASE_DIR), "icona.ico")
    return path if os.path.exists(path) else ""


def tray_image(color):
    """Icona tonda con la scritta CL, colorata secondo lo stato."""
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse((2, 2, 61, 61), fill=color, outline="white", width=3)
    try:
        font = ImageFont.truetype("segoeuib.ttf", 26)
    except OSError:
        font = ImageFont.load_default()
    draw.text((32, 33), "CL", fill="white", font=font, anchor="mm")
    return img


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------

def run_gui():
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
    from tkinter.scrolledtext import ScrolledText

    events = queue.Queue()
    engine = Engine(events.put)
    cfg = load_config()

    root = tk.Tk()
    root.title("%s %s" % (APP_NAME, APP_VERSION))
    if icon_path():
        try:
            root.iconbitmap(default=icon_path())  # vale anche per la finestra di importazione
        except tk.TclError:
            pass
    style = ttk.Style(root)
    if "vista" in style.theme_names():
        style.theme_use("vista")

    COLORS = {"info": "#333333", "ok": "#1a7f37", "warn": "#b35900", "err": "#c62828", "rx": "#0b57d0"}

    # --- Contenuto scorrevole: se la finestra è più piccola compaiono le barre di scorrimento ---
    canvas = tk.Canvas(root, highlightthickness=0, borderwidth=0)
    canvas.grid(row=0, column=0, sticky="nsew")
    root.rowconfigure(0, weight=1)
    root.columnconfigure(0, weight=1)
    vbar = ttk.Scrollbar(root, orient="vertical", command=canvas.yview)
    hbar = ttk.Scrollbar(root, orient="horizontal", command=canvas.xview)
    canvas.configure(yscrollcommand=vbar.set, xscrollcommand=hbar.set)
    body = ttk.Frame(canvas)
    body_id = canvas.create_window(0, 0, window=body, anchor="nw")
    body_req = {}

    def fit_body(event=None):
        # Spazio totale, contando anche le barre già visibili: così non compaiono e spariscono a vicenda
        total_w = canvas.winfo_width() + (vbar.winfo_width() if vbar.winfo_ismapped() else 0)
        total_h = canvas.winfo_height() + (hbar.winfo_height() if hbar.winfo_ismapped() else 0)
        req_w, req_h = body.winfo_reqwidth(), body.winfo_reqheight()
        sb = vbar.winfo_reqwidth()
        need_h = req_w > total_w
        need_v = req_h > total_h - (sb if need_h else 0)
        need_h = req_w > total_w - (sb if need_v else 0)
        for bar_, need, place in ((vbar, need_v, dict(row=0, column=1, sticky="ns")),
                                  (hbar, need_h, dict(row=1, column=0, sticky="ew"))):
            if need and not bar_.winfo_ismapped():
                bar_.grid(**place)
            elif not need and bar_.winfo_ismapped():
                bar_.grid_remove()
        w = max(total_w - (sb if need_v else 0), req_w)
        h = max(total_h - (sb if need_h else 0), req_h)
        canvas.itemconfigure(body_id, width=w, height=h)
        canvas.configure(scrollregion=(0, 0, w, h))
        body_req["size"] = (req_w, req_h)

    canvas.bind("<Configure>", fit_body)

    def on_wheel(event):
        w = event.widget
        if not vbar.winfo_ismapped() or isinstance(w, str) or w.winfo_toplevel() is not root or \
                str(w).startswith(str(txt)):
            return  # la rotellina sui messaggi scorre i messaggi
        canvas.yview_scroll(int(-event.delta / 120) or (-1 if event.delta > 0 else 1), "units")

    root.bind_all("<MouseWheel>", on_wheel)

    # --- Schede: Club Log e UDP ---
    nb = ttk.Notebook(body)
    nb.pack(fill="x", padx=10, pady=(10, 5))
    cred = ttk.Frame(nb, padding=8)
    nb.add(cred, text="Club Log")
    lf = ttk.Frame(nb, padding=8)
    nb.add(lf, text="UDP")

    v_call = tk.StringVar(value=cfg["callsign"])
    v_email = tk.StringVar(value=cfg["email"])
    v_pwd = tk.StringVar(value=cfg["password"])
    v_api = tk.StringVar(value=cfg["api"])
    v_show = tk.BooleanVar(value=False)
    v_freq = tk.BooleanVar(value=cfg["include_freq"])
    v_dry = tk.BooleanVar(value=cfg["dry_run"])
    v_auto = tk.BooleanVar(value=cfg["autostart"])
    v_tray = tk.BooleanVar(value=cfg["tray"] and pystray is not None)
    v_interval = tk.StringVar(value=str(cfg["interval"]))
    v_batch = tk.StringVar(value=str(cfg["batch"]))

    # A sinistra i campi in colonna, a destra le opzioni in colonna
    fields = ttk.Frame(cred)
    fields.grid(row=0, column=0, sticky="nw", padx=(0, 24))
    ttk.Label(fields, text="Nominativo DX:").grid(row=0, column=0, sticky="e")
    e_call = ttk.Entry(fields, textvariable=v_call, width=16)
    e_call.grid(row=0, column=1, columnspan=3, sticky="w", padx=4)
    ttk.Label(fields, text="Email Club Log:").grid(row=1, column=0, sticky="e", pady=(6, 0))
    e_email = ttk.Entry(fields, textvariable=v_email, width=40)
    e_email.grid(row=1, column=1, columnspan=3, sticky="w", padx=4, pady=(6, 0))
    ttk.Label(fields, text="App password:").grid(row=2, column=0, sticky="e", pady=(6, 0))
    e_pwd = ttk.Entry(fields, textvariable=v_pwd, width=40, show="•")
    e_pwd.grid(row=2, column=1, columnspan=3, sticky="w", padx=4, pady=(6, 0))
    ttk.Label(fields, text="API key:").grid(row=3, column=0, sticky="e", pady=(6, 0))
    if BUILTIN_API_KEY:
        e_api = ttk.Label(fields, text="integrata nel programma", foreground=COLORS["ok"])
    else:
        e_api = ttk.Entry(fields, textvariable=v_api, width=40, show="•")
    e_api.grid(row=3, column=1, columnspan=3, sticky="w", padx=4, pady=(6, 0))

    def toggle_show():
        ch = "" if v_show.get() else "•"
        e_pwd.configure(show=ch)
        if not BUILTIN_API_KEY:
            e_api.configure(show=ch)

    opts = ttk.Frame(cred)
    opts.grid(row=0, column=1, sticky="nw")
    c_auto = ttk.Checkbutton(opts, text="Avvia ascolto all'apertura", variable=v_auto)
    c_auto.pack(anchor="w", pady=1)
    c_freq = ttk.Checkbutton(opts, text="Invia la frequenza", variable=v_freq)
    c_freq.pack(anchor="w", pady=1)
    c_show = ttk.Checkbutton(opts, text="Mostra password/chiave", variable=v_show, command=toggle_show)
    c_show.pack(anchor="w", pady=1)
    c_tray = ttk.Checkbutton(opts, text="Riduci a icona nella tray bar", variable=v_tray,
                             state="normal" if pystray else "disabled")
    c_tray.pack(anchor="w", pady=1)
    boot_entry = startup_entry()
    v_boot = tk.BooleanVar(value=bool(boot_entry) and startup_is_mine(boot_entry))

    def toggle_boot():
        on = v_boot.get()
        other = startup_entry()
        try:
            set_startup(on)
        except OSError as e:
            v_boot.set(not on)
            messagebox.showerror(APP_NAME, "Impossibile modificare l'avvio con Windows:\n%s" % e)
            return
        if on:
            if other and not startup_is_mine(other):
                add_log("warn", "Avvio con Windows: sostituito il programma registrato prima (%s)" % other)
            add_log("ok", "Avvio con Windows attivato: all'accensione il programma si apre ridotto a icona"
                    + ("" if v_auto.get() else " (attiva anche \"Avvia ascolto all'apertura\" per "
                       "ricevere i QSO senza toccare niente)"))
        else:
            add_log("info", "Avvio con Windows disattivato")

    c_boot = ttk.Checkbutton(opts, text="Avvia con Windows", variable=v_boot, command=toggle_boot,
                             state="normal" if os.name == "nt" else "disabled")
    c_boot.pack(anchor="w", pady=1)
    c_dry = ttk.Checkbutton(opts, text="Modalità TEST (non invia a Club Log)", variable=v_dry)
    c_dry.pack(anchor="w", pady=(12, 1))  # in fondo, un po' staccata dalle altre

    ttk.Label(fields, text="Pausa tra due invii:").grid(row=4, column=0, sticky="e", pady=(10, 0))
    e_interval = ttk.Spinbox(fields, from_=1, to=600, textvariable=v_interval, width=6)
    e_interval.grid(row=4, column=1, sticky="w", padx=4, pady=(10, 0))
    ttk.Label(fields, text="secondi (minimo)").grid(row=4, column=2, sticky="w", pady=(10, 0))
    ttk.Label(fields, text="Invio a blocchi da:").grid(row=5, column=0, sticky="e", pady=(6, 0))
    e_batch = ttk.Spinbox(fields, from_=0, to=10000, textvariable=v_batch, width=6)
    e_batch.grid(row=5, column=1, sticky="w", padx=4, pady=(6, 0))
    ttk.Label(fields, text="QSO in coda (0 = mai)").grid(row=5, column=2, sticky="w", pady=(6, 0))

    # --- Porte UDP in ascolto ---
    for col, title in enumerate(["Attivo", "Programma", "Interfaccia (IP)", "Porta", "Multicast (opz.)", "Stato"]):
        ttk.Label(lf, text=title, font=("Segoe UI", 9, "bold")).grid(row=0, column=col, sticky="w", padx=4)
    # Colonna Stato larga quanto il messaggio più lungo tra quelli comuni
    from tkinter import font as tkfont
    status_px = tkfont.nametofont("TkDefaultFont").measure(
        "00:00:00  ultimo: N1MM-XML contactinfo (QARTest) da 192.168.100.200") + 16
    lf.columnconfigure(5, weight=1, minsize=status_px)

    ip_choices = local_ipv4_addresses()
    rows = []
    for i, lcfg in enumerate(cfg["listeners"]):
        r = {"name": lcfg["name"],
             "enabled": tk.BooleanVar(value=lcfg["enabled"]),
             "ip": tk.StringVar(value=lcfg["ip"]),
             "port": tk.StringVar(value=str(lcfg["port"])),
             "mcast": tk.StringVar(value=lcfg["mcast"])}
        r["w_en"] = ttk.Checkbutton(lf, variable=r["enabled"])
        r["w_en"].grid(row=i + 1, column=0, padx=4, pady=2)
        ttk.Label(lf, text=lcfg["name"]).grid(row=i + 1, column=1, sticky="w", padx=4)
        r["w_ip"] = ttk.Combobox(lf, textvariable=r["ip"], values=ip_choices, width=14)
        r["w_ip"].grid(row=i + 1, column=2, sticky="w", padx=4)
        r["w_port"] = ttk.Entry(lf, textvariable=r["port"], width=6)
        r["w_port"].grid(row=i + 1, column=3, sticky="w", padx=4)
        r["w_mcast"] = ttk.Entry(lf, textvariable=r["mcast"], width=14)
        r["w_mcast"].grid(row=i + 1, column=4, sticky="w", padx=4)
        # width=1: la larghezza la dà la colonna; un testo più lungo non allarga la finestra
        r["status"] = tk.Label(lf, text="Fermo", anchor="w", fg=COLORS["info"], width=1)
        r["status"].grid(row=i + 1, column=5, sticky="we", padx=4)
        rows.append(r)

    # --- Barra comandi e contatori ---
    bar = ttk.Frame(body, padding=(10, 2))
    bar.pack(fill="x")
    b_start = ttk.Button(bar, text="▶ Avvia ascolto")
    b_start.pack(side="left")
    b_stop = ttk.Button(bar, text="■ Ferma", state="disabled")
    b_stop.pack(side="left", padx=6)
    b_retry = ttk.Button(bar, text="Riprova coda")
    b_retry.pack(side="left")
    b_import = ttk.Button(bar, text="Importa log ADIF...")
    b_import.pack(side="left", padx=6)
    b_folder = ttk.Button(bar, text="Apri cartella dati")
    b_folder.pack(side="left")

    # --- Stato e contatori, in fondo alla finestra ---
    status = ttk.Frame(body, padding=(10, 0, 10, 6))
    status.pack(side="bottom", fill="x")
    v_mode = tk.StringVar()
    l_mode = tk.Label(status, textvariable=v_mode, font=("Segoe UI", 10, "bold"))
    l_mode.pack(side="left", padx=(0, 12))
    v_counters = tk.StringVar()
    ttk.Label(status, textvariable=v_counters, font=("Segoe UI", 10, "bold")).pack(side="left")

    # --- Log ---
    logf = ttk.LabelFrame(body, text=" Messaggi  (Alt+W per cancellare) ", padding=4)
    logf.pack(fill="both", expand=True, padx=10, pady=(5, 10))
    # height piccola: è la misura minima, l'area messaggi si allarga con la finestra
    txt = ScrolledText(logf, height=6, font=("Consolas", 9), state="disabled", wrap="word")
    txt.pack(fill="both", expand=True)
    for lvl, color in COLORS.items():
        txt.tag_configure(lvl, foreground=color)
    txt.tag_configure("err", foreground=COLORS["err"], font=("Consolas", 9, "bold"))

    def add_log(level, text):
        txt.configure(state="normal")
        txt.insert("end", time.strftime("%H:%M:%S  ") + text + "\n", level)
        lines = int(txt.index("end-1c").split(".")[0])
        if lines > 3000:
            txt.delete("1.0", "%d.0" % (lines - 3000))
        txt.configure(state="disabled")
        txt.see("end")

    def clear_log(event=None):
        txt.configure(state="normal")
        txt.delete("1.0", "end")
        txt.configure(state="disabled")
        return "break"

    root.bind("<Alt-w>", clear_log)
    root.bind("<Alt-W>", clear_log)  # con il blocco maiuscole attivo

    def collect():
        return {"callsign": v_call.get().strip().upper(), "email": v_email.get().strip(),
                "password": v_pwd.get().strip(), "api": v_api.get().strip(),
                "include_freq": v_freq.get(), "dry_run": v_dry.get(), "autostart": v_auto.get(),
                "tray": v_tray.get(), "interval": v_interval.get().strip(), "batch": v_batch.get().strip(),
                "listeners": [{"name": r["name"], "enabled": r["enabled"].get(),
                               "ip": r["ip"].get().strip(), "port": r["port"].get().strip(),
                               "mcast": r["mcast"].get().strip()} for r in rows]}

    def validate(c):
        errs = []
        if not c["callsign"]:
            errs.append("Inserisci il nominativo DX.")
        if not c["dry_run"]:
            for key, label in (("email", "l'email Club Log"), ("password", "l'app password"),
                               ("api", "l'API key")):
                if not c[key] and not (key == "api" and BUILTIN_API_KEY):
                    errs.append("Inserisci %s (o attiva la modalità TEST)." % label)
        try:
            c["interval"] = int(c["interval"])
            if not 1 <= c["interval"] <= 600:
                raise ValueError
        except ValueError:
            errs.append("La pausa minima tra due invii deve essere tra 1 e 600 secondi.")
        try:
            c["batch"] = int(c["batch"])
            if not 0 <= c["batch"] <= 10000:
                raise ValueError
        except ValueError:
            errs.append("La soglia per l'invio a blocchi deve essere tra 0 e 10000 QSO.")
        active, used = [], []
        for i, l in enumerate(c["listeners"]):
            try:
                l["port"] = int(l["port"])
                if not 1 <= l["port"] <= 65535:
                    raise ValueError
            except ValueError:
                errs.append("%s: porta non valida." % l["name"])
                continue
            try:
                ipaddress.IPv4Address(l["ip"])
            except ValueError:
                errs.append("%s: indirizzo IP non valido." % l["name"])
                continue
            if l["mcast"]:
                try:
                    if not ipaddress.IPv4Address(l["mcast"]).is_multicast:
                        raise ValueError
                except ValueError:
                    errs.append("%s: indirizzo multicast non valido (224.0.0.0-239.255.255.255)." % l["name"])
                    continue
            if not l["enabled"]:
                continue
            for other_name, oip, oport in used:
                if oport == l["port"] and (oip == l["ip"] or "0.0.0.0" in (oip, l["ip"])):
                    errs.append("%s e %s usano la stessa porta %d." % (other_name, l["name"], l["port"]))
            used.append((l["name"], l["ip"], l["port"]))
            active.append((i, l))
        if not active and not errs:
            errs.append("Attiva almeno una porta.")
        return errs, active

    def set_running(running):
        st = "disabled" if running else "normal"
        for w in (e_call, e_email, e_pwd, e_api, c_freq, c_dry, e_interval, e_batch):
            w.configure(state=st)
        for r in rows:
            for key in ("w_en", "w_port", "w_mcast"):
                r[key].configure(state=st)
            r["w_ip"].configure(state="disabled" if running else "normal")
        b_start.configure(state="disabled" if running else "normal")
        b_stop.configure(state="normal" if running else "disabled")

    # Salvataggio automatico a ogni modifica. I numeri non ancora validi (es. mentre si scrive)
    # mantengono l'ultimo valore valido.
    last_good = {"interval": cfg["interval"], "batch": cfg["batch"]}
    save_job = {"id": None, "error": False}

    def do_save(quiet=True):
        save_job["id"] = None
        c = collect()
        for key, lo, hi in (("interval", 1, 600), ("batch", 0, 10000)):
            try:
                value = int(c[key])
                if not lo <= value <= hi:
                    raise ValueError
                last_good[key] = value
            except ValueError:
                pass
            c[key] = last_good[key]
        for l in c["listeners"]:
            try:
                l["port"] = int(l["port"])
            except ValueError:
                pass
        try:
            save_config(c)
            save_job["error"] = False
        except OSError as e:
            if not save_job["error"]:  # una sola segnalazione finché il problema resta
                add_log("err", "Impossibile salvare le impostazioni: %s" % e)
            save_job["error"] = True

    def schedule_save(*_):
        if save_job["id"]:
            root.after_cancel(save_job["id"])
        save_job["id"] = root.after(500, do_save)

    for var in [v_call, v_email, v_pwd, v_api, v_freq, v_dry, v_auto, v_tray, v_interval, v_batch] + \
            [r[k] for r in rows for k in ("enabled", "ip", "port", "mcast")]:
        var.trace_add("write", schedule_save)

    def do_start():
        c = collect()
        errs, active = validate(c)
        if errs:
            messagebox.showerror(APP_NAME, "\n".join(errs))
            return
        do_save(quiet=True)
        for r in rows:
            r["status"].configure(text="Disattivato" if not r["enabled"].get() else "Avvio...",
                                  fg=COLORS["info"])
        if c["dry_run"]:
            add_log("warn", "Avvio in modalità TEST: i QSO vengono ricevuti ma NON inviati a Club Log.")
        else:
            add_log("info", "Avvio: i QSO verranno caricati nel log Club Log di %s." % c["callsign"])
        if BUILTIN_API_KEY:
            c = dict(c, api=BUILTIN_API_KEY)  # mai salvata nelle impostazioni
        engine.start(c, active)
        set_running(True)

    def do_stop():
        engine.stop()
        set_running(False)
        add_log("info", "Ascolto fermato. I QSO non ancora inviati restano in coda.")

    def do_retry():
        if engine.listeners:
            engine.uploader.resume()
            add_log("info", "Nuovo tentativo di invio della coda (%d QSO)." % engine.uploader.pending())
        else:
            add_log("warn", "Avvia l'ascolto per inviare la coda.")

    def do_folder():
        if os.name == "nt":
            os.startfile(BASE_DIR)

    def do_import():
        call = v_call.get().strip().upper()
        if not call:
            messagebox.showerror(APP_NAME, "Inserisci prima il nominativo DX della spedizione.")
            return
        path = filedialog.askopenfilename(
            parent=root, title="Scegli il file ADIF del log pregresso",
            filetypes=[("File ADIF", "*.adi *.adif"), ("Tutti i file", "*.*")])
        if not path:
            return
        try:
            with open(path, "rb") as f:
                records = parse_adif(f.read())
        except OSError as e:
            messagebox.showerror(APP_NAME, "Impossibile leggere il file:\n%s" % e)
            return
        if not records:
            messagebox.showerror(APP_NAME, "Nessun QSO trovato nel file:\n%s" % path)
            return

        win = tk.Toplevel(root)
        win.title("Importa log ADIF")
        win.transient(root)
        win.resizable(False, False)
        frm = ttk.Frame(win, padding=14)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="File: %s" % os.path.basename(path),
                  font=("Segoe UI", 10, "bold")).grid(row=0, column=0, columnspan=5, sticky="w")
        ttk.Label(frm, text="Vengono caricati solo i QSO con STATION_CALLSIGN = %s" % call).grid(
            row=1, column=0, columnspan=5, sticky="w", pady=(4, 8))

        v_missing = tk.BooleanVar(value=False)
        v_from = tk.StringVar()
        v_to = tk.StringVar()
        state = {}

        def parse_date(text):
            digits = re.sub(r"\D", "", text)
            if not digits:
                return ""
            dt.datetime.strptime(digits, "%Y%m%d")  # ValueError se non valida
            return digits

        def refresh(*_):
            try:
                dfrom, dto = parse_date(v_from.get()), parse_date(v_to.get())
            except ValueError:
                summary.configure(text="Data non valida: usa il formato AAAA-MM-GG.", fg=COLORS["err"])
                b_ok.configure(state="disabled", text="Carica su Club Log")
                return
            res = analyze_adif_import(records, call, v_freq.get(), v_missing.get(), dfrom, dto)
            state["res"] = res
            n = len(res["selected"])
            lines = ["QSO nel file:                     %d" % res["total"],
                     "QSO di %-10s da caricare:     %d" % (call, n)]
            if n:
                lines.append("   periodo: %s  ->  %s" % (format_stamp(res["first"]), format_stamp(res["last"])))
            others = sorted(res["others"].items(), key=lambda kv: -kv[1])
            lines.append("Altri nominativi (esclusi):       %d" % sum(res["others"].values()))
            if others:
                lines.append("   " + ", ".join("%s: %d" % kv for kv in others[:6])
                             + (", ..." if len(others) > 6 else ""))
            lines.append("Senza STATION_CALLSIGN (%s):  %d" % (
                "inclusi" if v_missing.get() else "esclusi", res["missing"]))
            if dfrom or dto:
                lines.append("Fuori dall'intervallo di date:    %d" % res["out_of_range"])
            lines.append("Non validi (data/banda/modo):     %d" % res["invalid"])
            summary.configure(text="\n".join(lines), fg=COLORS["info"])
            b_ok.configure(text="Carica su Club Log (%d QSO)" % n, state="normal" if n else "disabled")

        ttk.Checkbutton(frm, text="Includi anche i QSO senza STATION_CALLSIGN (verranno assegnati a %s)"
                        % call, variable=v_missing, command=refresh).grid(
            row=2, column=0, columnspan=5, sticky="w")
        ttk.Label(frm, text="Solo QSO dal").grid(row=3, column=0, sticky="w", pady=(8, 0))
        e_from = ttk.Entry(frm, textvariable=v_from, width=12)
        e_from.grid(row=3, column=1, sticky="w", padx=4, pady=(8, 0))
        ttk.Label(frm, text="al").grid(row=3, column=2, sticky="w", pady=(8, 0))
        e_to = ttk.Entry(frm, textvariable=v_to, width=12)
        e_to.grid(row=3, column=3, sticky="w", padx=4, pady=(8, 0))
        ttk.Label(frm, text="(AAAA-MM-GG, vuoto = qualsiasi data)").grid(row=3, column=4, sticky="w",
                                                                        pady=(8, 0))
        v_from.trace_add("write", refresh)
        v_to.trace_add("write", refresh)

        summary = tk.Label(frm, justify="left", anchor="w", font=("Consolas", 9))
        summary.grid(row=4, column=0, columnspan=5, sticky="w", pady=10)

        btns = ttk.Frame(frm)
        btns.grid(row=5, column=0, columnspan=5, sticky="e")
        b_ok = ttk.Button(btns, text="Carica su Club Log")
        b_ok.pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="Annulla", command=win.destroy).pack(side="left")

        def confirm():
            selected = state["res"]["selected"]
            if not messagebox.askyesno(
                    APP_NAME, "Caricare %d QSO nel log Club Log di %s?\n\n"
                              "I QSO vengono UNITI al log esistente: nessun QSO viene cancellato "
                              "e quelli già presenti vengono riconosciuti da Club Log." % (len(selected), call),
                    parent=win):
                return
            try:
                job = create_import_job(selected, path)
            except OSError as e:
                messagebox.showerror(APP_NAME, "Impossibile preparare il file da inviare:\n%s" % e, parent=win)
                return
            add_log("info", "Log importato da %s: %d QSO di %s pronti in %s" % (
                os.path.basename(path), len(selected), call, os.path.relpath(job, BASE_DIR)))
            if not engine.listeners or engine.uploader.dry_run:
                add_log("warn", "Il log importato verrà inviato appena avvii l'ascolto con la modalità TEST "
                                "disattivata.")
            engine.uploader.wake.set()
            win.destroy()

        b_ok.configure(command=confirm)
        refresh()
        win.grab_set()

    b_start.configure(command=do_start)
    b_stop.configure(command=do_stop)
    b_retry.configure(command=do_retry)
    b_import.configure(command=do_import)
    b_folder.configure(command=do_folder)

    # --- Tray bar ---
    TRAY_COLORS = {"info": "#757575", "ok": "#1a7f37", "warn": "#e08600", "err": "#c62828"}
    tray = {"icon": None, "color": None, "title": None, "hidden": False}

    def show_window():
        tray["hidden"] = False
        root.deiconify()
        root.state("normal")
        root.lift()
        root.focus_force()

    def on_unmap(event):
        # Pulsante "riduci a icona": nasconde la finestra e lascia solo l'icona nella tray
        if event.widget is root and tray["icon"] and v_tray.get() and root.state() == "iconic":
            tray["hidden"] = True
            root.after(10, root.withdraw)

    root.bind("<Unmap>", on_unmap)

    if pystray:
        try:
            tray["icon"] = pystray.Icon("clublog_listener", tray_image(TRAY_COLORS["info"]), APP_NAME,
                                        pystray.Menu(
                                            pystray.MenuItem("Mostra finestra",
                                                             lambda icon, item: events.put(("tray", "show")),
                                                             default=True),
                                            pystray.MenuItem("Esci",
                                                             lambda icon, item: events.put(("tray", "quit")))))
            threading.Thread(target=tray["icon"].run, daemon=True).start()
        except Exception as e:
            tray["icon"] = None
            add_log("warn", "Icona nella tray non disponibile: %s" % e)
    else:
        add_log("warn", "Per ridurre nella tray bar installa i moduli: pip install pystray pillow")

    def poll():
        try:
            while True:
                ev = events.get_nowait()
                if ev[0] == "log":
                    add_log(ev[1], ev[2])
                    if ev[1] == "err" and tray["hidden"] and tray["icon"]:
                        try:
                            tray["icon"].notify(ev[2][:250], APP_NAME)
                        except Exception:
                            pass
                elif ev[0] == "lstatus":
                    rows[ev[1]]["status"].configure(text=ev[2], fg=COLORS.get(ev[3], COLORS["info"]))
                elif ev[0] == "tray":
                    show_window()
                    if ev[1] == "quit" and on_close():
                        return
        except queue.Empty:
            pass
        s = engine.stats
        pending = engine.uploader.pending()
        jobs = len(engine.uploader.pending_jobs())
        v_counters.set("Ricevuti: %d   Inviati: %d   In coda: %d   Doppi ignorati: %d   Errori: %d%s" % (
            s["received"], s["sent"], pending, s["dupes"], s["errors"],
            "   File da caricare: %d" % jobs if jobs else ""))
        if not engine.listeners:
            mode, level = "FERMO", "info"
        elif engine.uploader.paused:
            mode, level = "INVIO IN PAUSA", "err"
        elif engine.uploader.dry_run:
            mode, level = "TEST", "warn"
        else:
            mode, level = "ONLINE", "ok"
        v_mode.set(mode)
        l_mode.configure(fg=COLORS[level])
        if tray["icon"]:
            if tray["color"] != level:
                tray["icon"].icon = tray_image(TRAY_COLORS[level])
                tray["color"] = level
            title = ("Club Log %s - %s\nRicevuti %d, inviati %d, in coda %d" % (
                v_call.get().strip().upper(), mode, s["received"], s["sent"], pending))[:127]
            if tray["title"] != title:
                tray["icon"].title = title
                tray["title"] = title
        if body_req.get("size") != (body.winfo_reqwidth(), body.winfo_reqheight()):
            fit_body()
        root.after(150, poll)

    def on_close():
        pending = engine.uploader.pending()
        if pending and not messagebox.askyesno(
                APP_NAME, "Ci sono %d QSO non ancora inviati.\nVerranno inviati al prossimo avvio.\n\n"
                          "Chiudere comunque?" % pending):
            return False
        do_save(quiet=True)
        engine.shutdown()
        if tray["icon"]:
            tray["icon"].stop()
        root.destroy()
        return True

    root.protocol("WM_DELETE_WINDOW", on_close)
    add_log("info", "%s %s - cartella dati: %s" % (APP_NAME, APP_VERSION, BASE_DIR))
    if engine.uploader.pending():
        add_log("warn", "%d QSO in coda dalla sessione precedente: verranno inviati all'avvio."
                % engine.uploader.pending())
    poll()
    # Misura iniziale adattata all'area libera del monitor su cui si apre, finestra centrata
    root.update_idletasks()  # dopo poll(): i contatori sono già scritti
    area = monitor_work_area(root.winfo_pointerx(), root.winfo_pointery()) or \
        (0, 0, root.winfo_screenwidth(), root.winfo_screenheight())
    scale = root.winfo_fpixels("1i") / 96.0
    frame_w, frame_h = int(16 * scale), int(39 * scale)  # bordi e barra del titolo
    width = min(body.winfo_reqwidth(), area[2] - frame_w)
    height = min(body.winfo_reqheight() + int(220 * scale), area[3] - frame_h)
    root.minsize(min(int(420 * scale), width), min(int(320 * scale), height))
    root.geometry("%dx%d+%d+%d" % (width, height, area[0] + (area[2] - width - frame_w) // 2,
                                    area[1] + (area[3] - height - frame_h) // 2))
    if STARTUP_ARG in sys.argv[1:]:
        # Avviato da Windows: solo l'icona nella tray (o nella barra delle applicazioni)
        if tray["icon"] and v_tray.get():
            tray["hidden"] = True
            root.withdraw()
        else:
            root.iconify()
    if cfg["autostart"]:
        root.after(300, do_start)
    root.mainloop()


if __name__ == "__main__":
    run_gui()
