"""Invia al Club Log Universal Listener pacchetti UDP di prova, uguali a quelli dei programmi veri.

Serve a provare ricezione e riconoscimento dei formati senza avere aperti i programmi.
Avvia prima il listener in modalità TEST, poi ad esempio:

    python simula_pacchetti.py                  tutti e 5 i programmi
    python simula_pacchetti.py JTDX QARTest     solo alcuni
    python simula_pacchetti.py --mycall IK2JUB --host 192.168.1.10

Ogni QSO usa l'ora UTC attuale e un nominativo di esempio diverso per programma.
"""
import argparse
import datetime as dt
import socket
import struct
import time

MAGIC = 0xADBCCBDA
SCHEMA = 3

# programma: (porta di default del listener, nominativo DX di esempio, banda/frequenza, modo)
PROGRAMS = {
    "WSJT-X": (2237, "K1ABC", 14074000, "FT8"),
    "JTDX": (2238, "DL1XYZ", 7074000, "FT8"),
    "MSHV": (2239, "JA1AA", 21140000, "FT8"),
    "QARTest": (12060, "VK2ZZ", 14025000, "CW"),
    "DXLog": (12061, "PY2AB", 28480000, "SSB"),
}


# --- protocollo binario WSJT-X (QDataStream big-endian) ---------------------

def utf8(s):
    b = s.encode("utf-8")
    return struct.pack(">I", len(b)) + b


def qdatetime(t, spec=1):
    jd = t.date().toordinal() + 1721425
    ms = ((t.hour * 60 + t.minute) * 60 + t.second) * 1000
    return struct.pack(">qIB", jd, ms, spec)  # 1 = UTC, 0 = ora locale


def header(mtype, client_id):
    return struct.pack(">III", MAGIC, SCHEMA, mtype) + utf8(client_id)


def wsjtx_heartbeat(client_id):
    return header(0, client_id) + struct.pack(">I", SCHEMA) + utf8("2.7.0") + utf8("")


def wsjtx_qso_logged(client_id, mycall, call, hz, mode, t_on, t_off):
    # JTDX manda le cifre dell'ora UTC marcate come ora locale
    spec = 0 if client_id == "JTDX" else 1
    return (header(5, client_id) + qdatetime(t_off, spec) + utf8(call) + utf8("FN42") +
            struct.pack(">Q", hz) + utf8(mode) + utf8("-10") + utf8("-12") + utf8("100") +
            utf8("") + utf8("") + qdatetime(t_on, spec) + utf8("") + utf8(mycall) + utf8("JN45") +
            utf8("") + utf8("") + utf8(""))


def adif_field(name, value):
    return "<%s:%d>%s" % (name, len(value), value)


def wsjtx_logged_adif(client_id, mycall, call, hz, mode, t_on, t_off):
    rec = "".join(adif_field(k, v) for k, v in (
        ("call", call), ("gridsquare", "FN42"), ("mode", mode), ("rst_sent", "-10"),
        ("rst_rcvd", "-12"), ("qso_date", t_on.strftime("%Y%m%d")), ("time_on", t_on.strftime("%H%M%S")),
        ("qso_date_off", t_off.strftime("%Y%m%d")), ("time_off", t_off.strftime("%H%M%S")),
        ("band", band_of(hz)), ("freq", "%.6f" % (hz / 1e6)), ("station_callsign", mycall),
        ("my_gridsquare", "JN45")))
    adif = "\n<adif_ver:5>3.1.0\n<programid:6>WSJT-X\n<EOH>\n" + rec + " <EOR>"
    return header(12, client_id) + utf8(adif)


def band_of(hz):
    mhz = hz / 1e6
    for lo, hi, band in ((1.8, 2, "160m"), (3.5, 4, "80m"), (7, 7.3, "40m"), (10.1, 10.15, "30m"),
                         (14, 14.35, "20m"), (18.068, 18.168, "17m"), (21, 21.45, "15m"),
                         (24.89, 24.99, "12m"), (28, 29.7, "10m"), (50, 54, "6m")):
        if lo <= mhz <= hi:
            return band
    return ""


# --- XML N1MM (QARTest, DXLog) -------------------------------------------

def n1mm_contactinfo(app, mycall, call, hz, mode, t_on, band):
    f10 = str(hz // 10)  # N1MM usa unità di 10 Hz
    return ('<?xml version="1.0" encoding="utf-8"?>\n<contactinfo>\n'
            "<app>%s</app>\n<contestname>DX</contestname>\n<timestamp>%s</timestamp>\n"
            "<mycall>%s</mycall>\n<band>%s</band>\n<rxfreq>%s</rxfreq>\n<txfreq>%s</txfreq>\n"
            "<operator>%s</operator>\n<mode>%s</mode>\n<call>%s</call>\n"
            "<snt>%s</snt>\n<rcv>%s</rcv>\n</contactinfo>\n"
            % (app, t_on.strftime("%Y-%m-%d %H:%M:%S"), mycall, band, f10, f10, mycall, mode, call,
               "599" if mode == "CW" else "59", "599" if mode == "CW" else "59")).encode("utf-8")


def packets(program, mycall, call, hz, mode):
    """Restituisce la lista (descrizione, bytes) che quel programma invierebbe per un QSO."""
    t_off = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None, microsecond=0)
    t_on = t_off - dt.timedelta(minutes=1)
    if program in ("WSJT-X", "JTDX", "MSHV"):
        return [("Heartbeat", wsjtx_heartbeat(program)),
                ("QSO Logged", wsjtx_qso_logged(program, mycall, call, hz, mode, t_on, t_off)),
                ("Logged ADIF", wsjtx_logged_adif(program, mycall, call, hz, mode, t_on, t_off))]
    if program == "QARTest":  # QARTest indica la banda in metri
        band = band_of(hz).rstrip("m")
        return [("contactinfo", n1mm_contactinfo("QARTest", mycall, call, hz, mode, t_on, band))]
    band = str(int(hz / 1e6))  # DXLog: banda in MHz come N1MM (14, 21, 28...)
    return [("contactinfo", n1mm_contactinfo("DXLog", mycall, call, hz, mode, t_on, band))]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("programmi", nargs="*", metavar="PROGRAMMA",
                    help="tra: %s (default: tutti)" % ", ".join(PROGRAMS))
    ap.add_argument("--host", default="127.0.0.1", help="indirizzo del listener (default 127.0.0.1)")
    ap.add_argument("--mycall", default="IK2JUB", help="STATION_CALLSIGN da mettere nei QSO")
    args = ap.parse_args()

    names = {n.lower(): n for n in PROGRAMS}
    chosen = []
    for p in args.programmi or PROGRAMS:
        if p.lower() not in names:
            ap.error("programma sconosciuto: %s" % p)
        chosen.append(names[p.lower()])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for program in chosen:
        port, call, hz, mode = PROGRAMS[program]
        for desc, data in packets(program, args.mycall.upper(), call, hz, mode):
            sock.sendto(data, (args.host, port))
            print("%-8s -> %s:%-5d  %-12s %s %s %.3f MHz" % (program, args.host, port, desc, call, mode,
                                                             hz / 1e6))
            time.sleep(0.2)
    sock.close()


if __name__ == "__main__":
    main()
