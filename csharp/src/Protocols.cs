// Formati UDP supportati (riconosciuti automaticamente su ogni porta):
//   * Protocollo binario WSJT-X (QDataStream, magic 0xADBCCBDA):
//       - tipo 5  "QSO Logged"
//       - tipo 12 "Logged ADIF"
//     usato da WSJT-X, JTDX e MSHV.
//   * XML N1MM <contactinfo>/<contactreplace>/<contactdelete>
//     usato da QARTest e da DXLog (opzione "Use N1MM QSO format").
//   * Testo ADIF semplice (es. "secondary UDP server" di WSJT-X/JTDX).

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace ClubLogListener
{
    sealed class Packet
    {
        public string Proto, Msg, Info;
        public List<Dictionary<string, string>> Records;

        public Packet(string proto, string msg, string info, List<Dictionary<string, string>> records)
        {
            Proto = proto;
            Msg = msg;
            Info = info;
            Records = records;
        }
    }

    sealed class TruncatedException : Exception
    {
        public TruncatedException() : base("pacchetto troncato") { }
    }

    // Lettura QDataStream big-endian
    sealed class QReader
    {
        readonly byte[] data;
        int pos;

        public QReader(byte[] data)
        {
            this.data = data;
        }

        byte[] Take(int size)
        {
            if (pos + size > data.Length)
                throw new TruncatedException();
            var b = new byte[size];
            Array.Copy(data, pos, b, 0, size);
            pos += size;
            if (BitConverter.IsLittleEndian)
                Array.Reverse(b);
            return b;
        }

        public byte U8() { return Take(1)[0]; }
        public uint U32() { return BitConverter.ToUInt32(Take(4), 0); }
        public int I32() { return BitConverter.ToInt32(Take(4), 0); }
        public ulong U64() { return BitConverter.ToUInt64(Take(8), 0); }
        public long I64() { return BitConverter.ToInt64(Take(8), 0); }

        public string Utf8()
        {
            uint n = U32();
            if (n == 0xFFFFFFFF)
                return "";
            if (pos + (long)n > data.Length)
                throw new TruncatedException();
            string s = Encoding.UTF8.GetString(data, pos, (int)n);
            pos += (int)n;
            return s;
        }

        // QString: quint32 lunghezza in byte + UTF-16BE
        public string QString()
        {
            uint n = U32();
            if (n == 0xFFFFFFFF)
                return "";
            int len = (int)Math.Min(n, (uint)(data.Length - pos));
            string s = Encoding.BigEndianUnicode.GetString(data, pos, len);
            pos += len;
            return s;
        }

        // storedUtc: schema 1 (Qt 5.0) scrive sempre l'ora UTC, qualunque sia il timespec.
        // localIsUtc: JTDX (finestra Log QSO) e MSHV prima della 2.68 marcano come ora locale
        // le cifre dell'ora UTC
        public DateTime? QDateTime(bool storedUtc, bool localIsUtc)
        {
            long jd = I64();
            uint ms = U32();
            byte spec = U8();
            int offset = 0;
            if (spec == 2)
                offset = I32();
            else if (spec == 3)
                QString();  // id del fuso orario
            if (jd <= 0 || ms == 0xFFFFFFFF)
                return null;
            DateTime b = new DateTime(1, 1, 1).AddDays(jd - 1721425 - 1).AddMilliseconds(ms);
            if (storedUtc)
                return b;
            if (spec == 0 && !localIsUtc)
                b = DateTime.SpecifyKind(b, DateTimeKind.Local).ToUniversalTime();
            else if (spec == 2)
                b = b.AddSeconds(-offset);
            return DateTime.SpecifyKind(b, DateTimeKind.Unspecified);
        }
    }

    static class Protocols
    {
        public const uint WsjtxMagic = 0xADBCCBDA;
        static readonly string[] WsjtxTypes = {
            "Heartbeat", "Status", "Decode", "Clear", "Reply", "QSO Logged", "Close", "Replay", "Halt Tx",
            "Free Text", "WSPR Decode", "Location", "Logged ADIF", "Highlight Callsign", "Switch Configuration",
            "Configure" };
        static readonly Regex Eor = new Regex("<eor>", RegexOptions.IgnoreCase);
        static readonly Regex Contact = new Regex(@"^<contact\w+>", RegexOptions.IgnoreCase);
        static readonly string[] N1mmTimeFormats = {
            "yyyy-M-d H:m:s", "yyyy-M-d'T'H:m:s", "yyyy/M/d H:m:s", "yyyy-M-d H:m" };

        // WSJT-X, JTDX, MSHV. Info = id del client.
        public static Packet ParseWsjtx(byte[] data)
        {
            var r = new QReader(data);
            if (r.U32() != WsjtxMagic)
                throw new FormatException("magic errato");
            uint schema = r.U32();
            uint mtype = r.U32();
            string clientId = r.Utf8();
            string name = mtype < WsjtxTypes.Length ? WsjtxTypes[mtype] : "tipo " + mtype;
            var records = new List<Dictionary<string, string>>();
            if (mtype == 12)
                records = Adif.Parse(r.Utf8());
            else if (mtype == 5)
            {
                bool utcDigits = clientId.StartsWith("JTDX", StringComparison.OrdinalIgnoreCase) ||
                                 clientId.StartsWith("MSHV", StringComparison.OrdinalIgnoreCase);
                DateTime? off = r.QDateTime(schema == 1, utcDigits);
                var rec = new Dictionary<string, string>();
                rec["call"] = r.Utf8();
                rec["gridsquare"] = r.Utf8();
                ulong hz = r.U64();
                rec["mode"] = r.Utf8();
                rec["rst_sent"] = r.Utf8();
                rec["rst_rcvd"] = r.Utf8();
                r.Utf8();  // tx power
                r.Utf8();  // comments
                r.Utf8();  // name
                DateTime? on = r.QDateTime(schema == 1, utcDigits);
                try
                {
                    rec["operator"] = r.Utf8();
                    rec["station_callsign"] = r.Utf8();
                    rec["my_gridsquare"] = r.Utf8();
                }
                catch (TruncatedException)
                {
                    // versioni vecchie senza questi campi
                }
                DateTime? start = on ?? off;
                if (start.HasValue)
                {
                    rec["qso_date"] = start.Value.ToString("yyyyMMdd", Adif.Inv);
                    rec["time_on"] = start.Value.ToString("HHmmss", Adif.Inv);
                }
                if (off.HasValue)
                {
                    rec["qso_date_off"] = off.Value.ToString("yyyyMMdd", Adif.Inv);
                    rec["time_off"] = off.Value.ToString("HHmmss", Adif.Inv);
                }
                if (hz != 0)
                    rec["freq"] = Adif.Mhz(hz / 1e6);
                records.Add(rec);
            }
            return new Packet("WSJT-X", name, clientId, records);
        }

        // XML N1MM (QARTest, DXLog). Info = programma che l'ha inviato.
        public static Packet ParseN1mmXml(string text)
        {
            var settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Prohibit;
            settings.XmlResolver = null;
            var doc = new XmlDocument();
            using (var reader = XmlReader.Create(new StringReader(text), settings))
                doc.Load(reader);
            XmlElement root = doc.DocumentElement;
            string tag = root.Name.ToLowerInvariant();

            Func<string, string> get = name =>
            {
                foreach (XmlNode child in root.ChildNodes)
                    if (child is XmlElement && child.Name.ToLowerInvariant() == name)
                        return (child.InnerText ?? "").Trim();
                return "";
            };

            string program = get("app");
            if (program.Length == 0)
                program = get("logger");
            if (program.Length == 0)
                program = "?";
            var records = new List<Dictionary<string, string>>();
            if (tag != "contactinfo" && tag != "contactreplace")
                return new Packet("N1MM-XML", tag, program, records);

            var rec = new Dictionary<string, string>();
            rec["call"] = get("call");
            rec["mode"] = get("mode");
            rec["rst_sent"] = get("snt");
            rec["rst_rcvd"] = get("rcv");
            rec["station_callsign"] = get("mycall");
            rec["operator"] = get("operator");
            rec["gridsquare"] = get("gridsquare");

            DateTime t;
            if (DateTime.TryParseExact(get("timestamp"), N1mmTimeFormats, Adif.Inv,
                                       System.Globalization.DateTimeStyles.None, out t))
            {
                rec["qso_date"] = t.ToString("yyyyMMdd", Adif.Inv);
                rec["time_on"] = t.ToString("HHmmss", Adif.Inv);
            }

            // Frequenze N1MM in unità di 10 Hz
            foreach (var pair in new[] { new[] { "txfreq", "freq" }, new[] { "rxfreq", "freq_rx" } })
            {
                string val = get(pair[0]);
                double f;
                if (val.Length > 0 && Adif.TryFloat(val, out f) && f / 100000.0 > 0)
                    rec[pair[1]] = Adif.Mhz(f / 100000.0);
            }
            if (!rec.ContainsKey("freq") && rec.ContainsKey("freq_rx"))
            {
                rec["freq"] = rec["freq_rx"];
                rec.Remove("freq_rx");
            }

            string band = get("band");
            if (band.Length > 0 && !rec.ContainsKey("freq"))
            {
                string lower = band.ToLowerInvariant();
                if (program.ToLowerInvariant().Contains("qartest") && Adif.MeterBands.Contains(band))
                    rec["band"] = band + "m";
                else if (Adif.N1mmBandMhz.ContainsKey(band))
                    rec["band"] = Adif.N1mmBandMhz[band];
                else if (lower.EndsWith("m"))  // comprende anche cm e mm
                    rec["band"] = lower;
            }
            records.Add(rec);
            return new Packet("N1MM-XML", tag, program, records);
        }

        // Riconosce il formato del pacchetto.
        public static Packet Parse(byte[] data)
        {
            if (data.Length >= 4 && (uint)(data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]) == WsjtxMagic)
                return ParseWsjtx(data);
            string text = Encoding.UTF8.GetString(data).Replace("\0", "").Trim();
            if (text.StartsWith("<?xml", StringComparison.Ordinal) || Contact.IsMatch(text) || text.StartsWith("<", StringComparison.Ordinal))
            {
                if (Eor.IsMatch(text))
                    return new Packet("ADIF", "record ADIF", "", Adif.Parse(text));
                return ParseN1mmXml(text);
            }
            if (Eor.IsMatch(text))
                return new Packet("ADIF", "record ADIF", "", Adif.Parse(text));
            throw new FormatException("formato sconosciuto");
        }
    }
}
