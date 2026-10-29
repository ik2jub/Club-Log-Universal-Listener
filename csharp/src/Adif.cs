// ADIF: lettura, normalizzazione dei QSO per Club Log, importazione di un log pregresso.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace ClubLogListener
{
    sealed class ImportResult
    {
        public int Total, Missing, Invalid, OutOfRange;
        public List<Dictionary<string, string>> Selected = new List<Dictionary<string, string>>();
        public Dictionary<string, int> Others = new Dictionary<string, int>();
        public string First = "", Last = "";
    }

    static class Adif
    {
        struct Band
        {
            public double Lo, Hi;
            public string Name;
            public Band(double lo, double hi, string name) { Lo = lo; Hi = hi; Name = name; }
        }

        static readonly Band[] Bands = {
            new Band(0.1357, 0.1378, "2190m"), new Band(0.472, 0.479, "630m"), new Band(1.8, 2.0, "160m"),
            new Band(3.5, 4.0, "80m"), new Band(5.06, 5.45, "60m"), new Band(7.0, 7.3, "40m"), new Band(10.1, 10.15, "30m"),
            new Band(14.0, 14.35, "20m"), new Band(18.068, 18.168, "17m"), new Band(21.0, 21.45, "15m"),
            new Band(24.89, 24.99, "12m"), new Band(28.0, 29.7, "10m"), new Band(40.0, 45.0, "8m"), new Band(50.0, 54.0, "6m"),
            new Band(54.000001, 69.9, "5m"), new Band(70.0, 71.0, "4m"), new Band(144.0, 148.0, "2m"),
            new Band(222.0, 225.0, "1.25m"), new Band(420.0, 450.0, "70cm"), new Band(902.0, 928.0, "33cm"),
            new Band(1240.0, 1300.0, "23cm"), new Band(2300.0, 2450.0, "13cm"), new Band(3300.0, 3500.0, "9cm"),
            new Band(5650.0, 5925.0, "6cm"), new Band(10000.0, 10500.0, "3cm"), new Band(24000.0, 24250.0, "1.25cm"),
            new Band(47000.0, 47200.0, "6mm"), new Band(75500.0, 81000.0, "4mm"),
        };

        // Valori del campo <band> N1MM (MHz) e QARTest (metri)
        public static readonly Dictionary<string, string> N1mmBandMhz = new Dictionary<string, string> {
            {"1.8", "160m"}, {"3.5", "80m"}, {"5", "60m"}, {"7", "40m"}, {"10", "30m"},
            {"14", "20m"}, {"18", "17m"}, {"21", "15m"}, {"24", "12m"}, {"28", "10m"},
            {"50", "6m"}, {"70", "4m"}, {"144", "2m"}, {"222", "1.25m"}, {"420", "70cm"},
            {"432", "70cm"}, {"902", "33cm"}, {"1240", "23cm"}, {"1296", "23cm"},
        };
        public static readonly HashSet<string> MeterBands = new HashSet<string> {
            "160", "80", "60", "40", "30", "20", "17", "15", "12", "10", "6", "4", "2" };

        // Modi che in ADIF 3 sono submode di MFSK / SSB
        static readonly HashSet<string> MfskSubmodes = new HashSet<string> { "FT4", "JS8", "Q65" };
        static readonly HashSet<string> SsbSubmodes = new HashSet<string> { "USB", "LSB" };

        static readonly string[] UploadFields = {
            "call", "qso_date", "time_on", "qso_date_off", "time_off", "band", "band_rx",
            "freq", "freq_rx", "mode", "submode", "rst_sent", "rst_rcvd",
            "station_callsign", "operator", "gridsquare", "my_gridsquare",
            "prop_mode", "sat_name" };

        static readonly Regex Tag = new Regex(@"<([A-Za-z0-9_]+)(?::([0-9]+)(?::[A-Za-z])?)?>");
        static readonly Regex Eoh = new Regex("<eoh>", RegexOptions.IgnoreCase);
        static readonly Regex NonDigit = new Regex(@"\D");
        static readonly Regex BadFileChars = new Regex(@"[^A-Za-z0-9_.-]");
        static readonly Encoding Latin1 = Encoding.GetEncoding(28591);
        static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);
        public static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

        public static IEnumerable<string> BandNames
        {
            get { return Bands.Select(b => b.Name); }
        }

        public static string FreqToBand(double mhz)
        {
            foreach (Band b in Bands)
                if (b.Lo <= mhz && mhz <= b.Hi)
                    return b.Name;
            return "";
        }

        // Banda di una frequenza nominale (es. 1.2 GHz), con un margine del 10%
        public static string NearBand(double mhz)
        {
            foreach (Band b in Bands)
                if (b.Lo * 0.9 <= mhz && mhz <= b.Hi * 1.1)
                    return b.Name;
            return "";
        }

        public static bool TryFloat(string s, out double value)
        {
            return double.TryParse(s, NumberStyles.Float, Inv, out value);
        }

        public static string Mhz(double mhz)
        {
            return mhz.ToString("F6", Inv);
        }

        // Testo ricevuto via UDP: le lunghezze dei campi si contano in caratteri
        public static List<Dictionary<string, string>> Parse(string text)
        {
            return Parse(text, false);
        }

        // File: in ADIF le lunghezze dei campi sono in byte. Latin-1 fa corrispondere un
        // carattere a ogni byte; ogni valore viene poi decodificato in UTF-8 se possibile.
        public static List<Dictionary<string, string>> Parse(byte[] data)
        {
            return Parse(Latin1.GetString(data), true);
        }

        static List<Dictionary<string, string>> Parse(string text, bool bytes)
        {
            var records = new List<Dictionary<string, string>>();
            var current = new Dictionary<string, string>();
            int pos = 0;
            Match m = Eoh.Match(text);  // salta l'header se presente
            if (m.Success)
                pos = m.Index + m.Length;
            while (pos <= text.Length)
            {
                m = Tag.Match(text, pos);
                if (!m.Success)
                    break;
                string name = m.Groups[1].Value.ToLowerInvariant();
                int end = m.Index + m.Length;
                if (name == "eor")
                {
                    if (current.Count > 0)
                        records.Add(current);
                    current = new Dictionary<string, string>();
                    pos = end;
                    continue;
                }
                long length;
                if (!m.Groups[2].Success || !long.TryParse(m.Groups[2].Value, NumberStyles.None, Inv, out length))
                {
                    pos = end;
                    continue;
                }
                string value = text.Substring(end, (int)Math.Min(length, text.Length - end));
                current[name] = bytes ? DecodeValue(value) : value;
                if (end + length > text.Length)
                    break;
                pos = end + (int)length;
            }
            return records;
        }

        static string DecodeValue(string latin1)
        {
            try
            {
                return StrictUtf8.GetString(Latin1.GetBytes(latin1));
            }
            catch (DecoderFallbackException)
            {
                return latin1;
            }
        }

        public static string FormatStamp(string stamp)
        {
            return string.Format("{0}-{1}-{2} {3}:{4}Z", Util.Slice(stamp, 0, 4), Util.Slice(stamp, 4, 6),
                Util.Slice(stamp, 6, 8), Util.Slice(stamp, 8, 10), Util.Slice(stamp, 10, 12));
        }

        public static string Build(Dictionary<string, string> record)
        {
            var sb = new StringBuilder();
            foreach (string key in UploadFields)
            {
                string value = Util.Get(record, key);
                if (value.Length > 0)
                    sb.AppendFormat("<{0}:{1}>{2}", key.ToUpperInvariant(), value.Length, value);
            }
            return sb.Append("<EOR>").ToString();
        }

        // Usa la fine del QSO come data/ora del QSO, se c'è TIME_OFF. Senza QSO_DATE_OFF, una fine
        // prima dell'inizio vuol dire che il QSO è passato a cavallo della mezzanotte UTC: la data di
        // fine è il giorno dopo l'inizio.
        static void UseEndTime(Dictionary<string, string> r)
        {
            string tOff = Util.Get(r, "time_off");
            if (tOff.Length < 4)
                return;
            string dateOff = Util.Get(r, "qso_date_off");
            if (dateOff.Length != 8)
            {
                string tOn = Util.Get(r, "time_on");
                DateTime day;
                if (!DateTime.TryParseExact(Util.Get(r, "qso_date"), "yyyyMMdd", Inv, DateTimeStyles.None, out day))
                    return;
                if (tOn.Length >= 4 && string.CompareOrdinal(tOff.PadRight(6, '0'), tOn.PadRight(6, '0')) < 0)
                    day = day.AddDays(1);
                dateOff = day.ToString("yyyyMMdd", Inv);
            }
            r["qso_date"] = r["qso_date_off"] = dateOff;
            r["time_on"] = tOff;
        }

        // Pulisce un record per Club Log. Restituisce null e l'errore se il QSO non è valido.
        public static Dictionary<string, string> Normalize(Dictionary<string, string> rec, bool includeFreq, out string error)
        {
            var r = new Dictionary<string, string>();
            foreach (var kv in rec)
            {
                string v = kv.Value == null ? "" : kv.Value.Trim();
                if (v.Length > 0)
                    r[kv.Key.ToLowerInvariant()] = v;
            }
            r["call"] = Util.Get(r, "call").ToUpperInvariant();
            foreach (string key in new[] { "station_callsign", "operator", "gridsquare", "my_gridsquare" })
                if (r.ContainsKey(key))
                    r[key] = r[key].ToUpperInvariant();

            foreach (string key in new[] { "qso_date", "qso_date_off" })
                if (r.ContainsKey(key))
                    r[key] = NonDigit.Replace(r[key], "");
            foreach (string key in new[] { "time_on", "time_off" })
                if (r.ContainsKey(key))
                    r[key] = Util.Slice(NonDigit.Replace(r[key], ""), 0, 6);
            UseEndTime(r);

            double freq = 0;
            bool hasFreq = Util.Get(r, "freq").Length > 0 && TryFloat(r["freq"], out freq);
            if (Util.Get(r, "band").Length == 0 && hasFreq && freq != 0)
                r["band"] = FreqToBand(freq);
            if (Util.Get(r, "band").Length > 0)
                r["band"] = r["band"].ToLowerInvariant();
            double freqRx;
            if (Util.Get(r, "freq_rx").Length > 0 && Util.Get(r, "band_rx").Length == 0 && TryFloat(r["freq_rx"], out freqRx))
                r["band_rx"] = FreqToBand(freqRx);

            string mode = Util.Get(r, "mode").ToUpperInvariant();
            if (MfskSubmodes.Contains(mode))
            {
                r["mode"] = "MFSK";
                r["submode"] = mode;
            }
            else if (SsbSubmodes.Contains(mode))
            {
                r["mode"] = "SSB";
                r["submode"] = mode;
            }
            else if (mode.Length > 0)
                r["mode"] = mode;

            if (!includeFreq)
            {
                r.Remove("freq");
                r.Remove("freq_rx");
            }

            var missing = new[] { "call", "qso_date", "time_on", "band", "mode" }.Where(k => Util.Get(r, k).Length == 0).ToList();
            if (missing.Count > 0)
            {
                error = "campi mancanti: " + string.Join(", ", missing);
                return null;
            }
            if (r["qso_date"].Length != 8 || r["time_on"].Length < 4)
            {
                error = string.Format("data/ora non valida ({0} {1})", r["qso_date"], r["time_on"]);
                return null;
            }
            error = null;
            return r;
        }

        public static string Describe(Dictionary<string, string> rec)
        {
            string mode = Util.Get(rec, "submode");
            if (mode.Length == 0)
                mode = Util.Get(rec, "mode");
            string d = Util.Get(rec, "qso_date"), t = Util.Get(rec, "time_on");
            string call = rec.ContainsKey("call") ? rec["call"] : "?";
            string band = rec.ContainsKey("band") ? rec["band"] : "?";
            return string.Format("{0}  {1} {2}  {3}-{4}-{5} {6}:{7}Z", call, band, mode,
                Util.Slice(d, 0, 4), Util.Slice(d, 4, 6), Util.Slice(d, 6, 8), Util.Slice(t, 0, 2), Util.Slice(t, 2, 4));
        }

        // Rappresentazione di un record grezzo nei messaggi di errore, come un dict Python
        public static string Repr(Dictionary<string, string> rec)
        {
            return "{" + string.Join(", ", rec.Select(kv => "'" + kv.Key + "': '" + kv.Value + "'")) + "}";
        }

        // Filtra i record di un log pregresso: tiene solo quelli con STATION_CALLSIGN
        // uguale al nominativo della spedizione (ed eventualmente nell'intervallo di date).
        public static ImportResult AnalyzeImport(List<Dictionary<string, string>> records, string callsign, bool includeFreq,
                                                 bool includeMissing, string dateFrom, string dateTo)
        {
            callsign = callsign.Trim().ToUpperInvariant();
            var res = new ImportResult();
            res.Total = records.Count;
            foreach (var raw in records)
            {
                string station = Util.Get(raw, "station_callsign").Trim().ToUpperInvariant();
                if (station.Length == 0)
                {
                    res.Missing++;
                    if (!includeMissing)
                        continue;
                }
                else if (station != callsign)
                {
                    int n;
                    res.Others.TryGetValue(station, out n);
                    res.Others[station] = n + 1;
                    continue;
                }
                string err;
                var rec = Normalize(raw, includeFreq, out err);
                if (rec == null)
                {
                    res.Invalid++;
                    continue;
                }
                if (dateFrom.Length > 0 && string.CompareOrdinal(rec["qso_date"], dateFrom) < 0 ||
                    dateTo.Length > 0 && string.CompareOrdinal(rec["qso_date"], dateTo) > 0)
                {
                    res.OutOfRange++;
                    continue;
                }
                rec["station_callsign"] = callsign;
                res.Selected.Add(rec);
                string stamp = rec["qso_date"] + rec["time_on"];
                if (res.First.Length == 0 || string.CompareOrdinal(stamp, res.First) < 0)
                    res.First = stamp;
                if (res.Last.Length == 0 || string.CompareOrdinal(stamp, res.Last) > 0)
                    res.Last = stamp;
            }
            return res;
        }

        // Salva i QSO filtrati in caricamenti_in_attesa: il thread di invio li manda a Club Log.
        public static string CreateImportJob(List<Dictionary<string, string>> records, string sourcePath)
        {
            Directory.CreateDirectory(App.JobsDir);
            string name = BadFileChars.Replace(Path.GetFileNameWithoutExtension(sourcePath), "_");
            string path = Path.Combine(App.JobsDir, DateTime.Now.ToString("yyyyMMdd-HHmmss", Inv) + "_" +
                                       Util.Slice(name, 0, 40) + ".adi");
            string text = string.Format("Log importato da {0}\r\n<ADIF_VER:5>3.1.4<PROGRAMID:{1}>{2}<EOH>\r\n{3}\r\n",
                Path.GetFileName(sourcePath), App.Name.Length, App.Name, string.Join("\r\n", records.Select(Build)));
            // estensione diversa: il thread di invio non lo vede finché non è completo
            Util.WriteAtomic(path, text, path + ".tmp");
            return path;
        }
    }
}
