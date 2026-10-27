// Log dei programmi: QSO registrati mentre il listener non ascoltava.
// WSJT-X e JTDX scrivono sempre wsjtx_log.adi nella loro cartella dati (non configurabile); con
// --rig-name=XXX la cartella è "<programma> - XXX". MSHV usa <cartella di MSHV>\log\mshvlog.edim.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace ClubLogListener
{
    static class LogProgrammi
    {
        public static readonly string[] Programs = { "WSJT-X", "JTDX", "MSHV" };

        // Codici dei modi nel log di MSHV (HvLogW::SaveEDI)
        static readonly Dictionary<string, string> MshvModes = new Dictionary<string, string> {
            {"0", "NON"}, {"1", "SSB"}, {"2", "CW"}, {"6", "FM"}, {"10", "JTMS"}, {"11", "FSK441"},
            {"12", "ISCAT-A"}, {"13", "ISCAT-B"}, {"14", "JT6M"}, {"15", "FSK315"}, {"17", "MSK144"},
            {"18", "JT65A"}, {"19", "JT65B"}, {"20", "JT65C"}, {"21", "PI4"}, {"22", "FT8"}, {"23", "MSKMS"},
            {"24", "FT4"}, {"25", "Q65A"}, {"26", "Q65B"}, {"27", "Q65C"}, {"28", "Q65D"}, {"29", "FT2"} };
        static readonly Regex MshvBand = new Regex(@"^([\d.]+)\s*([kMG])", RegexOptions.IgnoreCase);

        // Cartelle di installazione di MSHV, dalle voci di disinstallazione di Windows
        public static List<string> MshvDirs()
        {
            var dirs = new List<string>();
            var roots = new[] {
                new KeyValuePair<RegistryKey, string>(Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                new KeyValuePair<RegistryKey, string>(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                new KeyValuePair<RegistryKey, string>(Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") };
            foreach (var root in roots)
            {
                try
                {
                    using (RegistryKey key = root.Key.OpenSubKey(root.Value))
                    {
                        if (key == null)
                            continue;
                        foreach (string name in key.GetSubKeyNames())
                        {
                            using (RegistryKey sub = key.OpenSubKey(name))
                            {
                                if (sub == null)
                                    continue;
                                string display = Convert.ToString(sub.GetValue("DisplayName") ?? "");
                                string uninstall = Convert.ToString(sub.GetValue("UninstallString") ?? "").Trim().Trim('"');
                                if (!display.ToUpperInvariant().StartsWith("MSHV") || uninstall.Length == 0)
                                    continue;
                                string folder = Path.GetDirectoryName(uninstall);
                                if (!string.IsNullOrEmpty(folder) && !dirs.Any(d => string.Equals(d, folder, StringComparison.OrdinalIgnoreCase)))
                                    dirs.Add(folder);
                            }
                        }
                    }
                }
                catch (Exception)
                {
                }
            }
            return dirs;
        }

        // File di log del programma su questo PC: (percorso, tipo) con tipo "adif" o "mshv"
        public static List<KeyValuePair<string, string>> FindLogs(string program)
        {
            var found = new List<KeyValuePair<string, string>>();
            if (program == "WSJT-X" || program == "JTDX")
            {
                string baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string[] names;
                try
                {
                    names = Directory.GetDirectories(baseDir).Select(Path.GetFileName)
                                     .OrderBy(n => n, StringComparer.Ordinal).ToArray();
                }
                catch (Exception)
                {
                    names = new string[0];
                }
                foreach (string name in names)
                {
                    if (string.Equals(name, program, StringComparison.OrdinalIgnoreCase) ||
                        name.StartsWith(program + " - ", StringComparison.OrdinalIgnoreCase))
                    {
                        string path = Path.Combine(Path.Combine(baseDir, name), "wsjtx_log.adi");
                        if (File.Exists(path))
                            found.Add(new KeyValuePair<string, string>(path, "adif"));
                    }
                }
            }
            else if (program == "MSHV")
            {
                // Con "Use Save QSOs In ADIF Log" (attiva di default) MSHV aggiunge ogni QSO a mshvlog.adi con
                // il nominativo usato in quel momento: è la fonte migliore. Altrimenti si legge mshvlog.edim.
                foreach (string folder in MshvDirs())
                {
                    string adif = Path.Combine(Path.Combine(folder, "log"), "mshvlog.adi");
                    string edim = MshvEdim(folder);
                    if (MshvAdifEnabled(folder) && File.Exists(adif))
                        found.Add(new KeyValuePair<string, string>(adif, "adif"));
                    else if (File.Exists(edim))
                        found.Add(new KeyValuePair<string, string>(edim, "mshv"));
                }
            }
            return found;
        }

        public static string MshvEdim(string folder)
        {
            return Path.Combine(Path.Combine(folder, "log"), "mshvlog.edim");
        }

        // Stato di "Use Save QSOs In ADIF Log" in settings\ms_settings (se manca: attiva, come in MSHV)
        static bool MshvAdifEnabled(string folder)
        {
            try
            {
                foreach (string line in File.ReadAllLines(Path.Combine(Path.Combine(folder, "settings"), "ms_settings"), Encoding.UTF8))
                    if (line.StartsWith("def_use_adif_save="))
                        return line.Substring("def_use_adif_save=".Length).Trim() != "0";
            }
            catch (Exception)
            {
            }
            return true;
        }

        // Il log di MSHV salva la frequenza senza punto decimale: lo rimette dove la frequenza cade
        // nella banda indicata (es. 70154 con banda 70 MHz -> 70.154)
        static string MshvFreq(string digits, double mhz)
        {
            digits = digits.TrimStart('0');
            if (digits.Length == 0 || !digits.All(char.IsDigit))
                return "";
            var candidates = new List<string> { "0." + digits };
            for (int k = 1; k <= digits.Length; k++)
                candidates.Add(digits.Substring(0, k) + "." + digits.Substring(k));
            foreach (string c in candidates)
            {
                double v = double.Parse(c, CultureInfo.InvariantCulture);
                if (Math.Abs(v - mhz) <= mhz * 0.15 && Adif.FreqToBand(v).Length > 0)
                    return Adif.Mhz(v);
            }
            return "";
        }

        // Nominativo impostato in MSHV (settings\ms_macros, salvato appena si conferma la modifica)
        public static string MshvCallsign(string logPath)
        {
            try
            {
                string macros = Path.Combine(Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(logPath)), "settings"), "ms_macros");
                foreach (string line in File.ReadAllLines(macros, Encoding.UTF8))
                    if (line.StartsWith("macr_my_call="))
                        return line.Substring("macr_my_call=".Length).Trim().ToUpperInvariant();
            }
            catch (Exception)
            {
            }
            return "";
        }

        // Record ADIF dal log di MSHV (mshvlog.edim), con gli stessi campi dell'ADIF di MSHV.
        // Il log non ha il nominativo di ogni QSO: si usa quello impostato in MSHV, come fa MSHV.
        public static List<Dictionary<string, string>> ReadMshv(string path)
        {
            string mycall = MshvCallsign(path);
            var records = new List<Dictionary<string, string>>();
            bool inQsos = false;
            foreach (string line in File.ReadAllLines(path, Encoding.UTF8))
            {
                if (line.StartsWith("[END;", StringComparison.OrdinalIgnoreCase))
                    inQsos = false;
                if (inQsos && line.Length > 0)
                {
                    var p = line.Split(';').ToList();
                    while (p.Count < 29)
                        p.Add("");
                    string secOn = p[18].Length > 0 ? p[18] : "00";
                    string secOff = p[20].Length > 0 ? p[20] : secOn;
                    var rec = new Dictionary<string, string> {
                        {"call", p[4]}, {"qso_date", p[0]}, {"time_on", p[1] + secOn}, {"qso_date_off", p[2]},
                        {"time_off", p[3] + secOff}, {"rst_sent", p[6]}, {"rst_rcvd", p[7]}, {"gridsquare", p[8]} };
                    string mode;
                    if (!MshvModes.TryGetValue(p[5], out mode))
                        mode = p[5];
                    if (mode == "FT2" || mode == "FT4" || mode.StartsWith("Q65"))
                    {
                        rec["mode"] = "MFSK";
                        rec["submode"] = mode;
                    }
                    else if (mode.StartsWith("ISCAT"))
                    {
                        rec["mode"] = "ISCAT";
                        rec["submode"] = mode;
                    }
                    else if (mode.StartsWith("JT65"))
                    {
                        rec["mode"] = "JT65";
                        rec["submode"] = mode;
                    }
                    else
                        rec["mode"] = mode;
                    Match m = MshvBand.Match(p[9]);
                    if (m.Success)
                    {
                        double mhz = double.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture) *
                                     (m.Groups[2].Value.ToUpperInvariant() == "K" ? 0.001 : m.Groups[2].Value.ToUpperInvariant() == "G" ? 1000.0 : 1.0);
                        string freq = MshvFreq(p[10], mhz);
                        if (freq.Length > 0)
                        {
                            rec["freq"] = freq;
                            rec["band"] = Adif.FreqToBand(double.Parse(freq, CultureInfo.InvariantCulture));
                        }
                        else
                            rec["band"] = Adif.NearBand(mhz);
                    }
                    if (p[12].Length > 0)
                        rec["prop_mode"] = p[12];
                    if (p[22].Length > 0)
                        rec["sat_name"] = p[22];
                    if (mycall.Length > 0)
                        rec["station_callsign"] = mycall;
                    records.Add(rec);
                }
                if (line.StartsWith("[QSORecords;", StringComparison.OrdinalIgnoreCase))
                    inQsos = true;
            }
            return records;
        }

        public static List<Dictionary<string, string>> Read(string path, string kind)
        {
            return kind == "mshv" ? ReadMshv(path) : Adif.Parse(File.ReadAllBytes(path));
        }

        // Momento della registrazione del QSO (fine QSO, o inizio se manca), in secondi UTC
        public static double? Timestamp(Dictionary<string, string> raw)
        {
            var rec = raw.ToDictionary(kv => kv.Key.ToLowerInvariant(), kv => (kv.Value ?? "").Trim());
            string date = Util.Get(rec, "qso_date_off"), t = Util.Get(rec, "time_off");
            if (date.Length != 8 || t.Length < 4)
            {
                date = Util.Get(rec, "qso_date");
                t = Util.Get(rec, "time_on");
            }
            DateTime d;
            if (!DateTime.TryParseExact(date + Util.Slice(t, 0, 6).PadRight(6, '0'), "yyyyMMddHHmmss", CultureInfo.InvariantCulture,
                                        DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out d))
                return null;
            return (d - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
        }

        // Chiave dei doppioni: stesso nominativo, data, ora (al minuto), banda e modo
        public static string Key(Dictionary<string, string> rec)
        {
            string mode = Util.Get(rec, "submode");
            return string.Join("|", rec["call"], rec["qso_date"], Util.Slice(rec["time_on"], 0, 4), rec["band"],
                               mode.Length > 0 ? mode : rec["mode"]);
        }

        // Stesso file e stesso formato della versione Python: ultimo momento in ascolto per programma e
        // nominativo di MSHV in quel momento per log
        public static void LoadState(Dictionary<string, double> times, Dictionary<string, string> calls)
        {
            Dictionary<string, object> d;
            try
            {
                d = Json.Parse(File.ReadAllText(App.StateFile, Encoding.UTF8)) as Dictionary<string, object>;
            }
            catch (Exception)
            {
                return;
            }
            object o;
            if (d == null)
                return;
            try
            {
                if (d.TryGetValue("ultimo_ascolto", out o) && o is Dictionary<string, object>)
                    foreach (var kv in (Dictionary<string, object>)o)
                        times[kv.Key] = Convert.ToDouble(kv.Value, CultureInfo.InvariantCulture);
            }
            catch (Exception)
            {
                times.Clear();
            }
            if (d.TryGetValue("nominativo_mshv", out o) && o is Dictionary<string, object>)
                foreach (var kv in (Dictionary<string, object>)o)
                    calls[kv.Key] = Convert.ToString(kv.Value, CultureInfo.InvariantCulture);
        }

        public static void SaveState(Dictionary<string, double> times, Dictionary<string, string> calls)
        {
            var d = new Dictionary<string, object> {
                { "ultimo_ascolto", times.ToDictionary(kv => kv.Key, kv => (object)kv.Value) },
                { "nominativo_mshv", calls.ToDictionary(kv => kv.Key, kv => (object)kv.Value) } };
            Util.WriteAtomic(App.StateFile, Json.Write(d, 2), App.StateFile + ".tmp");
        }
    }
}
