// QSO inseriti a mano e cancellazioni da Club Log: funzioni comuni alle finestre e al motore.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace ClubLogListener
{
    sealed class ReceivedQso
    {
        public Dictionary<string, string> Rec;
        public string Status;
    }

    static class Manuale
    {
        public const string Source = "Manuale";
        public static readonly string[] Modes = {
            "FT8", "FT4", "CW", "SSB", "USB", "LSB", "RTTY", "PSK31", "JT65", "JT9", "Q65",
            "MSK144", "FST4", "JS8", "FM", "AM", "SSTV" };
        // Bande che delete.php accetta (bandid); per le altre il QSO va cancellato dal sito
        public static readonly Dictionary<string, string> DeleteBandIds = new Dictionary<string, string> {
            {"160m", "160"}, {"80m", "80"}, {"60m", "60"}, {"40m", "40"}, {"30m", "30"}, {"20m", "20"},
            {"17m", "17"}, {"15m", "15"}, {"12m", "12"}, {"10m", "10"}, {"6m", "6"}, {"4m", "4"},
            {"2m", "2"}, {"70cm", "70"}, {"23cm", "23"}, {"13cm", "13"} };
        public const string StatusSent = "ricevuto";
        public const string StatusQueued = "in coda";
        public const string StatusDeleted = "cancellato";
        public const string StatusRejected = "rifiutato";
        public const string StatusClubLog = "su Club Log";  // dal log scaricato, non passato dal listener
        static readonly string[] ProgramFields = {
            "call", "mode", "submode", "rst_sent", "rst_rcvd", "qso_date", "time_on", "qso_date_off", "time_off",
            "band", "station_callsign" };

        public static string DefaultRst(string mode)
        {
            switch (mode.ToUpperInvariant())
            {
                case "CW": case "RTTY": case "PSK31": case "PSK63":
                    return "599";
                case "SSB": case "USB": case "LSB": case "FM": case "AM": case "SSTV":
                    return "59";
                default:
                    return "-10";
            }
        }

        static string G(Dictionary<string, string> rec, string key)
        {
            return Util.Get(rec, key).Trim();
        }

        // Chiave di un QSO così come è stato inviato a Club Log: data e ora al secondo, senza normalizzare
        public static string StoredKey(Dictionary<string, string> rec)
        {
            string mode = G(rec, "submode");
            if (mode.Length == 0)
                mode = G(rec, "mode");
            return string.Join("|", G(rec, "call").ToUpperInvariant(), G(rec, "qso_date"),
                Util.Slice(G(rec, "time_on").PadRight(6, '0'), 0, 6), G(rec, "band").ToLowerInvariant(), mode.ToUpperInvariant());
        }

        public static double? StoredTimestamp(Dictionary<string, string> rec)
        {
            DateTime t;
            if (!DateTime.TryParseExact(G(rec, "qso_date") + Util.Slice(G(rec, "time_on").PadRight(6, '0'), 0, 6),
                    "yyyyMMddHHmmss", Adif.Inv, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out t))
                return null;
            return (t - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
        }

        // Data e ora nel formato di delete.php: AAAA-MM-GG HH:MM:SS
        public static string DeleteDatetime(Dictionary<string, string> rec)
        {
            string d = G(rec, "qso_date"), t = G(rec, "time_on").PadRight(6, '0');
            return string.Format("{0}-{1}-{2} {3}:{4}:{5}", Util.Slice(d, 0, 4), Util.Slice(d, 4, 6), Util.Slice(d, 6, 8),
                Util.Slice(t, 0, 2), Util.Slice(t, 2, 4), Util.Slice(t, 4, 6));
        }

        // Data (AAAA-MM-GG) e ora (HH:MM o HH:MM:SS) scritte a mano. FormatException con il motivo.
        public static DateTime ParseUtcInput(string dateText, string timeText)
        {
            string d = Regex.Replace(dateText, @"\D", ""), t = Regex.Replace(timeText, @"\D", "");
            if (d.Length != 8)
                throw new FormatException("Data non valida: usa il formato AAAA-MM-GG.");
            if (t.Length != 4 && t.Length != 6)
                throw new FormatException("Ora non valida: usa il formato HH:MM o HH:MM:SS.");
            DateTime res;
            if (!DateTime.TryParseExact(d + t.PadRight(6, '0'), "yyyyMMddHHmmss", Adif.Inv, DateTimeStyles.None, out res))
                throw new FormatException("Data o ora inesistente.");
            return DateTime.SpecifyKind(res, DateTimeKind.Utc);
        }

        public static List<Dictionary<string, string>> ReadAdifFile(string path)
        {
            try
            {
                return Adif.Parse(File.ReadAllBytes(path));
            }
            catch (Exception)
            {
                return new List<Dictionary<string, string>>();
            }
        }

        // Stesso QSO in qso_ricevuti.adi e nel log scaricato da Club Log (che può scrivere il modo diversamente)
        public static string MinuteKey(Dictionary<string, string> rec)
        {
            return string.Join("|", G(rec, "call").ToUpperInvariant(), G(rec, "qso_date"), Util.Slice(G(rec, "time_on"), 0, 4),
                G(rec, "band").ToLowerInvariant());
        }

        // QSO di qso_ricevuti.adi come sono stati inviati a Club Log, in ordine di arrivo, con lo stato,
        // seguiti dai QSO del log scaricato da Club Log che non sono passati dal listener.
        // Un QSO cancellato o rifiutato più volte compare più volte nel file: ogni riga di
        // qso_cancellati.adi / qso_rifiutati.adi vale per la ricezione più vecchia, la coda per le più recenti.
        public static List<ReceivedQso> ReceivedQsos(List<string> queuedKeys)
        {
            var recs = ReadAdifFile(App.BackupAdif);
            var res = recs.Select(r => new ReceivedQso { Rec = r, Status = StatusSent }).ToList();
            var known = new HashSet<string>(recs.Select(MinuteKey));
            foreach (var r in ReadAdifFile(App.ClubLogAdif))
                if (!known.Contains(MinuteKey(r)))
                    res.Add(new ReceivedQso { Rec = r, Status = StatusClubLog });
            var keys = res.Select(e => StoredKey(e.Rec)).ToList();
            var sources = new[] {
                new { Keys = ReadAdifFile(App.DeletedAdif).Select(StoredKey).ToList(), Label = StatusDeleted, NewestFirst = false,
                      Applies = new[] { StatusSent, StatusClubLog } },
                new { Keys = ReadAdifFile(App.RejectedAdif).Select(StoredKey).ToList(), Label = StatusRejected, NewestFirst = false,
                      Applies = new[] { StatusSent } },
                new { Keys = queuedKeys, Label = StatusQueued, NewestFirst = true, Applies = new[] { StatusSent } } };
            foreach (var src in sources)
            {
                var left = new Dictionary<string, int>();
                foreach (string k in src.Keys)
                    left[k] = (left.ContainsKey(k) ? left[k] : 0) + 1;
                for (int n = 0; n < res.Count; n++)
                {
                    int i = src.NewestFirst ? res.Count - 1 - n : n;
                    int count;
                    if (src.Applies.Contains(res[i].Status) && left.TryGetValue(keys[i], out count) && count > 0)
                    {
                        res[i].Status = src.Label;
                        left[keys[i]] = count - 1;
                    }
                }
            }
            return res;
        }

        // Dove si può aggiungere un QSO inserito a mano: etichetta e percorso di wsjtx_log.adi;
        // percorso vuoto = file ADIF da importare in MSHV
        public static List<KeyValuePair<string, string>> ProgramLogTargets()
        {
            var res = new List<KeyValuePair<string, string>>();
            foreach (string program in new[] { "WSJT-X", "JTDX" })
                foreach (var f in LogProgrammi.FindLogs(program))  // es. "WSJT-X - IC7300"
                    res.Add(new KeyValuePair<string, string>(Path.GetFileName(Path.GetDirectoryName(f.Key)), f.Key));
            if (LogProgrammi.MshvDirs().Count > 0)
                res.Add(new KeyValuePair<string, string>("MSHV (file da importare)", ""));
            return res;
        }

        // Per i programmi la fine del QSO è uguale all'inizio
        static Dictionary<string, string> ProgramRecord(Dictionary<string, string> rec)
        {
            var r = new Dictionary<string, string>(rec);
            r["qso_date_off"] = Util.Get(rec, "qso_date");
            r["time_off"] = Util.Get(rec, "time_on");
            return r;
        }

        static string Field(string key, string value)
        {
            return string.Format("<{0}:{1}>{2}", key, System.Text.Encoding.UTF8.GetByteCount(value), value);
        }

        // Aggiunge il QSO in fondo a wsjtx_log.adi (WSJT-X o JTDX), nel loro formato, dopo averne salvato
        // una copia. WSJT-X e JTDX scrivono il log solo aggiungendo in fondo, come qui.
        public static string AppendToWsjtxLog(string path, Dictionary<string, string> rec)
        {
            var r = ProgramRecord(rec);
            string line = string.Join(" ", ProgramFields.Where(k => Util.Get(r, k).Length > 0).Select(k => Field(k, r[k]))) + " <eor>";
            Directory.CreateDirectory(App.ProgramLogCopiesDir);
            string copy = Path.Combine(App.ProgramLogCopiesDir,
                Regex.Replace(Path.GetFileName(Path.GetDirectoryName(path)), @"[^A-Za-z0-9_.-]", "_") + "_wsjtx_log.adi");
            File.Copy(path, copy, true);
            bool newline = true;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                if (fs.Length > 0)
                {
                    fs.Seek(-1, SeekOrigin.End);
                    newline = fs.ReadByte() == '\n';
                }
            Util.AppendText(path, "", (newline ? "" : "\r\n") + line + "\r\n");
            return copy;
        }

        public const string MshvImportNote = "In MSHV apri la finestra del log, usa \"Add ADIF To Log\" e scegli il file indicato, " +
            "una volta sola: MSHV non controlla i doppioni. Non inserire il QSO a mano in MSHV: lo trasmetterebbe via UDP " +
            "(e a Club Log, se attivo) e arriverebbe due volte. L'importazione invece non trasmette niente.";
        public const string MshvFixNote = "Se il QSO vecchio è anche nel log di MSHV, cancellalo lì: nella finestra del log " +
            "selezionalo e premi DELETE SELECTED. In alternativa correggilo direttamente con EDIT QSO, senza importare il file. " +
            "In mshvlog.adi il QSO vecchio resta (MSHV non riscrive quel file), ma il listener non lo rimanda.";

        // File ADIF con il QSO, da aggiungere al log di MSHV con il suo comando "Add ADIF To Log".
        // InvalidOperationException se MSHV non gestisce il modo (HvLogW::AddExtrnalAdif lo scarterebbe).
        public static string WriteMshvImport(Dictionary<string, string> rec)
        {
            var r = ProgramRecord(rec);
            string mode = Util.Get(r, "submode");
            if (mode.Length == 0)
                mode = Util.Get(r, "mode");  // MSHV usa FT4, Q65... come modi
            mode = mode.ToUpperInvariant();
            if (mode == "USB" || mode == "LSB")
                mode = "SSB";
            if (!LogProgrammi.MshvImportModes.Contains(mode))
                throw new InvalidOperationException("MSHV non gestisce il modo " + mode + ", file non creato");
            r["mode"] = mode;
            r.Remove("submode");
            r["band"] = Util.Get(r, "band").ToUpperInvariant();  // come in mshvlog.adi (es. 20M)
            Directory.CreateDirectory(App.MshvImportDir);
            string path = Path.Combine(App.MshvImportDir, string.Format("{0}_{1}_{2}.adi", Util.Get(r, "qso_date"),
                Util.Slice(Util.Get(r, "time_on"), 0, 4), Regex.Replace(Util.Get(r, "call"), "[^A-Za-z0-9]", "_")));
            string text = "QSO da aggiungere al log di MSHV con Add ADIF To Log\r\n" + Field("ADIF_VER", "3.1.0") +
                Field("PROGRAMID", App.Name) + "<EOH>\r\n" +
                string.Concat(ProgramFields.Where(k => Util.Get(r, k).Length > 0).Select(k => Field(k.ToUpperInvariant(), r[k]))) +
                "<EOR>\r\n";
            File.WriteAllText(path, text, new System.Text.UTF8Encoding(false));
            return path;
        }

        // QSO non cancellati con lo stesso nominativo e la stessa banda entro un'ora
        public static List<Dictionary<string, string>> NearbyQsos(List<ReceivedQso> entries, string call, string band,
                                                                 double whenTs, string excludeKey)
        {
            var res = new List<Dictionary<string, string>>();
            foreach (var e in entries)
            {
                if (e.Status == StatusDeleted || G(e.Rec, "call").ToUpperInvariant() != call ||
                    G(e.Rec, "band").ToLowerInvariant() != band || StoredKey(e.Rec) == excludeKey)
                    continue;
                double? ts = StoredTimestamp(e.Rec);
                if (ts != null && Math.Abs(ts.Value - whenTs) <= 3600)
                    res.Add(e.Rec);
            }
            return res;
        }
    }
}
