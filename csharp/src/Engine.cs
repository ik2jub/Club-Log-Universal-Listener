// Logica comune (indipendente dalla GUI) e impostazioni.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace ClubLogListener
{
    sealed class ListenerSettings
    {
        public string Name, Ip, Port, Mcast;
        public bool Enabled;

        public ListenerSettings(string name, bool enabled, string ip, string port, string mcast)
        {
            Name = name;
            Enabled = enabled;
            Ip = ip;
            Port = port;
            Mcast = mcast;
        }
    }

    sealed class Settings
    {
        public string Callsign = "", Email = "", Password = "", Api = "";
        public bool IncludeFreq = false, DryRun = false, Autostart = false, Tray = false;
        public int Interval = App.DefaultIntervalS, Batch = App.DefaultBatchThreshold;
        public List<ListenerSettings> Listeners = App.DefaultListeners();

        // Stesso file e stesso formato della versione Python
        public static Settings Load()
        {
            var cfg = new Settings();
            Dictionary<string, object> saved;
            try
            {
                saved = Json.Parse(File.ReadAllText(App.ConfigFile, Encoding.UTF8)) as Dictionary<string, object>;
            }
            catch (Exception)
            {
                return cfg;
            }
            if (saved == null)
                return cfg;
            cfg.Callsign = Json.GetString(saved, "callsign", cfg.Callsign);
            cfg.Email = Json.GetString(saved, "email", cfg.Email);
            cfg.IncludeFreq = Json.GetBool(saved, "include_freq", cfg.IncludeFreq);
            cfg.DryRun = Json.GetBool(saved, "dry_run", cfg.DryRun);
            cfg.Autostart = Json.GetBool(saved, "autostart", cfg.Autostart);
            cfg.Tray = Json.GetBool(saved, "tray", cfg.Tray);
            cfg.Interval = Json.GetInt(saved, "interval", cfg.Interval);
            cfg.Batch = Json.GetInt(saved, "batch", cfg.Batch);
            cfg.Password = Secrets.Unprotect(Json.GetString(saved, "password", ""));
            cfg.Api = Secrets.Unprotect(Json.GetString(saved, "api", ""));
            object list;
            if (saved.TryGetValue("listeners", out list) && list is object[])
            {
                foreach (object o in (object[])list)
                {
                    var d = o as Dictionary<string, object>;
                    if (d == null)
                        continue;
                    var lst = cfg.Listeners.FirstOrDefault(l => l.Name == Json.GetString(d, "name", ""));
                    if (lst == null)
                        continue;
                    lst.Enabled = Json.GetBool(d, "enabled", lst.Enabled);
                    lst.Ip = Json.GetString(d, "ip", lst.Ip);
                    lst.Port = Json.GetString(d, "port", lst.Port);
                    lst.Mcast = Json.GetString(d, "mcast", lst.Mcast);
                }
            }
            return cfg;
        }

        public void Save()
        {
            var listeners = Listeners.Select(l =>
            {
                int port;
                object p = int.TryParse(l.Port, out port) ? (object)port : l.Port;
                return (object)new Dictionary<string, object> {
                    {"name", l.Name}, {"enabled", l.Enabled}, {"ip", l.Ip}, {"port", p}, {"mcast", l.Mcast} };
            }).ToList();
            var outd = new Dictionary<string, object> {
                {"callsign", Callsign}, {"email", Email}, {"password", Secrets.Protect(Password)},
                {"api", Secrets.Protect(Api)}, {"include_freq", IncludeFreq}, {"dry_run", DryRun},
                {"autostart", Autostart}, {"tray", Tray}, {"interval", Interval}, {"batch", Batch},
                {"listeners", listeners} };
            File.WriteAllText(App.ConfigFile, Json.Write(outd, 2).Replace("\n", "\r\n"), new UTF8Encoding(false));
        }

        public Settings Copy()
        {
            var c = (Settings)MemberwiseClone();
            c.Listeners = Listeners.Select(l => new ListenerSettings(l.Name, l.Enabled, l.Ip, l.Port, l.Mcast)).ToList();
            return c;
        }
    }

    sealed class Engine
    {
        readonly Action<UiEvent> emit;
        public readonly Stats Stats = new Stats();
        public readonly Uploader Uploader;
        readonly List<Listener> listeners = new List<Listener>();
        readonly object sync = new object();
        Dictionary<string, double> seen = new Dictionary<string, double>();
        string callsign = "";
        bool includeFreq = true;
        volatile bool dryRun = true;
        readonly Dictionary<string, double> state = new Dictionary<string, double>();
        readonly Dictionary<string, string> mshvCalls = new Dictionary<string, string>();
        readonly object stateSync = new object();

        public Engine(Action<UiEvent> emit)
        {
            this.emit = emit;
            Uploader = new Uploader(emit, Stats);
            Uploader.Start();
            LogProgrammi.LoadState(state, mshvCalls);
        }

        public bool Running
        {
            get { return listeners.Count > 0; }
        }

        public void Start(Settings settings, List<KeyValuePair<int, ListenerConfig>> active)
        {
            callsign = settings.Callsign.ToUpperInvariant();
            includeFreq = settings.IncludeFreq;
            dryRun = settings.DryRun;
            Uploader.Configure(settings, settings.DryRun);
            Uploader.Resume();
            // Periodo da controllare nei log: dall'ultimo momento in ascolto a adesso
            double now = Util.Now();
            var gaps = new List<KeyValuePair<string, double?>>();
            Dictionary<string, string> callsBefore;  // nominativo di MSHV all'ultimo momento in ascolto
            lock (stateSync)
            {
                callsBefore = new Dictionary<string, string>(mshvCalls);
                foreach (var kv in active)
                {
                    if (!LogProgrammi.Programs.Contains(kv.Value.Name))
                        continue;
                    double last;
                    gaps.Add(new KeyValuePair<string, double?>(kv.Value.Name,
                        state.TryGetValue(kv.Value.Name, out last) ? (double?)last : null));
                }
            }
            foreach (var kv in active)
            {
                var lst = new Listener(kv.Key, kv.Value, HandleQso, emit, Alive);
                lst.Start();
                listeners.Add(lst);
            }
            if (gaps.Count > 0)
            {
                var t = new Thread(() => ScanLogs(gaps, now, callsBefore));
                t.IsBackground = true;
                t.Start();
            }
        }

        void Alive(string program)
        {
            var calls = new Dictionary<string, string>();
            if (program == "MSHV")
                foreach (string folder in LogProgrammi.MshvDirs())
                {
                    string path = LogProgrammi.MshvEdim(folder);  // chiave: il log che non ha il nominativo
                    string call = LogProgrammi.MshvCallsign(path);
                    if (call.Length > 0)
                        calls[path] = call;
                }
            lock (stateSync)
            {
                state[program] = Util.Now();
                foreach (var kv in calls)
                    mshvCalls[kv.Key] = kv.Value;
                try
                {
                    LogProgrammi.SaveState(state, mshvCalls);
                }
                catch (Exception e)
                {
                    emit(UiEvent.Log("warn", "impossibile salvare " + App.StateFile + ": " + e.Message));
                }
            }
        }

        static string UtcText(double t)
        {
            return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(t).ToString("yyyy-MM-dd HH:mm", Adif.Inv);
        }

        // Mette in coda i QSO registrati nei log di WSJT-X/JTDX/MSHV mentre il listener non ascoltava
        void ScanLogs(List<KeyValuePair<string, double?>> gaps, double until, Dictionary<string, string> callsBefore)
        {
            HashSet<string> known = null;
            foreach (var gap in gaps)
            {
                string program = gap.Key;
                if (gap.Value == null)
                {
                    emit(UiEvent.Log("info", string.Format("[{0}] primo avvio: da ora i QSO registrati a listener spento " +
                                                           "verranno recuperati dal log del programma", program)));
                    continue;
                }
                double last = gap.Value.Value, since = last - App.GapMarginS;
                string period = UtcText(last) + " - " + UtcText(until) + " UTC";
                var files = LogProgrammi.FindLogs(program);
                if (files.Count == 0)
                {
                    emit(UiEvent.Log("info", string.Format("[{0}] log del programma non trovato su questo PC: nessun " +
                                                           "recupero dei QSO registrati a listener spento", program)));
                    continue;
                }
                if (known == null)
                    known = ReceivedKeys();
                foreach (var file in files)
                {
                    List<Dictionary<string, string>> records;
                    try
                    {
                        records = LogProgrammi.Read(file.Key, file.Value);
                    }
                    catch (Exception e)
                    {
                        emit(UiEvent.Log("warn", string.Format("[{0}] impossibile leggere il log {1}: {2}", program, file.Key, e.Message)));
                        continue;
                    }
                    var pending = new List<KeyValuePair<Dictionary<string, string>, Dictionary<string, string>>>();
                    foreach (var raw in records)
                    {
                        double? t = LogProgrammi.Timestamp(raw);
                        if (t == null || t.Value < since || t.Value > until)
                            continue;
                        string err;
                        var rec = Adif.Normalize(raw, includeFreq, out err);
                        if (rec != null && known.Contains(LogProgrammi.Key(rec)))
                            continue;  // già ricevuto via UDP prima dello spegnimento
                        pending.Add(new KeyValuePair<Dictionary<string, string>, Dictionary<string, string>>(raw, rec));
                    }
                    int found = pending.Count;
                    // Il log di MSHV non ha il nominativo di ogni QSO: se in MSHV è stato cambiato mentre il
                    // listener non ascoltava, non si sa con quale nominativo è stato fatto ciascun QSO
                    string before;
                    if (!callsBefore.TryGetValue(file.Key, out before))
                        before = "";
                    string nowCall = file.Value == "mshv" ? LogProgrammi.MshvCallsign(file.Key) : "";
                    if (found > 0 && before.Length > 0 && nowCall.Length > 0 && before != nowCall)
                    {
                        Interlocked.Increment(ref Stats.Errors);
                        emit(UiEvent.Log("err", string.Format("[{0}] nominativo cambiato in MSHV mentre il listener era spento " +
                            "({1} -> {2}): {3} QSO del periodo {4} NON recuperati, perché non si sa con quale nominativo " +
                            "sono stati fatti. Controllali in MSHV, esportali in ADIF e caricali con \"Importa log ADIF...\":",
                            program, before, nowCall, found, period)));
                        foreach (var p in pending)
                            emit(UiEvent.Log("err", "        " + (p.Value != null ? Adif.Describe(p.Value) : Adif.Repr(p.Key))));
                        continue;
                    }
                    foreach (var p in pending)
                        HandleQso(p.Key, program, "log a listener spento", file.Key);
                    if (found > 0)
                        emit(UiEvent.Log("warn", string.Format("[{0}] {1} QSO registrati a listener spento ({2}) recuperati dal log {3}",
                                                               program, found, period, file.Key)));
                    else
                        emit(UiEvent.Log("info", string.Format("[{0}] nessun QSO registrato a listener spento ({1}) nel log {2}",
                                                               program, period, file.Key)));
                }
            }
        }

        // Chiavi dei QSO già ricevuti, dalla copia qso_ricevuti.adi
        // Chiavi dei QSO già ricevuti (qso_ricevuti.adi) o cancellati a mano da Club Log
        // (qso_cancellati.adi): il recupero dai log dei programmi non li rimanda
        internal static HashSet<string> ReceivedKeys()
        {
            var keys = new HashSet<string>();
            foreach (string path in new[] { App.BackupAdif, App.DeletedAdif })
                foreach (var raw in Manuale.ReadAdifFile(path))
                {
                    string err;
                    var rec = Adif.Normalize(raw, true, out err);
                    if (rec != null)
                        keys.Add(LogProgrammi.Key(rec));
                }
            return keys;
        }

        public void Stop()
        {
            foreach (var lst in listeners)
                lst.Stop();
            foreach (var lst in listeners)
                lst.Join(2000);
            listeners.Clear();
            Uploader.Paused = true;
        }

        public void Shutdown()
        {
            Stop();
            Uploader.Stop();
            Uploader.Join(3000);
        }

        void HandleQso(Dictionary<string, string> raw, string program, string proto, string sender)
        {
            string err;
            var rec = Adif.Normalize(raw, includeFreq, out err);
            if (rec == null)
            {
                Interlocked.Increment(ref Stats.Errors);
                emit(UiEvent.Log("err", string.Format("[{0}] QSO scartato ({1}): {2}", program, err, Adif.Repr(raw))));
                return;
            }
            string station = Util.Get(rec, "station_callsign");
            if (station.Length > 0 && callsign.Length > 0 && station != callsign)
            {
                Interlocked.Increment(ref Stats.Errors);
                emit(UiEvent.Log("err", string.Format("[{0}] QSO scartato: STATION_CALLSIGN {1} diverso dal nominativo DX {2} - {3}",
                    program, station, callsign, Adif.Describe(rec))));
                return;
            }
            string key = LogProgrammi.Key(rec);
            double now = Util.Now();
            string adif;
            lock (sync)
            {
                seen = seen.Where(kv => now - kv.Value < App.DedupWindowS).ToDictionary(kv => kv.Key, kv => kv.Value);
                if (seen.ContainsKey(key))
                {
                    Interlocked.Increment(ref Stats.Dupes);
                    return;  // es. WSJT-X invia sia "QSO Logged" sia "Logged ADIF"
                }
                seen[key] = now;
                Interlocked.Increment(ref Stats.Received);
                adif = Adif.Build(rec);
                Backup(adif);
            }

            string desc = Adif.Describe(rec);
            emit(UiEvent.Log("rx", string.Format("[{0}] QSO ricevuto da {1} ({2}): {3}", program, sender, proto, desc)));
            if (dryRun)
            {
                emit(UiEvent.Log("ok", string.Format("[{0}] TEST, non inviato a Club Log: {1}", program, desc)));
                emit(UiEvent.Log("info", "        ADIF: " + adif));
                return;
            }
            Uploader.Add(adif, desc, program);
        }

        void Backup(string adif)
        {
            try
            {
                Util.AppendText(App.BackupAdif, "QSO ricevuti da " + App.Name + "\r\n<ADIF_VER:5>3.1.4<EOH>\r\n", adif + "\r\n");
            }
            catch (Exception e)
            {
                emit(UiEvent.Log("warn", "impossibile scrivere il backup ADIF: " + e.Message));
            }
        }

        // QSO inserito a mano: come uno ricevuto, senza il controllo dei doppioni ravvicinati
        // (lo fa la finestra, chiedendo conferma). Restituisce l'errore o null.
        public string AddManual(Dictionary<string, string> input, Settings s)
        {
            var raw = new Dictionary<string, string>(input);
            raw["station_callsign"] = s.Callsign;
            string err;
            var rec = Adif.Normalize(raw, true, out err);
            if (rec == null)
                return err;
            string adif = Adif.Build(rec);
            lock (sync)
            {
                seen[LogProgrammi.Key(rec)] = Util.Now();  // se arriva anche via UDP è un doppione
                Interlocked.Increment(ref Stats.Received);
                Backup(adif);
            }
            string desc = Adif.Describe(rec);
            emit(UiEvent.Log("rx", string.Format("[{0}] QSO inserito a mano: {1}", Manuale.Source, desc)));
            if (s.DryRun)
            {
                emit(UiEvent.Log("ok", string.Format("[{0}] TEST, non inviato a Club Log: {1}", Manuale.Source, desc)));
                emit(UiEvent.Log("info", "        ADIF: " + adif));
                return null;
            }
            Uploader.Add(adif, desc, Manuale.Source);
            if (!Running)
                emit(UiEvent.Log("warn", string.Format("[{0}] il QSO verrà inviato a Club Log appena avvii l'ascolto: {1}",
                    Manuale.Source, desc)));
            return null;
        }

        // Cancella da Club Log un QSO di qso_ricevuti.adi, o lo toglie dalla coda se non è ancora partito.
        // Esito: "coda", "cancellato", "test", "non trovato", "errore". Va chiamata fuori dalla GUI:
        // aspetta la risposta di Club Log.
        public string DeleteQso(Dictionary<string, string> rec, Settings s, out string msg)
        {
            string desc = Adif.Describe(rec);
            int removed = Uploader.Remove(Manuale.StoredKey(rec));
            if (removed < 0)
            {
                msg = string.Format("Il QSO {0} è in invio proprio ora: riprova tra qualche secondo.", desc);
                return "errore";
            }
            if (removed > 0)
            {
                MarkDeleted(rec);
                msg = "QSO tolto dalla coda prima dell'invio: " + desc;
                emit(UiEvent.Log("ok", string.Format("[{0}] {1}", Manuale.Source, msg)));
                return "coda";
            }
            if (s.DryRun)
            {
                msg = "TEST, non cancellato da Club Log: " + desc;
                emit(UiEvent.Log("ok", string.Format("[{0}] {1}", Manuale.Source, msg)));
                return "test";
            }
            string bandId;
            if (!Manuale.DeleteBandIds.TryGetValue(Util.Get(rec, "band").Trim().ToLowerInvariant(), out bandId))
            {
                msg = string.Format("Club Log non permette di cancellare con le API i QSO in banda {0}: " +
                    "cancella {1} dal sito di Club Log (Log Inspector).", Util.Get(rec, "band"), desc);
                return "errore";
            }
            string when = Manuale.DeleteDatetime(rec);
            // Club Log vuole data e ora esatte; se ha registrato l'ora senza i secondi va bene anche :00
            var attempts = new List<string> { when };
            if (!when.EndsWith(":00", StringComparison.Ordinal))
                attempts.Add(when.Substring(0, when.Length - 2) + "00");
            foreach (string attempt in attempts)
            {
                int code;
                string text;
                try
                {
                    code = Uploader.Delete(Util.Get(rec, "call").Trim(), attempt, bandId, s, out text);
                }
                catch (Exception e)  // rete assente, timeout, SSL...
                {
                    msg = string.Format("Cancellazione non riuscita, rete non disponibile ({0}): {1}", e.Message, desc);
                    emit(UiEvent.Log("err", string.Format("[{0}] {1}", Manuale.Source, msg)));
                    return "errore";
                }
                string shortText = Util.Slice(text.Replace("\r", " ").Replace("\n", " "), 0, 160);
                if (code != 200)
                {
                    msg = string.Format("Club Log non ha cancellato {0} (HTTP {1}: {2})", desc, code, shortText);
                    emit(UiEvent.Log("err", string.Format("[{0}] {1}", Manuale.Source, msg)));
                    return "errore";
                }
                if (!Regex.IsMatch(text, @"not\s*deleted", RegexOptions.IgnoreCase))
                {
                    MarkDeleted(rec);
                    msg = string.Format("Cancellato da Club Log: {0} ({1} UTC)  [{2}]", desc, attempt, shortText);
                    emit(UiEvent.Log("ok", string.Format("[{0}] {1}", Manuale.Source, msg)));
                    return "cancellato";
                }
            }
            msg = string.Format("Club Log non ha trovato il QSO {0} ({1} UTC): nessuna cancellazione", desc, when);
            emit(UiEvent.Log("warn", string.Format("[{0}] {1}", Manuale.Source, msg)));
            return "non trovato";
        }

        // Scarica tutto il log da Club Log (getadif.php) in log_clublog.adi. Esito "ok" o "errore".
        // Va chiamata fuori dalla GUI: aspetta la risposta di Club Log.
        public string DownloadClubLogLog(Settings s, out string msg)
        {
            if (File.Exists(App.ClubLogAdif))
            {
                double age = (DateTime.UtcNow - File.GetLastWriteTimeUtc(App.ClubLogAdif)).TotalSeconds;
                if (age >= 0 && age < App.DownloadMinIntervalS)
                {
                    msg = string.Format("Il log è stato scaricato {0} secondi fa: per non caricare Club Log con richieste " +
                        "ravvicinate si può riscaricarlo tra {1} secondi.", (int)age, App.DownloadMinIntervalS - (int)age);
                    return "errore";
                }
            }
            int code;
            string text;
            try
            {
                code = Uploader.GetAdif(s, out text);
            }
            catch (Exception e)  // rete assente, timeout, SSL...
            {
                msg = string.Format("Download non riuscito, rete non disponibile ({0})", e.Message);
                return "errore";
            }
            string shortText = Util.Slice(text.Replace("\r", " ").Replace("\n", " "), 0, 160);
            if (code != 200)
            {
                msg = string.Format("Club Log non ha dato il log (HTTP {0}: {1})", code, shortText);
                emit(UiEvent.Log("err", string.Format("[{0}] {1}", Manuale.Source, msg)));
                return "errore";
            }
            if (!Regex.IsMatch(text, "<eoh>|<eor>", RegexOptions.IgnoreCase))
            {
                msg = "Club Log non ha risposto con un log ADIF: " + shortText;
                return "errore";
            }
            int count = Adif.Parse(text).Count;
            try
            {
                Util.WriteAtomic(App.ClubLogAdif, text, App.ClubLogAdif + ".tmp");
            }
            catch (Exception e)
            {
                msg = string.Format("Impossibile salvare {0}: {1}", Path.GetFileName(App.ClubLogAdif), e.Message);
                return "errore";
            }
            msg = string.Format("Scaricato da Club Log il log di {0}: {1} QSO", s.Callsign, count);
            emit(UiEvent.Log("ok", string.Format("[{0}] {1}", Manuale.Source, msg)));
            return "ok";
        }

        // Aggiunge il QSO inserito a mano (già normalizzato) ai log scelti: etichetta e percorso
        // (vuoto = file per MSHV). Restituisce le righe di esito per la finestra.
        public List<string> AddToProgramLogs(Dictionary<string, string> rec, List<KeyValuePair<string, string>> targets)
        {
            var lines = new List<string>();
            foreach (var t in targets)
            {
                string msg, level = "ok";
                try
                {
                    if (t.Value.Length > 0)
                    {
                        Manuale.AppendToWsjtxLog(t.Value, rec);
                        msg = "aggiunto a " + t.Value + " (si vede come già collegato dopo il riavvio del programma)";
                    }
                    else
                        msg = "file da importare in MSHV: " + Manuale.WriteMshvImport(rec);
                }
                catch (Exception e)
                {
                    msg = string.Format("NON aggiunto a {0}: {1}", t.Value.Length > 0 ? t.Value : "MSHV", e.Message);
                    level = "err";
                }
                emit(UiEvent.Log(level, string.Format("[{0}] {1} {2}", Manuale.Source, t.Key, msg)));
                lines.Add(t.Key + ": " + msg);
            }
            return lines;
        }

        // Il QSO resta in qso_ricevuti.adi: così il recupero dai log dei programmi non lo rimanda
        void MarkDeleted(Dictionary<string, string> rec)
        {
            try
            {
                Util.AppendText(App.DeletedAdif, "QSO cancellati da Club Log con " + App.Name + "\r\n<ADIF_VER:5>3.1.4<EOH>\r\n",
                                Adif.Build(rec) + "\r\n");
            }
            catch (Exception e)
            {
                emit(UiEvent.Log("warn", string.Format("impossibile scrivere {0}: {1}", Path.GetFileName(App.DeletedAdif), e.Message)));
            }
        }
    }
}
