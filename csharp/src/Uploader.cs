// Thread di invio a Club Log: coda persistente, realtime.php per i singoli QSO,
// putlogs.php per gli arretrati e per i log importati.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace ClubLogListener
{
    sealed class Stats
    {
        public int Received, Sent, Dupes, Errors;
    }

    sealed class QueueItem
    {
        public string Adif, Desc, Source;
        public int Attempts;
    }

    sealed class Credentials
    {
        public string Email = "", Password = "", Callsign = "", Api = "";
    }

    sealed class Uploader
    {
        readonly Action<UiEvent> emit;
        readonly Stats stats;
        readonly object sync = new object();
        readonly List<QueueItem> items;
        public readonly AutoResetEvent Wake = new AutoResetEvent(false);
        readonly Thread thread;
        volatile bool stopping;
        public volatile bool Paused;
        public volatile bool DryRun = true;
        Credentials creds = new Credentials();
        double interval = App.DefaultIntervalS;
        int batchThreshold = App.DefaultBatchThreshold;
        public double NextTry;
        double lastBatch;
        bool batchWaitLogged;
        readonly QueueItem jobState = new QueueItem();  // tentativi falliti per i log importati

        static Uploader()
        {
            // Niente "Expect: 100-continue" (Python non lo manda) e almeno TLS 1.2 per HTTPS
            ServicePointManager.Expect100Continue = false;
            if (ServicePointManager.SecurityProtocol != SecurityProtocolType.SystemDefault)
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
        }

        public Uploader(Action<UiEvent> emit, Stats stats)
        {
            this.emit = emit;
            this.stats = stats;
            items = Load();
            thread = new Thread(Run);
            thread.IsBackground = true;
            thread.Name = "Uploader";
        }

        public void Start() { thread.Start(); }

        void Log(string level, string text)
        {
            emit(UiEvent.Log(level, text));
        }

        List<QueueItem> Load()
        {
            string text;
            try
            {
                text = File.ReadAllText(App.QueueFile, Encoding.UTF8);
            }
            catch (FileNotFoundException)
            {
                return new List<QueueItem>();
            }
            catch (DirectoryNotFoundException)
            {
                return new List<QueueItem>();
            }
            catch (Exception e)
            {
                return SetAside(e.Message);
            }
            try
            {
                var list = Json.Parse(text) as object[];
                if (list == null)
                    throw new FormatException("contenuto non valido");
                var res = new List<QueueItem>();
                foreach (object o in list)
                {
                    var d = o as Dictionary<string, object>;
                    if (d == null || !(Json.GetString(d, "adif", "").Length > 0))
                        throw new FormatException("contenuto non valido");
                    var it = new QueueItem();
                    it.Adif = Json.GetString(d, "adif", "");
                    it.Desc = Json.GetString(d, "desc", "");
                    it.Source = Json.GetString(d, "source", "");
                    it.Attempts = Json.GetInt(d, "attempts", 0);
                    res.Add(it);
                }
                return res;
            }
            catch (Exception e)
            {
                return SetAside(e.Message);
            }
        }

        // Non sovrascrivere mai una coda illeggibile: la si mette da parte
        List<QueueItem> SetAside(string reason)
        {
            string bad = App.QueueFile + DateTime.Now.ToString(".'illeggibile'-yyyyMMdd-HHmmss");
            try
            {
                Util.ReplaceFile(App.QueueFile, bad);
            }
            catch (Exception)
            {
            }
            Log("err", string.Format("coda illeggibile ({0}), salvata come {1}. I QSO sono comunque in {2}.",
                reason, Path.GetFileName(bad), Path.GetFileName(App.BackupAdif)));
            return new List<QueueItem>();
        }

        // Da chiamare con sync bloccato
        void Save()
        {
            var list = items.Select(i => (object)new Dictionary<string, object> {
                {"adif", i.Adif}, {"desc", i.Desc}, {"source", i.Source}, {"attempts", i.Attempts} }).ToList();
            try
            {
                Util.WriteAtomic(App.QueueFile, Json.Write(list, 1).Replace("\n", "\r\n"), App.QueueFile + ".tmp");
            }
            catch (Exception e)
            {
                Log("err", "impossibile salvare la coda: " + e.Message);
            }
        }

        public int Pending()
        {
            lock (sync)
                return items.Count;
        }

        public void Configure(Settings s, bool dryRun)
        {
            var c = new Credentials();
            c.Email = s.Email;
            c.Password = s.Password;
            c.Callsign = s.Callsign;
            c.Api = s.Api;
            creds = c;
            DryRun = dryRun;
            interval = Math.Max(1.0, s.Interval);
            batchThreshold = s.Batch;
        }

        public void Add(string adif, string desc, string source)
        {
            lock (sync)
            {
                var it = new QueueItem();
                it.Adif = adif;
                it.Desc = desc;
                it.Source = source;
                items.Add(it);
                Save();
            }
            Wake.Set();
        }

        public void Resume()
        {
            Paused = false;
            NextTry = 0;
            Wake.Set();
        }

        public void Stop()
        {
            stopping = true;
            Wake.Set();
        }

        public bool Join(int ms) { return thread.Join(ms); }

        void DropFirst()
        {
            lock (sync)
            {
                if (items.Count > 0)
                    items.RemoveAt(0);
                Save();
            }
        }

        // Codifica application/x-www-form-urlencoded, uguale a urllib.parse.urlencode
        static string FormEncode(string s)
        {
            var sb = new StringBuilder();
            foreach (byte b in Encoding.UTF8.GetBytes(s))
            {
                char c = (char)b;
                if (c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || "_.-~".IndexOf(c) >= 0)
                    sb.Append(c);
                else if (c == ' ')
                    sb.Append('+');
                else
                    sb.Append('%').Append(b.ToString("X2"));
            }
            return sb.ToString();
        }

        KeyValuePair<string, string>[] CredFields()
        {
            Credentials c = creds;
            return new[] {
                new KeyValuePair<string, string>("email", c.Email),
                new KeyValuePair<string, string>("password", c.Password),
                new KeyValuePair<string, string>("callsign", c.Callsign),
                new KeyValuePair<string, string>("api", c.Api) };
        }

        static int Http(string url, byte[] body, string contentType, int timeoutS, out string text)
        {
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "POST";
            req.ContentType = contentType;
            req.UserAgent = App.Name.Replace(" ", "") + "/" + App.Version;
            req.Timeout = timeoutS * 1000;
            req.ReadWriteTimeout = timeoutS * 1000;
            req.ContentLength = body.Length;
            using (Stream s = req.GetRequestStream())
                s.Write(body, 0, body.Length);
            HttpWebResponse resp;
            try
            {
                resp = (HttpWebResponse)req.GetResponse();
            }
            catch (WebException e)
            {
                resp = e.Response as HttpWebResponse;
                if (resp == null)
                    throw;
            }
            using (resp)
            using (var reader = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
            {
                text = reader.ReadToEnd().Trim();
                return (int)resp.StatusCode;
            }
        }

        // Un solo QSO con realtime.php
        int Post(string adif, out string text)
        {
            var fields = CredFields().Concat(new[] { new KeyValuePair<string, string>("adif", adif) });
            string body = string.Join("&", fields.Select(kv => FormEncode(kv.Key) + "=" + FormEncode(kv.Value)));
            return Http(App.RealtimeUrl, Encoding.ASCII.GetBytes(body), "application/x-www-form-urlencoded", 20, out text);
        }

        // Un file ADIF con molti QSO con putlogs.php (clear=0: unisce, non cancella il log)
        int PostBatch(string adifFile, string filename, out string text)
        {
            string boundary = "----ClubLogListener" + (long)(Util.Now() * 1000);
            var sb = new StringBuilder();
            foreach (var kv in CredFields().Concat(new[] { new KeyValuePair<string, string>("clear", "0") }))
                sb.AppendFormat("--{0}\r\nContent-Disposition: form-data; name=\"{1}\"\r\n\r\n{2}\r\n", boundary, kv.Key, kv.Value);
            sb.AppendFormat("--{0}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{1}\"\r\n" +
                            "Content-Type: application/octet-stream\r\n\r\n", boundary, filename);
            sb.Append(adifFile).AppendFormat("\r\n--{0}--\r\n", boundary);
            return Http(App.PutlogsUrl, new UTF8Encoding(false).GetBytes(sb.ToString()),
                        "multipart/form-data; boundary=" + boundary, 120, out text);
        }

        void RetryLater(QueueItem item, string reason)
        {
            item.Attempts++;
            int delay = Math.Min(300, 5 * (1 << Math.Min(item.Attempts, 6)));
            lock (sync)
                Save();
            Log("warn", string.Format("{0} - nuovo tentativo tra {1} s ({2} QSO in coda, salvati su disco)",
                reason, delay, Pending()));
            NextTry = Util.Now() + delay;
        }

        // Club Log chiede di fermarsi dopo un 403 o un errore inatteso, altrimenti blocca l'IP
        void Pause(string reason)
        {
            Paused = true;
            Interlocked.Increment(ref stats.Errors);
            Log("err", reason + ". Invio in pausa: verifica e premi 'Riprova coda'. I QSO restano in coda su disco.");
        }

        public static List<string> PendingJobs()
        {
            try
            {
                var names = Directory.GetFiles(App.JobsDir).Select(Path.GetFileName)
                    .Where(f => f.EndsWith(".adi", StringComparison.OrdinalIgnoreCase)).ToList();
                names.Sort(StringComparer.Ordinal);
                return names;
            }
            catch (Exception)
            {
                return new List<string>();
            }
        }

        static string Short(string text)
        {
            return Util.Slice(text.Replace("\r", " ").Replace("\n", " "), 0, 160);
        }

        void Run()
        {
            while (!stopping)
            {
                try
                {
                    Step();
                }
                catch (Exception e)  // il thread non deve mai morire
                {
                    Log("err", "errore interno nell'invio: " + e.Message);
                    Wake.WaitOne(1000);
                }
            }
        }

        void Step()
        {
            int pending;
            QueueItem item;
            lock (sync)
            {
                pending = items.Count;
                item = pending > 0 ? items[0] : null;
            }
            var jobs = PendingJobs();
            double now = Util.Now();
            // In modalità TEST la coda e i file importati restano intatti
            bool idle = (item == null && jobs.Count == 0) || Paused || DryRun;
            if (idle || now < NextTry)
            {
                double wait = idle ? 1.0 : Math.Min(1.0, Math.Max(0.1, NextTry - now));
                Wake.WaitOne((int)(wait * 1000));
                return;
            }
            bool batchDue = item != null && 0 < batchThreshold && batchThreshold <= pending;
            if (jobs.Count > 0 || batchDue)
            {
                double wait = lastBatch + App.BatchMinIntervalS - now;
                if (wait > 0)
                {
                    if (item != null && !batchDue)
                    {
                        SendOne(item);  // il tempo reale continua mentre il file aspetta
                        return;
                    }
                    if (!batchWaitLogged)
                    {
                        Log("info", string.Format("Prossimo invio a blocchi tra {0} s " +
                            "(Club Log non vuole invii a blocchi ravvicinati).", (int)wait));
                        batchWaitLogged = true;
                    }
                    NextTry = now + wait;
                    return;
                }
                if (jobs.Count > 0)
                    SendJob(Path.Combine(App.JobsDir, jobs[0]));
                else
                    SendBatch(item);
            }
            else
                SendOne(item);
        }

        void SendJob(string path)
        {
            string name = Path.GetFileName(path);
            byte[] data;
            try
            {
                data = File.ReadAllBytes(path);
            }
            catch (Exception e)
            {
                Pause(string.Format("impossibile leggere il file da caricare {0}: {1}", name, e.Message));
                return;
            }
            int count = Regex.Matches(Encoding.GetEncoding(28591).GetString(data), "<EOR>", RegexOptions.IgnoreCase).Count;
            Log("info", string.Format("Invio del log importato {0} ({1} QSO) con putlogs.php...", name, count));
            int code;
            string text;
            try
            {
                code = PostBatch(Encoding.UTF8.GetString(data), name, out text);
            }
            catch (Exception e)  // rete assente, timeout, SSL...
            {
                RetryLater(jobState, string.Format("rete non disponibile ({0}) per il file {1}", e.Message, name));
                return;
            }
            lastBatch = Util.Now();
            batchWaitLogged = false;
            string shortText = Short(text);
            if (code == 200)
            {
                jobState.Attempts = 0;
                try
                {
                    Directory.CreateDirectory(App.JobsDoneDir);
                    Util.ReplaceFile(path, Path.Combine(App.JobsDoneDir, name));
                }
                catch (Exception e)
                {
                    // Se il file restasse in attesa verrebbe reinviato: meglio fermarsi
                    Pause(string.Format("file {0} accettato ma impossibile spostarlo ({1})", name, e.Message));
                }
                Interlocked.Add(ref stats.Sent, count);
                Log("ok", string.Format("Club Log ha accettato il log importato {0} ({1} QSO), unito al log " +
                    "esistente: lo elabora entro circa un minuto [{2}]", name, count, shortText));
                NextTry = Util.Now() + interval;
            }
            else
                Pause(string.Format("Club Log ha rifiutato il log importato {0} (HTTP {1}: {2})", name, code, shortText));
        }

        void SendBatch(QueueItem first)
        {
            List<QueueItem> batch;
            lock (sync)
                batch = items.Take(App.BatchMaxQso).ToList();
            string adifFile = string.Format("Coda di {0}\n<ADIF_VER:5>3.1.4<PROGRAMID:{1}>{0}<EOH>\n{2}\n",
                App.Name, App.Name.Length, string.Join("\n", batch.Select(i => i.Adif)));
            Log("info", string.Format("Invio a blocchi di {0} QSO in coda (putlogs.php)...", batch.Count));
            int code;
            string text;
            try
            {
                code = PostBatch(adifFile, "coda.adi", out text);
            }
            catch (Exception e)  // rete assente, timeout, SSL...
            {
                RetryLater(first, "rete non disponibile (" + e.Message + ")");
                return;
            }
            lastBatch = Util.Now();
            batchWaitLogged = false;
            string shortText = Short(text);
            if (code == 200)
            {
                lock (sync)
                {
                    items.RemoveRange(0, Math.Min(batch.Count, items.Count));
                    Save();
                }
                Interlocked.Add(ref stats.Sent, batch.Count);
                Log("ok", string.Format("Club Log ha accettato il blocco di {0} QSO: li elabora entro circa un minuto [{1}]",
                    batch.Count, shortText));
                NextTry = Util.Now() + interval;
            }
            else
                Pause(string.Format("Club Log ha rifiutato l'invio a blocchi (HTTP {0}: {1})", code, shortText));
        }

        void SendOne(QueueItem item)
        {
            int code;
            string text;
            try
            {
                code = Post(item.Adif, out text);
            }
            catch (Exception e)  // rete assente, timeout, SSL...
            {
                RetryLater(item, string.Format("rete non disponibile ({0}): {1}", e.Message, item.Desc));
                return;
            }
            string shortText = Short(text);
            if (code == 200)  // QSO OK / QSO Duplicate / QSO Modified
            {
                Interlocked.Increment(ref stats.Sent);
                if (Regex.IsMatch(text, "dup", RegexOptions.IgnoreCase))
                    Log("ok", "Club Log: già presente (duplicato) - " + item.Desc);
                else if (Regex.IsMatch(text, "modif|updated", RegexOptions.IgnoreCase))
                    Log("warn", string.Format("Club Log ha accettato ma modificato {0}: {1}", item.Desc, shortText));
                else
                    Log("ok", string.Format("Club Log OK: {0}  [{1}]", item.Desc, shortText));
                DropFirst();
                NextTry = Util.Now() + interval;
            }
            else if (code == 403 || text.StartsWith("Login rejected", StringComparison.Ordinal))
                Pause(string.Format("Club Log ha rifiutato le credenziali (HTTP {0}: {1})", code, shortText));
            else if (code == 400)
            {
                Interlocked.Increment(ref stats.Errors);
                Log("err", string.Format("Club Log ha rifiutato il QSO {0} (HTTP 400: {1}) - salvato in {2}",
                    item.Desc, shortText, Path.GetFileName(App.RejectedAdif)));
                try
                {
                    Util.AppendText(App.RejectedAdif, "", item.Adif + "\r\n");
                }
                catch (Exception)
                {
                }
                DropFirst();
                NextTry = Util.Now() + interval;
            }
            else if (App.RetryableHttp.Contains(code))  // 500 (manutenzione) e simili: riprovare più tardi
                RetryLater(item, string.Format("Club Log ha risposto HTTP {0} ({1})", code, shortText));
            else  // qualsiasi altro codice: Club Log chiede di fermarsi
                Pause(string.Format("Club Log ha risposto HTTP {0} ({1})", code, shortText));
        }
    }
}
