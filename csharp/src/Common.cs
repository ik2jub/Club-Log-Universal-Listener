// Club Log Universal Listener - versione C# per .NET Framework 4.8 (incluso in Windows 10/11).
// Costanti, percorsi dei file, cifratura delle credenziali, API key integrata e JSON.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

// Senza questo attributo il runtime tratta il programma come scritto per .NET 4.0 (es. TLS vecchi)
[assembly: System.Runtime.Versioning.TargetFramework(".NETFramework,Version=v4.8", FrameworkDisplayName = ".NET Framework 4.8")]
[assembly: AssemblyTitle("Club Log Universal Listener")]
[assembly: AssemblyProduct("Club Log Universal Listener")]
[assembly: AssemblyCopyright("Copyright (c) 2026 IK2JUB - MIT")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

namespace ClubLogListener
{
    static class App
    {
        public const string Name = "Club Log Universal Listener";
        public const string Version = "1.0";
        public static string RealtimeUrl = "https://clublog.org/realtime.php";
        public static string PutlogsUrl = "https://clublog.org/putlogs.php";
        public static string DeleteUrl = "https://clublog.org/delete.php";
        public static string GetAdifUrl = "https://clublog.org/getadif.php";

        public static string BaseDir, ConfigFile, QueueFile, BackupAdif, RejectedAdif, DeletedAdif, JobsDir, JobsDoneDir, StateFile;
        // Log intero scaricato da Club Log; copie di wsjtx_log.adi; file ADIF da importare in MSHV
        public static string ClubLogAdif, ProgramLogCopiesDir, MshvImportDir;
        public const int DownloadMinIntervalS = 300;  // tra due download del log intero: niente richieste ravvicinate

        public const int DedupWindowS = 30 * 60;
        public const int HoldQsoLoggedS = 3;  // attesa del Logged ADIF dopo un QSO Logged di WSJT-X/JTDX
        public const int AliveEveryS = 60;    // ogni quanto si salva l'ultimo momento in ascolto (copre spegnimenti e crash)
        public const int GapMarginS = 300;    // margine prima dell'ultimo momento in ascolto: i doppioni vengono scartati
        // Club Log non pubblica limiti numerici: chiede un ritmo "normale" per realtime.php,
        // putlogs.php per gli arretrati e nessun invio a blocchi ripetuto e ravvicinato.
        public const int DefaultIntervalS = 5;        // pausa minima tra due QSO inviati con realtime.php
        public const int DefaultBatchThreshold = 20;  // da quanti QSO in coda si passa all'invio a blocchi (0 = mai)
        public const int BatchMinIntervalS = 300;     // pausa minima tra due invii a blocchi
        public const int BatchMaxQso = 5000;
        // Errori temporanei del server per cui realtime.php viene ritentato più tardi;
        // per ogni altro codice diverso da 200 gli invii si fermano
        public static readonly int[] RetryableHttp = { 500, 502, 503, 504 };

        static App()
        {
            SetBaseDir(AppDomain.CurrentDomain.BaseDirectory);
        }

        public static void SetBaseDir(string dir)
        {
            BaseDir = Path.GetFullPath(dir).TrimEnd('\\');
            ConfigFile = Path.Combine(BaseDir, "clublog_listener.json");
            QueueFile = Path.Combine(BaseDir, "clublog_listener_coda.json");
            BackupAdif = Path.Combine(BaseDir, "qso_ricevuti.adi");
            RejectedAdif = Path.Combine(BaseDir, "qso_rifiutati.adi");
            DeletedAdif = Path.Combine(BaseDir, "qso_cancellati.adi");
            ClubLogAdif = Path.Combine(BaseDir, "log_clublog.adi");
            ProgramLogCopiesDir = Path.Combine(BaseDir, "copie_log_programmi");
            MshvImportDir = Path.Combine(BaseDir, "da_importare_in_MSHV");
            // File ADIF importati: restano qui finché Club Log non li accetta, poi vengono spostati
            JobsDir = Path.Combine(BaseDir, "caricamenti_in_attesa");
            JobsDoneDir = Path.Combine(BaseDir, "caricamenti_inviati");
            // Ultimo momento in cui ogni programma era in ascolto: al riavvio si cercano nel suo log i
            // QSO registrati nel frattempo
            StateFile = Path.Combine(BaseDir, "clublog_listener_stato.json");
        }

        // Programmi e porte di default. JTDX e MSHV usano di default la 2237 come
        // WSJT-X: qui si propongono porte diverse per farli convivere.
        public static List<ListenerSettings> DefaultListeners()
        {
            return new List<ListenerSettings> {
                new ListenerSettings("DXLog", true, "0.0.0.0", "12061", ""),
                new ListenerSettings("QARTest", true, "0.0.0.0", "12060", ""),
                new ListenerSettings("WSJT-X", true, "0.0.0.0", "2237", ""),
                new ListenerSettings("JTDX", true, "0.0.0.0", "2238", ""),
                new ListenerSettings("MSHV", true, "0.0.0.0", "2239", ""),
            };
        }
    }

    static class Util
    {
        static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        // Secondi dal 1970, come time.time() in Python
        public static double Now()
        {
            return (DateTime.UtcNow - Epoch).TotalSeconds;
        }

        public static string Slice(string s, int start, int end)
        {
            if (s == null || start >= s.Length)
                return "";
            return s.Substring(start, Math.Min(end, s.Length) - start);
        }

        public static string Get(Dictionary<string, string> d, string key)
        {
            string v;
            return d.TryGetValue(key, out v) && v != null ? v : "";
        }

        // Come os.replace: sostituisce la destinazione se esiste già
        public static void ReplaceFile(string src, string dst)
        {
            if (File.Exists(dst))
                File.Replace(src, dst, null, true);
            else
                File.Move(src, dst);
        }

        // Scrittura atomica e forzata su disco: il file sopravvive a crash e mancanza di corrente
        public static void WriteAtomic(string path, string text, string tmp)
        {
            using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                byte[] data = new UTF8Encoding(false).GetBytes(text);
                fs.Write(data, 0, data.Length);
                fs.Flush(true);
            }
            ReplaceFile(tmp, path);
        }

        public static void AppendText(string path, string header, string text)
        {
            using (var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read))
            {
                byte[] data = new UTF8Encoding(false).GetBytes((fs.Length == 0 ? header : "") + text);
                fs.Write(data, 0, data.Length);
            }
        }
    }

    // Cifratura credenziali (DPAPI di Windows, legata all'utente corrente).
    // Formato "dpapi:<base64>" compatibile con la versione Python.
    static class Secrets
    {
        public static string Protect(string text)
        {
            if (string.IsNullOrEmpty(text))
                return "";
            byte[] enc = ProtectedData.Protect(Encoding.UTF8.GetBytes(text), null, DataProtectionScope.CurrentUser);
            return "dpapi:" + Convert.ToBase64String(enc);
        }

        public static string Unprotect(string value)
        {
            if (string.IsNullOrEmpty(value))
                return "";
            try
            {
                if (value.StartsWith("dpapi:", StringComparison.Ordinal))
                    return Encoding.UTF8.GetString(ProtectedData.Unprotect(
                        Convert.FromBase64String(value.Substring(6)), null, DataProtectionScope.CurrentUser));
                if (value.StartsWith("plain:", StringComparison.Ordinal))
                    return value.Substring(6);
            }
            catch (Exception)
            {
            }
            return "";
        }
    }

    // API key integrata (facoltativa).
    // Il codice pubblico non contiene nessuna chiave. Chi vuole una versione con la chiave
    // integrata esegue compila_con_chiave.bat, che crea chiave_api.cs (escluso da git) e lo
    // compila insieme al programma. L'offuscamento evita solo la lettura a colpo d'occhio:
    // non è una protezione crittografica, perciò l'eseguibile va distribuito solo all'interno
    // del gruppo. Stesso formato di chiave_api.py della versione Python.
    static class BuiltinKey
    {
        static readonly byte[] Salt = Encoding.ASCII.GetBytes("ClubLogUniversalListener");
        public static readonly string ApiKey = Load();

        static byte[] Mix(byte[] data)
        {
            var res = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
                res[i] = (byte)(data[i] ^ Salt[i % Salt.Length] ^ (i * 7 & 0xFF));
            return res;
        }

        public static string Obfuscate(string key)
        {
            char[] chars = Convert.ToBase64String(Mix(Encoding.UTF8.GetBytes(key))).ToCharArray();
            Array.Reverse(chars);
            return new string(chars);
        }

        public static string Reveal(string value)
        {
            char[] chars = value.ToCharArray();
            Array.Reverse(chars);
            return new UTF8Encoding(false, true).GetString(Mix(Convert.FromBase64String(new string(chars))));
        }

        static string Load()
        {
#if CHIAVE_API
            try
            {
                return Reveal(ChiaveApi.CHIAVE).Trim();
            }
            catch (Exception)
            {
                return "";
            }
#else
            return "";
#endif
        }
    }

    // JSON: lettura con JavaScriptSerializer, scrittura indentata come json.dump di Python
    static class Json
    {
        public static object Parse(string text)
        {
            var ser = new JavaScriptSerializer();
            ser.MaxJsonLength = int.MaxValue;
            return ser.DeserializeObject(text);
        }

        public static string Write(object value, int indent)
        {
            var sb = new StringBuilder();
            WriteValue(sb, value, indent, 0);
            return sb.ToString();
        }

        static void WriteValue(StringBuilder sb, object v, int indent, int level)
        {
            if (v == null)
                sb.Append("null");
            else if (v is string)
                WriteString(sb, (string)v);
            else if (v is bool)
                sb.Append((bool)v ? "true" : "false");
            else if (v is int || v is long || v is decimal)
                sb.Append(Convert.ToString(v, CultureInfo.InvariantCulture));
            else if (v is double)
                sb.Append(((double)v).ToString("R", CultureInfo.InvariantCulture));
            else if (v is IDictionary)
            {
                var d = (IDictionary)v;
                if (d.Count == 0)
                {
                    sb.Append("{}");
                    return;
                }
                sb.Append("{");
                bool first = true;
                foreach (DictionaryEntry e in d)
                {
                    sb.Append(first ? "\n" : ",\n").Append(' ', indent * (level + 1));
                    WriteString(sb, Convert.ToString(e.Key, CultureInfo.InvariantCulture));
                    sb.Append(": ");
                    WriteValue(sb, e.Value, indent, level + 1);
                    first = false;
                }
                sb.Append("\n").Append(' ', indent * level).Append("}");
            }
            else if (v is IEnumerable)
            {
                var items = new List<object>();
                foreach (object o in (IEnumerable)v)
                    items.Add(o);
                if (items.Count == 0)
                {
                    sb.Append("[]");
                    return;
                }
                sb.Append("[");
                for (int i = 0; i < items.Count; i++)
                {
                    sb.Append(i == 0 ? "\n" : ",\n").Append(' ', indent * (level + 1));
                    WriteValue(sb, items[i], indent, level + 1);
                }
                sb.Append("\n").Append(' ', indent * level).Append("]");
            }
            else
                WriteString(sb, Convert.ToString(v, CultureInfo.InvariantCulture));
        }

        static void WriteString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    default:
                        if (c < 0x20 || c > 0x7F)
                            sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else
                            sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }

        public static string GetString(IDictionary<string, object> d, string key, string def)
        {
            object v;
            if (d == null || !d.TryGetValue(key, out v) || v == null)
                return def;
            return Convert.ToString(v, CultureInfo.InvariantCulture);
        }

        public static bool GetBool(IDictionary<string, object> d, string key, bool def)
        {
            object v;
            if (d == null || !d.TryGetValue(key, out v) || v == null)
                return def;
            if (v is bool)
                return (bool)v;
            if (v is string)
                return ((string)v).Length > 0;
            try
            {
                return Convert.ToDecimal(v, CultureInfo.InvariantCulture) != 0;
            }
            catch (Exception)
            {
                return def;
            }
        }

        public static int GetInt(IDictionary<string, object> d, string key, int def)
        {
            int n;
            return int.TryParse(GetString(d, key, ""), NumberStyles.Integer, CultureInfo.InvariantCulture, out n) ? n : def;
        }
    }
}
