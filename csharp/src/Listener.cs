// Thread di ascolto UDP: uno per ogni porta attiva.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace ClubLogListener
{
    // Messaggio dai thread alla GUI: "log" (Level, Text), "lstatus" (Index, Text, Level), "tray" (Text)
    sealed class UiEvent
    {
        public string Kind, Level, Text;
        public int Index;

        public static UiEvent Log(string level, string text)
        {
            var e = new UiEvent();
            e.Kind = "log";
            e.Level = level;
            e.Text = text;
            return e;
        }
    }

    sealed class ListenerConfig
    {
        public string Name, Ip, Mcast;
        public int Port;
    }

    delegate void QsoHandler(Dictionary<string, string> rec, string program, string proto, string sender);

    sealed class Listener
    {
        sealed class Held
        {
            public double Due;
            public string Key, Proto, Ip;
            public Dictionary<string, string> Rec;
        }

        readonly int idx;
        readonly ListenerConfig cfg;
        readonly QsoHandler onQso;
        readonly Action<UiEvent> emit;
        readonly Action<string> onAlive;
        readonly Thread thread;
        volatile bool stopping;
        // QSO Logged in attesa del Logged ADIF dello stesso QSO
        List<Held> held = new List<Held>();

        public Listener(int idx, ListenerConfig cfg, QsoHandler onQso, Action<UiEvent> emit, Action<string> onAlive)
        {
            this.idx = idx;
            this.cfg = cfg;
            this.onQso = onQso;
            this.emit = emit;
            this.onAlive = onAlive ?? (name => { });
            thread = new Thread(Run);
            thread.IsBackground = true;
            thread.Name = "Listener " + cfg.Name;
        }

        public void Start() { thread.Start(); }
        public void Stop() { stopping = true; }
        public bool Join(int ms) { return thread.Join(ms); }

        void Status(string text, string level)
        {
            var e = new UiEvent();
            e.Kind = "lstatus";
            e.Index = idx;
            e.Text = text;
            e.Level = level;
            emit(e);
        }

        void Log(string level, string text)
        {
            emit(UiEvent.Log(level, "[" + cfg.Name + "] " + text));
        }

        void Run()
        {
            string ip = cfg.Ip, mcast = cfg.Mcast;
            int port = cfg.Port;
            Socket sock;
            try
            {
                sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                if (mcast.Length > 0)
                    sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                sock.Bind(new IPEndPoint(IPAddress.Parse(ip), port));
                if (mcast.Length > 0)
                    sock.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership,
                                         new MulticastOption(IPAddress.Parse(mcast), IPAddress.Parse(ip)));
                sock.ReceiveTimeout = 500;
            }
            catch (Exception e)
            {
                Status("ERRORE: " + e.Message, "err");
                Log("err", string.Format("impossibile ascoltare su {0}:{1}{2} - {3}", ip, port,
                    mcast.Length > 0 ? " (multicast " + mcast + ")" : "", e.Message));
                return;
            }
            string where = ip + ":" + port + (mcast.Length > 0 ? " + multicast " + mcast : "");
            Status("In ascolto su " + where + " - nessun pacchetto", "ok");
            Log("info", "in ascolto su " + where);
            onAlive(cfg.Name);
            double aliveAt = Util.Now();

            var buf = new byte[65535];
            while (!stopping)
            {
                ReleaseHeld(false);
                if (Util.Now() - aliveAt >= App.AliveEveryS)
                {
                    onAlive(cfg.Name);
                    aliveAt = Util.Now();
                }
                EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
                int n;
                try
                {
                    n = sock.ReceiveFrom(buf, ref remote);
                }
                catch (SocketException e)
                {
                    if (stopping)
                        break;
                    if (e.SocketErrorCode != SocketError.TimedOut)
                        Thread.Sleep(50);
                    continue;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                var data = new byte[n];
                Array.Copy(buf, data, n);
                var addr = (IPEndPoint)remote;
                string sender = addr.Address.ToString();
                string stamp = DateTime.Now.ToString("HH:mm:ss");
                Packet p;
                try
                {
                    p = Protocols.Parse(data);
                }
                catch (Exception e)
                {
                    Status(stamp + "  pacchetto non riconosciuto da " + sender, "warn");
                    Log("warn", string.Format("pacchetto non riconosciuto da {0}:{1} ({2} byte): {3}", sender, addr.Port, n, e.Message));
                    continue;
                }
                string label = p.Proto + " " + p.Msg + (p.Info.Length > 0 ? " (" + p.Info + ")" : "");
                Status(stamp + "  ultimo: " + label + " da " + sender, "ok");
                if (p.Proto == "N1MM-XML" && p.Msg == "contactdelete")
                    Log("warn", "cancellazione QSO ricevuta: va eliminato a mano su Club Log");
                string proto = p.Proto + " " + p.Msg;
                foreach (var rec in p.Records)
                {
                    string key = sender + "|" + p.Info + "|" + Util.Get(rec, "call").ToUpperInvariant();
                    if (p.Proto == "WSJT-X" && p.Msg == "QSO Logged")
                    {
                        // WSJT-X/JTDX mandano subito dopo lo stesso QSO in ADIF, che ha l'orario UTC
                        // esplicito: se arriva si usa quello (JTDX può dare un orario sbagliato qui)
                        var h = new Held();
                        h.Due = Util.Now() + App.HoldQsoLoggedS;
                        h.Key = key;
                        h.Rec = rec;
                        h.Proto = proto;
                        h.Ip = sender;
                        held.Add(h);
                        continue;
                    }
                    if (p.Proto == "WSJT-X" && p.Msg == "Logged ADIF")
                        held.RemoveAll(h => h.Key == key);
                    onQso(rec, cfg.Name, proto, sender);
                }
            }

            ReleaseHeld(true);
            onAlive(cfg.Name);
            try
            {
                sock.Close();
            }
            catch (Exception)
            {
            }
            Status("Fermo", "info");
        }

        void ReleaseHeld(bool force)
        {
            double now = Util.Now();
            var due = held.FindAll(h => force || h.Due <= now);
            if (due.Count == 0)
                return;
            held.RemoveAll(h => force || h.Due <= now);
            foreach (var h in due)
                onQso(h.Rec, cfg.Name, h.Proto, h.Ip);
        }
    }
}
