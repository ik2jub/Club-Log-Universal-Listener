// Finestra principale.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Net.Sockets;
using System.Windows.Forms;

namespace ClubLogListener
{
    // Il programma gestisce da sé la scala dello schermo (125%, 150%...): i font crescono da soli,
    // le larghezze fisse si moltiplicano con S()
    static class Ui
    {
        public static readonly float Scale = GetScale();

        static float GetScale()
        {
            using (Graphics g = Graphics.FromHwnd(IntPtr.Zero))
                return g.DpiX / 96F;
        }

        public static int S(int v)
        {
            return (int)Math.Round(v * Scale);
        }

        public static Padding P(int left, int top, int right, int bottom)
        {
            return new Padding(S(left), S(top), S(right), S(bottom));
        }
    }

    sealed class ListenerRow
    {
        public string Name;
        public CheckBox Enabled;
        public ComboBox Ip;
        public TextBox Port, Mcast;
        public Label Status;
    }

    sealed class MainForm : Form
    {
        internal static readonly Dictionary<string, Color> Colors = new Dictionary<string, Color> {
            {"info", ColorTranslator.FromHtml("#333333")}, {"ok", ColorTranslator.FromHtml("#1a7f37")},
            {"warn", ColorTranslator.FromHtml("#b35900")}, {"err", ColorTranslator.FromHtml("#c62828")},
            {"rx", ColorTranslator.FromHtml("#0b57d0")} };
        static readonly Dictionary<string, Color> TrayColors = new Dictionary<string, Color> {
            {"info", ColorTranslator.FromHtml("#757575")}, {"ok", ColorTranslator.FromHtml("#1a7f37")},
            {"warn", ColorTranslator.FromHtml("#e08600")}, {"err", ColorTranslator.FromHtml("#c62828")} };

        readonly ConcurrentQueue<UiEvent> events = new ConcurrentQueue<UiEvent>();
        internal readonly Engine engine;
        readonly Settings cfg;
        readonly string savedApi;  // con la chiave integrata, la chiave salvata resta com'è

        internal TextBox eCall, eEmail, ePwd, eApi;
        internal CheckBox cShow, cFreq, cDry, cAuto, cTray, cBoot;
        internal NumericUpDown eInterval, eBatch;
        internal readonly List<ListenerRow> rows = new List<ListenerRow>();
        internal Button bStart, bStop, bRetry, bNew, bSearch, bImport, bFolder;
        ToolStripStatusLabel lMode, lCounters;
        internal RichTextBox txt;
        TableLayoutPanel mainPanel;
        TabControl tabs;
        readonly Timer saveTimer = new Timer();
        bool saveError;
        StatusStrip statusStrip;
        Font logFont, logFontBold;

        readonly NotifyIcon tray;
        readonly Dictionary<string, Icon> trayIcons = new Dictionary<string, Icon>();
        string trayLevel, trayTitle;
        bool trayHidden;
        readonly Timer timer = new Timer();

        public MainForm()
        {
            engine = new Engine(events.Enqueue);
            cfg = Settings.Load();
            savedApi = cfg.Api;
            foreach (var kv in TrayColors)
                trayIcons[kv.Key] = IconArt.MakeIcon(SystemInformation.SmallIconSize.Width, kv.Value);

            SuspendLayout();
            AutoScaleMode = AutoScaleMode.None;
            Font = new Font("Segoe UI", 9F);
            Text = App.Name + " " + App.Version;
            Icon = AppIcon() ?? trayIcons["ok"];
            StartPosition = FormStartPosition.Manual;
            KeyPreview = true;

            var main = mainPanel = new TableLayoutPanel();
            main.AutoScroll = true;
            main.Dock = DockStyle.Fill;
            main.ColumnCount = 1;
            main.RowCount = 3;
            main.Padding = Ui.P(8, 6, 8, 4);
            main.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            // Schede (altezza calcolata in FitToScreen), pulsanti, messaggi che occupano il resto
            main.RowStyles.Add(new RowStyle(SizeType.Absolute, 0));
            main.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            main.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            tabs = new TabControl();
            tabs.Dock = DockStyle.Fill;
            tabs.TabPages.Add(Page("Club Log", BuildCredentials()));
            tabs.TabPages.Add(Page("UDP", BuildPorts()));
            main.Controls.Add(tabs, 0, 0);
            main.Controls.Add(BuildBar(), 0, 1);
            main.Controls.Add(Group(" Messaggi  (Alt+W per cancellare) ", BuildLog(), false), 0, 2);

            var status = statusStrip = new StatusStrip();
            status.SizingGrip = true;
            lMode = new ToolStripStatusLabel();
            lMode.Font = new Font("Segoe UI", 10F, FontStyle.Bold);
            lMode.Margin = Ui.P(4, 3, 16, 2);
            lCounters = new ToolStripStatusLabel();
            lCounters.Font = new Font("Segoe UI", 10F, FontStyle.Bold);
            status.Items.Add(lMode);
            status.Items.Add(lCounters);

            Controls.Add(main);
            Controls.Add(status);
            main.BringToFront();
            ResumeLayout(false);
            PerformLayout();

            FitToScreen(Screen.FromPoint(Cursor.Position).WorkingArea);

            bStart.Click += (s, e) => DoStart();
            bStop.Click += (s, e) => DoStop();
            bRetry.Click += (s, e) => DoRetry();
            bNew.Click += (s, e) => OpenQsoForm(this, null, null);
            bSearch.Click += (s, e) =>
            {
                using (var f = new SearchForm(this))
                    f.ShowDialog(this);
            };
            bImport.Click += (s, e) => DoImport();
            bFolder.Click += (s, e) => DoFolder();

            // Salvataggio automatico a ogni modifica (mezzo secondo dopo l'ultima, mentre si scrive)
            saveTimer.Interval = 500;
            saveTimer.Tick += (s, e) =>
            {
                saveTimer.Stop();
                DoSave(true);
            };
            EventHandler changed = (s, e) =>
            {
                saveTimer.Stop();
                saveTimer.Start();
            };
            foreach (Control c in new Control[] { eCall, eEmail, ePwd, eApi })
                if (c != null)
                    c.TextChanged += changed;
            foreach (CheckBox c in new[] { cFreq, cDry, cAuto, cTray })
                c.CheckedChanged += changed;
            eInterval.ValueChanged += changed;
            eBatch.ValueChanged += changed;
            foreach (var r in rows)
            {
                r.Enabled.CheckedChanged += changed;
                r.Ip.TextChanged += changed;
                r.Port.TextChanged += changed;
                r.Mcast.TextChanged += changed;
            }

            // --- Tray bar ---
            tray = new NotifyIcon();
            tray.Icon = trayIcons["info"];
            tray.Text = App.Name;
            var menu = new ContextMenuStrip();
            var show = (ToolStripMenuItem)menu.Items.Add("Mostra finestra", null, (s, e) => ShowWindow());
            show.Font = new Font(menu.Font, FontStyle.Bold);
            menu.Items.Add("Esci", null, (s, e) =>
            {
                ShowWindow();
                Close();
            });
            tray.ContextMenuStrip = menu;
            tray.MouseClick += (s, e) =>
            {
                if (e.Button == MouseButtons.Left)
                    ShowWindow();
            };
            tray.Visible = true;

            AddLog("info", string.Format("{0} {1} - cartella dati: {2}", App.Name, App.Version, App.BaseDir));
            int pending = engine.Uploader.Pending();
            if (pending > 0)
                AddLog("warn", pending + " QSO in coda dalla sessione precedente: verranno inviati all'avvio.");

            timer.Interval = 150;
            timer.Tick += (s, e) => Poll();
            timer.Start();
            Poll();

            // Avviato da Windows: si apre ridotto a icona (e in OnShown si nasconde nella tray)
            if (AvvioWindows.StartedByWindows())
                WindowState = FormWindowState.Minimized;
        }

        // Adatta la finestra all'area libera del monitor (esclusa la barra delle applicazioni) e la
        // centra. Se la finestra è più piccola del contenuto compaiono le barre di scorrimento.
        internal void FitToScreen(Rectangle area)
        {
            // Schede: la misura della scheda più grande più bordi e linguette
            Size page = Size.Empty;
            foreach (TabPage p in tabs.TabPages)
            {
                Size pref = p.Controls[0].GetPreferredSize(Size.Empty);
                page = new Size(Math.Max(page.Width, pref.Width + p.Padding.Horizontal),
                                Math.Max(page.Height, pref.Height + p.Padding.Vertical));
            }
            IntPtr handle = tabs.Handle;  // DisplayRectangle è valido solo con il controllo creato
            Size chrome = tabs.Size - tabs.DisplayRectangle.Size;
            var tabsSize = new Size(page.Width + chrome.Width, page.Height + chrome.Height);
            mainPanel.RowStyles[0].Height = tabsSize.Height + tabs.Margin.Vertical;

            Control bar = mainPanel.GetControlFromPosition(0, 1);
            Size barPref = bar.GetPreferredSize(Size.Empty);
            int w = Math.Max(tabsSize.Width + tabs.Margin.Horizontal, barPref.Width + bar.Margin.Horizontal);
            int h = mainPanel.Padding.Vertical + (int)mainPanel.RowStyles[0].Height + barPref.Height + bar.Margin.Vertical;
            var content = new Size(w + mainPanel.Padding.Horizontal, h + Ui.S(130));  // con qualche riga di messaggi
            mainPanel.AutoScrollMinSize = content;
            MinimumSize = new Size(Math.Min(Ui.S(420), area.Width), Math.Min(Ui.S(320), area.Height));
            Size want = SizeFromClientSize(new Size(Math.Max(content.Width, statusStrip.GetPreferredSize(Size.Empty).Width),
                                                    content.Height + Ui.S(170) + statusStrip.Height));
            Size = new Size(Math.Min(want.Width, area.Width), Math.Min(want.Height, area.Height));
            Location = new Point(area.Left + (area.Width - Width) / 2, area.Top + (area.Height - Height) / 2);
        }

        // --- Costruzione dei controlli ---

        static TabPage Page(string title, Control content)
        {
            var p = new TabPage(title);
            p.Padding = Ui.P(8, 6, 8, 6);
            p.UseVisualStyleBackColor = true;
            content.Dock = DockStyle.Top;  // in alto: la scheda più bassa non allarga le sue righe
            p.Controls.Add(content);
            return p;
        }

        static GroupBox Group(string title, Control content, bool autoSize)
        {
            var g = new GroupBox();
            g.Text = title;
            g.Dock = DockStyle.Fill;
            g.Padding = Ui.P(8, 4, 8, 6);
            if (autoSize)
            {
                g.AutoSize = true;
                g.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            }
            content.Dock = DockStyle.Fill;
            g.Controls.Add(content);
            return g;
        }

        static Label Lbl(string text)
        {
            var l = new Label();
            l.Text = text;
            l.AutoSize = true;
            l.Anchor = AnchorStyles.Left;  // centrata in verticale nella riga
            return l;
        }

        static TextBox Box(string text, int width)
        {
            var t = new TextBox();
            t.Text = text;
            t.Width = Ui.S(width);
            return t;
        }

        static FlowLayoutPanel Flow()
        {
            var f = new FlowLayoutPanel();
            f.AutoSize = true;
            f.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            f.WrapContents = false;
            f.Margin = Ui.P(0, 6, 0, 0);
            return f;
        }

        static TableLayoutPanel Table(int columns)
        {
            var t = new TableLayoutPanel();
            t.AutoSize = true;
            t.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            t.ColumnCount = columns;
            for (int i = 0; i < columns; i++)
                t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            return t;
        }

        // A sinistra i campi in colonna, a destra le opzioni in colonna
        Control BuildCredentials()
        {
            var t = Table(2);
            var f = Table(3);
            f.Margin = Ui.P(0, 0, 24, 0);

            eCall = Box(cfg.Callsign, 120);
            eCall.CharacterCasing = CharacterCasing.Upper;
            eEmail = Box(cfg.Email, 280);
            ePwd = Box(cfg.Password, 280);
            ePwd.UseSystemPasswordChar = true;
            // Compilato con la chiave integrata (compila_con_chiave.bat) il campo API key non esiste
#if !CHIAVE_API
            eApi = Box(cfg.Api, 280);
            eApi.UseSystemPasswordChar = true;
#endif
            eInterval = Spin(1, 600, cfg.Interval, 65);
            eBatch = Spin(0, 10000, cfg.Batch, 65);

            int row = 0;
            AddField(f, row++, "Nominativo DX:", eCall, null);
            AddField(f, row++, "Email Club Log:", eEmail, null);
            AddField(f, row++, "App password:", ePwd, null);
#if !CHIAVE_API
            AddField(f, row++, "API key:", eApi, null);
#endif
            AddField(f, row++, "Pausa tra due invii:", eInterval, "secondi (minimo)");
            eInterval.Margin = Ui.P(3, 10, 3, 3);
            AddField(f, row++, "Invio a blocchi da:", eBatch, "QSO in coda (0 = mai)");
            t.Controls.Add(f, 0, 0);

            var opts = Flow();
            opts.FlowDirection = FlowDirection.TopDown;
            opts.Margin = Ui.P(0, 0, 0, 0);
#if CHIAVE_API
            cShow = Check("Mostra password", false);
#else
            cShow = Check("Mostra password/chiave", false);
#endif
            cShow.CheckedChanged += (s, e) =>
            {
                ePwd.UseSystemPasswordChar = !cShow.Checked;
                if (eApi != null)
                    eApi.UseSystemPasswordChar = !cShow.Checked;
            };
            cFreq = Check("Invia la frequenza", cfg.IncludeFreq);
            cDry = Check("Modalità TEST (non invia a Club Log)", cfg.DryRun);
            cAuto = Check("Avvia ascolto all'apertura", cfg.Autostart);
            cTray = Check("Riduci a icona nella tray bar", cfg.Tray);
            string boot = AvvioWindows.Entry();
            cBoot = Check("Avvia con Windows", boot.Length > 0 && AvvioWindows.IsMine(boot));
            cBoot.Click += (s, e) => ToggleBoot();
            cDry.Margin = Ui.P(0, 15, 16, 3);  // in fondo, un po' staccata dalle altre
            opts.Controls.AddRange(new Control[] { cAuto, cFreq, cShow, cTray, cBoot, cDry });
            t.Controls.Add(opts, 1, 0);
            return t;
        }

        static void AddField(TableLayoutPanel f, int row, string label, Control box, string unit)
        {
            Label l = LblRight(label);
            f.Controls.Add(l, 0, row);
            f.Controls.Add(box, 1, row);
            if (unit != null)
                f.Controls.Add(Lbl(unit), 2, row);
            else
                f.SetColumnSpan(box, 2);
        }

        void ToggleBoot()
        {
            bool on = cBoot.Checked;
            string other = AvvioWindows.Entry();
            try
            {
                AvvioWindows.Set(on);
            }
            catch (Exception e)
            {
                cBoot.Checked = !on;
                MessageBox.Show(this, "Impossibile modificare l'avvio con Windows:\n" + e.Message, App.Name,
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (on)
            {
                if (other.Length > 0 && !AvvioWindows.IsMine(other))
                    AddLog("warn", "Avvio con Windows: sostituito il programma registrato prima (" + other + ")");
                AddLog("ok", "Avvio con Windows attivato: all'accensione il programma si apre ridotto a icona" +
                       (cAuto.Checked ? "" : " (attiva anche \"Avvia ascolto all'apertura\" per ricevere i QSO " +
                                             "senza toccare niente)"));
            }
            else
                AddLog("info", "Avvio con Windows disattivato");
        }

        static Label LblRight(string text)
        {
            var l = Lbl(text);
            l.Anchor = AnchorStyles.Right;
            return l;
        }

        static CheckBox Check(string text, bool value)
        {
            var c = new CheckBox();
            c.Text = text;
            c.Checked = value;
            c.AutoSize = true;
            c.Margin = Ui.P(0, 3, 16, 3);
            return c;
        }

        static NumericUpDown Spin(int min, int max, int value, int width)
        {
            var n = new NumericUpDown();
            n.Minimum = min;
            n.Maximum = max;
            n.Value = Math.Max(min, Math.Min(max, value));
            n.Width = Ui.S(width);
            return n;
        }

        const string StatusSample = "00:00:00  ultimo: N1MM-XML contactinfo (QARTest) da 192.168.100.200";

        Control BuildPorts()
        {
            var t = new TableLayoutPanel();
            t.AutoSize = true;
            t.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            t.ColumnCount = 6;
            for (int i = 0; i < 5; i++)
                t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            string[] titles = { "Attivo", "Programma", "Interfaccia (IP)", "Porta", "Multicast (opz.)", "Stato" };
            var bold = new Font("Segoe UI", 9F, FontStyle.Bold);
            for (int c = 0; c < titles.Length; c++)
            {
                var l = Lbl(titles[c]);
                l.Font = bold;
                t.Controls.Add(l, c, 0);
            }

            var ipChoices = LocalIpv4Addresses().ToArray();
            // Colonna Stato larga quanto il messaggio più lungo tra quelli comuni
            int statusWidth = TextRenderer.MeasureText(StatusSample, Font).Width + Ui.S(8);
            for (int i = 0; i < cfg.Listeners.Count; i++)
            {
                var lc = cfg.Listeners[i];
                var r = new ListenerRow();
                r.Name = lc.Name;
                r.Enabled = new CheckBox();
                r.Enabled.Checked = lc.Enabled;
                r.Enabled.AutoSize = true;
                r.Enabled.Anchor = AnchorStyles.None;
                r.Ip = new ComboBox();
                r.Ip.Items.AddRange(ipChoices);
                r.Ip.Text = lc.Ip;
                r.Ip.Width = Ui.S(118);
                r.Port = Box(lc.Port, 48);
                r.Mcast = Box(lc.Mcast, 100);
                r.Status = new Label();
                r.Status.Text = "Fermo";
                r.Status.ForeColor = Colors["info"];
                r.Status.Dock = DockStyle.Fill;
                r.Status.TextAlign = ContentAlignment.MiddleLeft;
                r.Status.AutoEllipsis = true;
                r.Status.MinimumSize = new Size(statusWidth, 0);
                var name = Lbl(lc.Name);
                t.Controls.Add(r.Enabled, 0, i + 1);
                t.Controls.Add(name, 1, i + 1);
                t.Controls.Add(r.Ip, 2, i + 1);
                t.Controls.Add(r.Port, 3, i + 1);
                t.Controls.Add(r.Mcast, 4, i + 1);
                t.Controls.Add(r.Status, 5, i + 1);
                rows.Add(r);
            }
            return t;
        }

        Control BuildBar()
        {
            var bar = Flow();
            bar.Margin = Ui.P(2, 4, 0, 2);
            bStart = Btn("▶ Avvia ascolto");
            bStop = Btn("■ Ferma");
            bStop.Enabled = false;
            bRetry = Btn("Riprova coda");
            bNew = Btn("Nuovo QSO...");
            bSearch = Btn("Cerca QSO...");
            bImport = Btn("Importa log ADIF...");
            bFolder = Btn("Apri cartella dati");
            bar.Controls.AddRange(new Control[] { bStart, bStop, bRetry, bNew, bSearch, bImport, bFolder });
            return bar;
        }

        static Button Btn(string text)
        {
            var b = new Button();
            b.Text = text;
            b.AutoSize = true;
            b.Padding = Ui.P(6, 1, 6, 1);
            b.Margin = Ui.P(0, 0, 6, 0);
            return b;
        }

        Control BuildLog()
        {
            logFont = new Font("Consolas", 9F);
            logFontBold = new Font("Consolas", 9F, FontStyle.Bold);
            txt = new RichTextBox();
            txt.ReadOnly = true;
            txt.BackColor = SystemColors.Window;
            txt.Font = logFont;
            txt.DetectUrls = false;
            txt.HideSelection = false;
            txt.BorderStyle = BorderStyle.FixedSingle;
            txt.ScrollBars = RichTextBoxScrollBars.Vertical;
            return txt;
        }

        // icona.ico incorporata nell'exe da compila.bat, alla misura giusta per la scala dello schermo
        static Icon AppIcon()
        {
            try
            {
                using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("icona.ico"))
                    return s == null ? null : new Icon(s, SystemInformation.IconSize);
            }
            catch (Exception)
            {
                return null;
            }
        }

        static List<string> LocalIpv4Addresses()
        {
            var addrs = new HashSet<string> { "0.0.0.0", "127.0.0.1" };
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up)
                        continue;
                    foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                        if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                            addrs.Add(ua.Address.ToString());
                }
            }
            catch (Exception)
            {
            }
            return addrs.OrderBy(a => a != "0.0.0.0").ThenBy(a => a != "127.0.0.1").ThenBy(a => a, StringComparer.Ordinal).ToList();
        }

        // --- Messaggi ---

        internal void AddLog(string level, string text)
        {
            Color c;
            if (!Colors.TryGetValue(level, out c))
                c = Colors["info"];
            txt.SelectionStart = txt.TextLength;
            txt.SelectionLength = 0;
            txt.SelectionColor = c;
            txt.SelectionFont = level == "err" ? logFontBold : logFont;
            txt.AppendText(DateTime.Now.ToString("HH:mm:ss  ") + text + "\n");
            int lines = txt.GetLineFromCharIndex(txt.TextLength);
            if (lines > 3100)
            {
                txt.ReadOnly = false;
                txt.Select(0, txt.GetFirstCharIndexFromLine(lines - 3000));
                txt.SelectedText = "";
                txt.ReadOnly = true;
            }
            txt.SelectionStart = txt.TextLength;
            txt.ScrollToCaret();
        }

        internal void ClearLog()
        {
            txt.Clear();
        }

        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            if (keyData == (Keys.Alt | Keys.W))
            {
                ClearLog();
                return true;
            }
            return base.ProcessCmdKey(ref msg, keyData);
        }

        // --- Comandi ---

        internal Settings Collect()
        {
            var c = new Settings();
            c.Callsign = eCall.Text.Trim().ToUpperInvariant();
            c.Email = eEmail.Text.Trim();
            c.Password = ePwd.Text.Trim();
            c.Api = eApi != null ? eApi.Text.Trim() : savedApi;
            c.IncludeFreq = cFreq.Checked;
            c.DryRun = cDry.Checked;
            c.Autostart = cAuto.Checked;
            c.Tray = cTray.Checked;
            c.Interval = (int)eInterval.Value;
            c.Batch = (int)eBatch.Value;
            c.Listeners = rows.Select(r => new ListenerSettings(r.Name, r.Enabled.Checked, r.Ip.Text.Trim(),
                                                                r.Port.Text.Trim(), r.Mcast.Text.Trim())).ToList();
            return c;
        }

        // IPv4 in forma decimale con 4 numeri, come ipaddress.IPv4Address di Python
        static bool ParseIpv4(string s, out byte[] octets)
        {
            octets = new byte[4];
            string[] parts = s.Split('.');
            if (parts.Length != 4)
                return false;
            for (int i = 0; i < 4; i++)
            {
                string p = parts[i];
                int n;
                if (p.Length == 0 || p.Length > 3 || !p.All(ch => ch >= '0' && ch <= '9') ||
                    p.Length > 1 && p[0] == '0' || !int.TryParse(p, out n) || n > 255)
                    return false;
                octets[i] = (byte)n;
            }
            return true;
        }

        List<string> Validate(Settings c, out List<KeyValuePair<int, ListenerConfig>> active)
        {
            var errs = new List<string>();
            active = new List<KeyValuePair<int, ListenerConfig>>();
            if (c.Callsign.Length == 0)
                errs.Add("Inserisci il nominativo DX.");
            if (!c.DryRun)
            {
                if (c.Email.Length == 0)
                    errs.Add("Inserisci l'email Club Log (o attiva la modalità TEST).");
                if (c.Password.Length == 0)
                    errs.Add("Inserisci l'app password (o attiva la modalità TEST).");
#if CHIAVE_API
                if (BuiltinKey.ApiKey.Length == 0)
                    errs.Add("Chiave del programma non valida: ricompila con compila_con_chiave.bat.");
#else
                if (c.Api.Length == 0)
                    errs.Add("Inserisci l'API key (o attiva la modalità TEST).");
#endif
            }
            var used = new List<ListenerConfig>();
            for (int i = 0; i < c.Listeners.Count; i++)
            {
                var l = c.Listeners[i];
                int port;
                if (!int.TryParse(l.Port, out port) || port < 1 || port > 65535)
                {
                    errs.Add(l.Name + ": porta non valida.");
                    continue;
                }
                byte[] octets;
                if (!ParseIpv4(l.Ip, out octets))
                {
                    errs.Add(l.Name + ": indirizzo IP non valido.");
                    continue;
                }
                if (l.Mcast.Length > 0 && (!ParseIpv4(l.Mcast, out octets) || octets[0] < 224 || octets[0] > 239))
                {
                    errs.Add(l.Name + ": indirizzo multicast non valido (224.0.0.0-239.255.255.255).");
                    continue;
                }
                if (!l.Enabled)
                    continue;
                foreach (var o in used)
                    if (o.Port == port && (o.Ip == l.Ip || o.Ip == "0.0.0.0" || l.Ip == "0.0.0.0"))
                        errs.Add(string.Format("{0} e {1} usano la stessa porta {2}.", o.Name, l.Name, port));
                var lc = new ListenerConfig();
                lc.Name = l.Name;
                lc.Ip = l.Ip;
                lc.Port = port;
                lc.Mcast = l.Mcast;
                used.Add(lc);
                active.Add(new KeyValuePair<int, ListenerConfig>(i, lc));
            }
            if (active.Count == 0 && errs.Count == 0)
                errs.Add("Attiva almeno una porta.");
            return errs;
        }

        void SetRunning(bool running)
        {
            foreach (Control w in new Control[] { eCall, eEmail, ePwd, eApi, cFreq, cDry, eInterval, eBatch })
                if (w != null)
                    w.Enabled = !running;
            foreach (var r in rows)
            {
                r.Enabled.Enabled = !running;
                r.Ip.Enabled = !running;
                r.Port.Enabled = !running;
                r.Mcast.Enabled = !running;
            }
            bStart.Enabled = !running;
            bStop.Enabled = running;
        }

        void DoSave(bool quiet)
        {
            saveTimer.Stop();
            try
            {
                Collect().Save();
                saveError = false;
                if (!quiet)
                    AddLog("info", "Impostazioni salvate in " + App.ConfigFile);
            }
            catch (Exception e)
            {
                if (!saveError)  // una sola segnalazione finché il problema resta
                    AddLog("err", "Impossibile salvare le impostazioni: " + e.Message);
                saveError = true;
            }
        }

        internal void DoStart()
        {
            Settings c = Collect();
            List<KeyValuePair<int, ListenerConfig>> active;
            var errs = Validate(c, out active);
            if (errs.Count > 0)
            {
                MessageBox.Show(this, string.Join("\n", errs), App.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            DoSave(true);
            foreach (var r in rows)
            {
                r.Status.Text = r.Enabled.Checked ? "Avvio..." : "Disattivato";
                r.Status.ForeColor = Colors["info"];
            }
            if (c.DryRun)
                AddLog("warn", "Avvio in modalità TEST: i QSO vengono ricevuti ma NON inviati a Club Log.");
            else
                AddLog("info", "Avvio: i QSO verranno caricati nel log Club Log di " + c.Callsign + ".");
            if (BuiltinKey.ApiKey.Length > 0)
            {
                c = c.Copy();
                c.Api = BuiltinKey.ApiKey;  // mai salvata nelle impostazioni
            }
            engine.Start(c, active);
            SetRunning(true);
        }

        internal void DoStop()
        {
            engine.Stop();
            SetRunning(false);
            AddLog("info", "Ascolto fermato. I QSO non ancora inviati restano in coda.");
        }

        void DoRetry()
        {
            if (engine.Running)
            {
                engine.Uploader.Resume();
                AddLog("info", string.Format("Nuovo tentativo di invio della coda ({0} QSO).", engine.Uploader.Pending()));
            }
            else
                AddLog("warn", "Avvia l'ascolto per inviare la coda.");
        }

        void DoFolder()
        {
            try
            {
                Process.Start("explorer.exe", "\"" + App.BaseDir + "\"");
            }
            catch (Exception e)
            {
                AddLog("err", "Impossibile aprire la cartella: " + e.Message);
            }
        }

        // Impostazioni attuali per un QSO inserito a mano o una cancellazione, con gli errori
        internal Settings ClubSettings(bool forDelete, out List<string> errs)
        {
            Settings c = Collect().Copy();
            errs = new List<string>();
            if (c.Callsign.Length == 0)
                errs.Add("Inserisci il nominativo DX nella scheda Club Log.");
            if (forDelete && !c.DryRun)
            {
                if (c.Email.Length == 0)
                    errs.Add("Inserisci l'email Club Log nella scheda Club Log.");
                if (c.Password.Length == 0)
                    errs.Add("Inserisci l'app password nella scheda Club Log.");
                if (c.Api.Length == 0 && BuiltinKey.ApiKey.Length == 0)
                    errs.Add("Inserisci l'API key nella scheda Club Log.");
            }
            if (BuiltinKey.ApiKey.Length > 0)
                c.Api = BuiltinKey.ApiKey;  // mai salvata nelle impostazioni
            return c;
        }

        // Finestra Nuovo QSO, o Correggi QSO se c'è il QSO vecchio (com'è in qso_ricevuti.adi)
        internal void OpenQsoForm(IWin32Window parent, ReceivedQso old, Action onDone)
        {
            bool onClub = old != null && (old.Status == Manuale.StatusSent || old.Status == Manuale.StatusQueued ||
                                          old.Status == Manuale.StatusClubLog);
            List<string> errs;
            Settings c = ClubSettings(onClub, out errs);
            if (errs.Count > 0)
            {
                MessageBox.Show(parent, string.Join("\n", errs), App.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            using (var f = new QsoForm(this, c, old, onDone))
                f.ShowDialog(parent);
        }

        void DoImport()
        {
            string call = eCall.Text.Trim().ToUpperInvariant();
            if (call.Length == 0)
            {
                MessageBox.Show(this, "Inserisci prima il nominativo DX della spedizione.", App.Name,
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            string path;
            using (var dlg = new OpenFileDialog())
            {
                dlg.Title = "Scegli il file ADIF del log pregresso";
                dlg.Filter = "File ADIF (*.adi;*.adif)|*.adi;*.adif|Tutti i file (*.*)|*.*";
                if (dlg.ShowDialog(this) != DialogResult.OK)
                    return;
                path = dlg.FileName;
            }
            List<Dictionary<string, string>> records;
            try
            {
                records = Adif.Parse(File.ReadAllBytes(path));
            }
            catch (Exception e)
            {
                MessageBox.Show(this, "Impossibile leggere il file:\n" + e.Message, App.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (records.Count == 0)
            {
                MessageBox.Show(this, "Nessun QSO trovato nel file:\n" + path, App.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            using (var win = new ImportForm(this, path, records, call, cFreq.Checked))
                win.ShowDialog(this);
        }

        // --- Tray bar ---

        void ShowWindow()
        {
            trayHidden = false;
            Show();
            if (WindowState == FormWindowState.Minimized)
                WindowState = FormWindowState.Normal;
            Activate();
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            // Pulsante "riduci a icona": nasconde la finestra e lascia solo l'icona nella tray
            if (WindowState == FormWindowState.Minimized && cTray != null && cTray.Checked && tray != null)
            {
                trayHidden = true;
                Hide();
            }
        }

        void Poll()
        {
            UiEvent ev;
            int n = 0;
            while (n++ < 500 && events.TryDequeue(out ev))
            {
                if (ev.Kind == "log")
                {
                    AddLog(ev.Level, ev.Text);
                    if (ev.Level == "err" && trayHidden)
                        tray.ShowBalloonTip(5000, App.Name, Util.Slice(ev.Text, 0, 250), ToolTipIcon.Error);
                }
                else if (ev.Kind == "lstatus")
                {
                    Color c;
                    rows[ev.Index].Status.Text = ev.Text;
                    rows[ev.Index].Status.ForeColor = Colors.TryGetValue(ev.Level, out c) ? c : Colors["info"];
                }
            }
            Stats s = engine.Stats;
            int pending = engine.Uploader.Pending();
            int jobs = Uploader.PendingJobs().Count;
            lCounters.Text = string.Format("Ricevuti: {0}   Inviati: {1}   In coda: {2}   Doppi ignorati: {3}   Errori: {4}{5}",
                s.Received, s.Sent, pending, s.Dupes, s.Errors, jobs > 0 ? "   File da caricare: " + jobs : "");
            string mode, level;
            if (!engine.Running)
            {
                mode = "FERMO";
                level = "info";
            }
            else if (engine.Uploader.Paused)
            {
                mode = "INVIO IN PAUSA";
                level = "err";
            }
            else if (engine.Uploader.DryRun)
            {
                mode = "TEST";
                level = "warn";
            }
            else
            {
                mode = "ONLINE";
                level = "ok";
            }
            lMode.Text = mode;
            lMode.ForeColor = Colors[level];
            if (trayLevel != level)
            {
                tray.Icon = trayIcons[level];
                trayLevel = level;
            }
            // NotifyIcon accetta al massimo 63 caratteri
            string title = Util.Slice(string.Format("Club Log {0} - {1}\nRicevuti {2}, inviati {3}, in coda {4}",
                eCall.Text.Trim().ToUpperInvariant(), mode, s.Received, s.Sent, pending), 0, 63);
            if (trayTitle != title)
            {
                tray.Text = title;
                trayTitle = title;
            }
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            if (WindowState == FormWindowState.Minimized && cTray.Checked)
            {
                trayHidden = true;
                Hide();
            }
            if (cfg.Autostart)
            {
                var once = new Timer();
                once.Interval = 300;
                once.Tick += (s, a) =>
                {
                    once.Stop();
                    once.Dispose();
                    DoStart();
                };
                once.Start();
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            int pending = engine.Uploader.Pending();
            if (pending > 0 && e.CloseReason != CloseReason.WindowsShutDown &&
                MessageBox.Show(this, string.Format("Ci sono {0} QSO non ancora inviati.\nVerranno inviati al prossimo avvio.\n\n" +
                                "Chiudere comunque?", pending), App.Name, MessageBoxButtons.YesNo,
                                MessageBoxIcon.Question) != DialogResult.Yes)
            {
                e.Cancel = true;
                return;
            }
            DoSave(true);
            timer.Stop();
            engine.Shutdown();
            tray.Visible = false;
            tray.Dispose();
            base.OnFormClosing(e);
        }
    }
}
