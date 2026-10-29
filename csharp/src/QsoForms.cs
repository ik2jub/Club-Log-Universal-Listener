// Finestre per i QSO inseriti a mano: Nuovo QSO / Correggi QSO e Cerca QSO (con cancellazione).

using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

namespace ClubLogListener
{
    static class QsoUi
    {
        public static Label Lbl(string text)
        {
            var l = new Label();
            l.Text = text;
            l.AutoSize = true;
            l.Anchor = AnchorStyles.Left;
            return l;
        }

        public static Button Btn(string text)
        {
            var b = new Button();
            b.Text = text;
            b.AutoSize = true;
            b.Padding = Ui.P(6, 1, 6, 1);
            return b;
        }

        public static bool Ask(IWin32Window owner, string text, MessageBoxIcon icon)
        {
            return MessageBox.Show(owner, text, App.Name, MessageBoxButtons.YesNo, icon) == DialogResult.Yes;
        }

        public static void Show(IWin32Window owner, string text, MessageBoxIcon icon)
        {
            MessageBox.Show(owner, text, App.Name, MessageBoxButtons.OK, icon);
        }

        // Esegue work() in un thread (aspetta Club Log) e poi done(esito, messaggio) nella finestra
        public static void RunAsync(Form form, Control[] buttons, Func<string[]> work, Action<string, string> done)
        {
            foreach (var b in buttons)
                b.Enabled = false;
            form.UseWaitCursor = true;
            form.ControlBox = false;  // niente chiusura finché Club Log non risponde
            var t = new Thread(() =>
            {
                string[] res;
                try
                {
                    res = work();
                }
                catch (Exception e)  // il thread non deve mai morire in silenzio
                {
                    res = new[] { "errore", "Errore imprevisto: " + e.Message };
                }
                form.BeginInvoke((Action)(() =>
                {
                    form.UseWaitCursor = false;
                    form.ControlBox = true;
                    foreach (var b in buttons)
                        b.Enabled = true;
                    done(res[0], res[1]);
                }));
            });
            t.IsBackground = true;
            t.Start();
        }
    }

    sealed class QsoForm : Form
    {
        readonly MainForm owner;
        readonly Settings settings;
        readonly ReceivedQso old;
        readonly Action onDone;
        readonly TextBox eCall, eDate, eTime, eSent, eRcvd;
        readonly ComboBox cBand, cMode;
        readonly Label lLocal;
        readonly Button bOk, bCancel;
        readonly List<KeyValuePair<string, string>> targets;
        readonly List<CheckBox> targetBoxes = new List<CheckBox>();
        string lastDefault = "";

        public QsoForm(MainForm owner, Settings settings, ReceivedQso old, Action onDone)
        {
            this.owner = owner;
            this.settings = settings;
            this.old = old;
            this.onDone = onDone;

            SuspendLayout();
            AutoScaleMode = AutoScaleMode.None;
            Font = new Font("Segoe UI", 9F);
            Text = old != null ? "Correggi QSO" : "Nuovo QSO";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Padding = Ui.P(14, 14, 14, 14);

            var t = new TableLayoutPanel();
            t.AutoSize = true;
            t.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            t.ColumnCount = 3;
            for (int i = 0; i < 3; i++)
                t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            int row = 0;

            var lTitle = QsoUi.Lbl("Log Club Log di " + settings.Callsign + (settings.DryRun ? "  -  modalità TEST" : ""));
            lTitle.Font = new Font("Segoe UI", 10F, FontStyle.Bold);
            Span(t, lTitle, row++);
            if (old != null)
            {
                var lOld = QsoUi.Lbl(string.Format("QSO da correggere: {0}\n(su Club Log: {1} UTC)",
                    Adif.Describe(old.Rec), Manuale.DeleteDatetime(old.Rec)));
                lOld.Margin = Ui.P(3, 6, 3, 0);
                Span(t, lOld, row++);
            }

            eCall = Box(110);
            AddRow(t, row++, "Nominativo:", eCall, null);
            eDate = Box(90);
            var bNow = QsoUi.Btn("Adesso");
            bNow.Click += (s, e) =>
            {
                DateTime now = DateTime.UtcNow;
                eDate.Text = now.ToString("yyyy-MM-dd", Adif.Inv);
                eTime.Text = now.ToString("HH:mm:ss", Adif.Inv);
            };
            AddRow(t, row++, "Data (UTC):", eDate, bNow);
            eTime = Box(90);
            var lHint = QsoUi.Lbl("HH:MM o HH:MM:SS");
            lHint.ForeColor = Color.FromArgb(0x66, 0x66, 0x66);
            AddRow(t, row++, "Ora (UTC):", eTime, lHint);
            lLocal = QsoUi.Lbl("");
            t.Controls.Add(lLocal, 1, row);
            t.SetColumnSpan(lLocal, 2);
            row++;
            cBand = new ComboBox();
            cBand.DropDownStyle = ComboBoxStyle.DropDownList;
            cBand.Items.AddRange(Adif.BandNames.Cast<object>().ToArray());
            cBand.Width = Ui.S(80);
            AddRow(t, row++, "Banda:", cBand, null);
            cMode = new ComboBox();
            cMode.Items.AddRange(Manuale.Modes.Cast<object>().ToArray());
            cMode.Width = Ui.S(90);
            AddRow(t, row++, "Modo:", cMode, null);
            eSent = Box(60);
            AddRow(t, row++, "RST trasmesso:", eSent, null);
            eRcvd = Box(60);
            AddRow(t, row++, "RST ricevuto:", eRcvd, null);

            // Log dei programmi a cui aggiungere il QSO: mai in modalità TEST, sono i log veri
            targets = Manuale.ProgramLogTargets();
            if (targets.Count > 0)
            {
                var tf = new FlowLayoutPanel();
                tf.AutoSize = true;
                tf.FlowDirection = FlowDirection.TopDown;
                tf.Margin = Ui.P(3, 10, 3, 0);
                foreach (var tg in targets)
                {
                    var cb = new CheckBox();
                    cb.Text = tg.Key;
                    cb.AutoSize = true;
                    cb.Enabled = !settings.DryRun;
                    cb.Margin = Ui.P(0, 0, 0, 2);
                    tf.Controls.Add(cb);
                    targetBoxes.Add(cb);
                }
                if (settings.DryRun)
                {
                    var lt = QsoUi.Lbl("(non in modalità TEST)");
                    lt.ForeColor = Color.FromArgb(0x66, 0x66, 0x66);
                    tf.Controls.Add(lt);
                }
                var lAdd = QsoUi.Lbl("Aggiungi anche a:");
                lAdd.Anchor = AnchorStyles.Right | AnchorStyles.Top;
                lAdd.Margin = Ui.P(3, 12, 3, 0);
                t.Controls.Add(lAdd, 0, row);
                t.Controls.Add(tf, 1, row);
                t.SetColumnSpan(tf, 2);
                row++;
            }

            if (old != null)
            {
                var r = old.Rec;
                string od = Util.Get(r, "qso_date").Trim(), ot = Util.Get(r, "time_on").Trim().PadRight(6, '0');
                eCall.Text = Util.Get(r, "call").Trim();
                eDate.Text = string.Format("{0}-{1}-{2}", Util.Slice(od, 0, 4), Util.Slice(od, 4, 6), Util.Slice(od, 6, 8));
                eTime.Text = string.Format("{0}:{1}:{2}", Util.Slice(ot, 0, 2), Util.Slice(ot, 2, 4), Util.Slice(ot, 4, 6));
                cBand.SelectedItem = Util.Get(r, "band").Trim().ToLowerInvariant();
                string mode = Util.Get(r, "submode").Trim();
                cMode.Text = mode.Length > 0 ? mode : Util.Get(r, "mode").Trim();
                eSent.Text = Util.Get(r, "rst_sent").Trim();
                eRcvd.Text = Util.Get(r, "rst_rcvd").Trim();
                lastDefault = cMode.Text.Length > 0 ? Manuale.DefaultRst(cMode.Text) : "";
            }
            eDate.TextChanged += (s, e) => ShowLocal();
            eTime.TextChanged += (s, e) => ShowLocal();
            cMode.TextChanged += (s, e) => ModeChanged();
            ShowLocal();

            var btns = new FlowLayoutPanel();
            btns.AutoSize = true;
            btns.FlowDirection = FlowDirection.RightToLeft;
            btns.Anchor = AnchorStyles.Right;
            btns.Margin = Ui.P(3, 12, 3, 3);
            bCancel = QsoUi.Btn("Annulla");
            bCancel.DialogResult = DialogResult.Cancel;
            bOk = QsoUi.Btn(old != null ? "Correggi" : "Invia a Club Log");
            bOk.Click += (s, e) => Confirm();
            btns.Controls.Add(bCancel);
            btns.Controls.Add(bOk);
            Span(t, btns, row);
            AcceptButton = bOk;
            CancelButton = bCancel;

            Controls.Add(t);
            ResumeLayout(false);
            PerformLayout();
            ActiveControl = eCall;
        }

        static TextBox Box(int width)
        {
            var b = new TextBox();
            b.Width = Ui.S(width);
            return b;
        }

        static void Span(TableLayoutPanel t, Control c, int row)
        {
            t.Controls.Add(c, 0, row);
            t.SetColumnSpan(c, 3);
        }

        static void AddRow(TableLayoutPanel t, int row, string label, Control field, Control extra)
        {
            var l = QsoUi.Lbl(label);
            l.Anchor = AnchorStyles.Right;
            l.Margin = Ui.P(3, 6, 3, 0);
            field.Margin = Ui.P(3, 6, 3, 0);
            t.Controls.Add(l, 0, row);
            t.Controls.Add(field, 1, row);
            if (extra != null)
            {
                extra.Margin = Ui.P(3, 6, 3, 0);
                t.Controls.Add(extra, 2, row);
            }
        }

        void ShowLocal()
        {
            try
            {
                DateTime utc = Manuale.ParseUtcInput(eDate.Text, eTime.Text);
                lLocal.Text = "= " + utc.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss", Adif.Inv) + " ora locale";
                lLocal.ForeColor = MainForm.Colors["info"];
            }
            catch (FormatException e)
            {
                lLocal.Text = eDate.Text.Trim().Length > 0 && eTime.Text.Trim().Length > 0 ? e.Message
                    : "Data AAAA-MM-GG, ora UTC (non quella locale)";
                lLocal.ForeColor = MainForm.Colors["warn"];
            }
        }

        // Rapporto proposto in base al modo, se non è già stato scritto a mano
        void ModeChanged()
        {
            string def = Manuale.DefaultRst(cMode.Text.Trim());
            foreach (var box in new[] { eSent, eRcvd })
                if (box.Text.Trim().Length == 0 || box.Text.Trim() == lastDefault)
                    box.Text = def;
            lastDefault = def;
        }

        // Invia il QSO, lo aggiunge ai log scelti e chiude la finestra con il riepilogo
        void Send(Dictionary<string, string> rec)
        {
            string err = owner.engine.AddManual(rec, settings);
            if (err != null)
            {
                QsoUi.Show(this, "QSO non valido: " + err, MessageBoxIcon.Error);
                return;
            }
            var chosen = targets.Where((tg, i) => targetBoxes[i].Checked).ToList();
            var notes = new List<string>();
            if (chosen.Count > 0)
            {
                var full = new Dictionary<string, string>(rec);
                full["station_callsign"] = settings.Callsign;
                notes.AddRange(owner.engine.AddToProgramLogs(Adif.Normalize(full, true, out err), chosen));
                if (chosen.Any(tg => tg.Value.Length == 0))
                    notes.Add(Manuale.MshvImportNote);
            }
            if (old != null && targets.Any(tg => tg.Value.Length == 0))
                notes.Add(Manuale.MshvFixNote);
            if (old != null && targets.Any(tg => tg.Value.Length > 0))
                notes.Add("Se il QSO vecchio è nel log di WSJT-X o JTDX resta lì: questi programmi non hanno un comando " +
                          "per cancellarlo.");
            IWin32Window parent = Owner;
            Close();
            if (onDone != null)
                onDone();
            if (notes.Count > 0)
                QsoUi.Show(parent, string.Join("\n\n", notes), MessageBoxIcon.Information);
        }

        void Confirm()
        {
            var errs = new List<string>();
            string call = eCall.Text.Trim().ToUpperInvariant();
            if (!Regex.IsMatch(call, @"^[A-Z0-9]+(/[A-Z0-9]+)*$") || call.Length < 3 ||
                !Regex.IsMatch(call, @"\d") || !Regex.IsMatch(call, "[A-Z]"))
                errs.Add("Nominativo non valido.");
            DateTime when = DateTime.MinValue;
            try
            {
                when = Manuale.ParseUtcInput(eDate.Text, eTime.Text);
                if (when > DateTime.UtcNow.AddMinutes(10))
                    errs.Add("Data e ora sono nel futuro: vanno scritte in UTC.");
            }
            catch (FormatException e)
            {
                errs.Add(e.Message);
            }
            string band = cBand.SelectedItem as string ?? "";
            if (band.Length == 0)
                errs.Add("Scegli la banda.");
            string mode = cMode.Text.Trim().ToUpperInvariant();
            if (!Regex.IsMatch(mode, "^[A-Z0-9-]+$"))
                errs.Add("Modo non valido.");
            if (eSent.Text.Trim().Length > 10)
                errs.Add("RST trasmesso troppo lungo.");
            if (eRcvd.Text.Trim().Length > 10)
                errs.Add("RST ricevuto troppo lungo.");
            if (errs.Count > 0)
            {
                QsoUi.Show(this, string.Join("\n", errs), MessageBoxIcon.Error);
                return;
            }
            var rec = new Dictionary<string, string> {
                {"call", call}, {"qso_date", when.ToString("yyyyMMdd", Adif.Inv)}, {"time_on", when.ToString("HHmmss", Adif.Inv)},
                {"band", band}, {"mode", mode}, {"rst_sent", eSent.Text.Trim()}, {"rst_rcvd", eRcvd.Text.Trim()} };
            string err;
            string newDesc = Adif.Describe(Adif.Normalize(rec, true, out err));
            var entries = Manuale.ReceivedQsos(owner.engine.Uploader.QueuedKeys());
            double ts = (when - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            var near = Manuale.NearbyQsos(entries, call, band, ts, old != null ? Manuale.StoredKey(old.Rec) : null);
            if (near.Count > 0 && !QsoUi.Ask(this, string.Format("Ci sono già QSO con {0} in {1} vicini a quest'ora:\n\n{2}\n\n" +
                    "Continuare comunque?", call, band, string.Join("\n", near.Take(8).Select(Adif.Describe))), MessageBoxIcon.Warning))
                return;
            string test = settings.DryRun ? "\n\nModalità TEST: niente viene inviato o cancellato su Club Log." : "";
            if (old == null)
            {
                if (!QsoUi.Ask(this, "Inviare a Club Log il QSO?\n\n" + newDesc + test, MessageBoxIcon.Question))
                    return;
                Send(rec);
                return;
            }
            bool onClub = old.Status == Manuale.StatusSent || old.Status == Manuale.StatusQueued ||
                          old.Status == Manuale.StatusClubLog;
            if (!QsoUi.Ask(this, string.Format("Correggere il QSO?\n\nPrima:  {0}\nDopo:   {1}\n\n{2}{3}",
                    Adif.Describe(old.Rec), newDesc, onClub
                        ? "Il QSO vecchio viene cancellato da Club Log (non si può annullare) e quello corretto viene inviato."
                        : "Il QSO vecchio non è su Club Log (" + old.Status + "): viene solo inviato quello corretto.",
                    test), MessageBoxIcon.Warning))
                return;
            if (!onClub)
            {
                Send(rec);
                return;
            }
            QsoUi.RunAsync(this, new Control[] { bOk, bCancel }, () =>
            {
                string msg;
                string outcome = owner.engine.DeleteQso(old.Rec, settings, out msg);
                return new[] { outcome, msg };
            }, (outcome, msg) =>
            {
                if (outcome == "non trovato")
                {
                    if (!QsoUi.Ask(this, msg + ".\n\nInviare comunque il QSO corretto?", MessageBoxIcon.Warning))
                        return;
                }
                else if (outcome == "errore")
                {
                    QsoUi.Show(this, msg + "\n\nIl QSO corretto non è stato inviato.", MessageBoxIcon.Error);
                    return;
                }
                Send(rec);
            });
        }
    }

    sealed class SearchForm : Form
    {
        const int MaxRows = 2000;
        readonly MainForm owner;
        readonly TextBox fCall, fDate;
        readonly ComboBox fBand;
        readonly Label lCount;
        readonly ListView list;
        readonly Button bNew, bFix, bDel, bGet, bClose;
        readonly Label lDownload;
        List<ReceivedQso> entries = new List<ReceivedQso>();

        public SearchForm(MainForm owner)
        {
            this.owner = owner;
            SuspendLayout();
            AutoScaleMode = AutoScaleMode.None;
            Font = new Font("Segoe UI", 9F);
            Text = "Cerca QSO";
            ShowInTaskbar = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            Padding = Ui.P(10, 10, 10, 10);

            var flt = new FlowLayoutPanel();
            flt.AutoSize = true;
            flt.Dock = DockStyle.Top;
            flt.WrapContents = false;
            fCall = new TextBox();
            fCall.Width = Ui.S(90);
            fDate = new TextBox();
            fDate.Width = Ui.S(90);
            fBand = new ComboBox();
            fBand.DropDownStyle = ComboBoxStyle.DropDownList;
            fBand.Items.Add("(tutte)");
            fBand.Items.AddRange(Adif.BandNames.Cast<object>().ToArray());
            fBand.SelectedIndex = 0;
            fBand.Width = Ui.S(80);
            lCount = QsoUi.Lbl("");
            foreach (Control c in new Control[] { QsoUi.Lbl("Nominativo:"), fCall, QsoUi.Lbl("Data (UTC):"), fDate,
                                                  QsoUi.Lbl("Banda:"), fBand, lCount })
            {
                c.Margin = c is Label ? Ui.P(c == lCount ? 12 : 0, 6, 0, 0) : Ui.P(4, 3, 12, 3);
                flt.Controls.Add(c);
            }
            fCall.TextChanged += (s, e) => RefreshList();
            fDate.TextChanged += (s, e) => RefreshList();
            fBand.SelectedIndexChanged += (s, e) => RefreshList();

            list = new ListView();
            list.View = View.Details;
            list.FullRowSelect = true;
            list.MultiSelect = false;
            list.HideSelection = false;
            list.Dock = DockStyle.Fill;
            foreach (var col in new[] { new { T = "Data", W = 86 }, new { T = "Ora UTC", W = 70 }, new { T = "Nominativo", W = 100 },
                                         new { T = "Banda", W = 56 }, new { T = "Modo", W = 60 }, new { T = "RST tx", W = 54 },
                                         new { T = "RST rx", W = 54 }, new { T = "Stato", W = 80 } })
                list.Columns.Add(col.T, Ui.S(col.W));
            list.DoubleClick += (s, e) => DoFix();

            var note = QsoUi.Lbl("Sono elencati i QSO passati dal listener (qso_ricevuti.adi), compresi quelli ricevuti in " +
                                 "modalità TEST, con data e ora\ninviate a Club Log. Per vedere anche i QSO caricati in altro " +
                                 "modo (dal sito, da altri PC) scarica il log da Club Log.");
            note.ForeColor = Color.FromArgb(0x66, 0x66, 0x66);
            note.Dock = DockStyle.Bottom;
            note.Padding = Ui.P(0, 6, 0, 0);
            lDownload = QsoUi.Lbl("");
            lDownload.ForeColor = note.ForeColor;
            lDownload.Dock = DockStyle.Bottom;

            var btns = new FlowLayoutPanel();
            btns.AutoSize = true;
            btns.Dock = DockStyle.Bottom;
            btns.Padding = Ui.P(0, 8, 0, 0);
            bNew = QsoUi.Btn("Nuovo QSO...");
            bFix = QsoUi.Btn("Correggi...");
            bDel = QsoUi.Btn("Cancella da Club Log");
            bGet = QsoUi.Btn("Scarica log da Club Log");
            bClose = QsoUi.Btn("Chiudi");
            bClose.DialogResult = DialogResult.Cancel;
            bNew.Click += (s, e) => owner.OpenQsoForm(this, null, Reload);
            bFix.Click += (s, e) => DoFix();
            bDel.Click += (s, e) => DoDelete();
            bGet.Click += (s, e) => DoDownload();
            foreach (var b in new[] { bNew, bFix, bDel, bGet, bClose })
                b.Margin = Ui.P(0, 0, 6, 0);
            btns.Controls.AddRange(new Control[] { bNew, bFix, bDel, bGet, bClose });
            CancelButton = bClose;

            var spacer = new Panel();
            spacer.Height = Ui.S(8);
            spacer.Dock = DockStyle.Top;
            Controls.Add(list);
            Controls.Add(spacer);
            Controls.Add(flt);
            Controls.Add(note);
            Controls.Add(lDownload);
            Controls.Add(btns);
            ClientSize = new Size(Ui.S(660), Ui.S(460));
            MinimumSize = new Size(Ui.S(560), Ui.S(320));
            ResumeLayout(false);
            PerformLayout();
            Reload();
            ActiveControl = fCall;
        }

        void Reload()
        {
            entries = Manuale.ReceivedQsos(owner.engine.Uploader.QueuedKeys());
            if (File.Exists(App.ClubLogAdif))
                lDownload.Text = string.Format("Log scaricato da Club Log il {0} ({1} QSO non passati dal listener).",
                    File.GetLastWriteTime(App.ClubLogAdif).ToString("dd/MM/yyyy HH:mm", Adif.Inv),
                    entries.Count(e => e.Status == Manuale.StatusClubLog));
            else
                lDownload.Text = "Log di Club Log non ancora scaricato.";
            RefreshList();
        }

        void DoDownload()
        {
            List<string> errs;
            Settings c = owner.ClubSettings(false, out errs);
            // Anche in modalità TEST: il download non cambia niente su Club Log
            if (c.Email.Length == 0)
                errs.Add("Inserisci l'email Club Log nella scheda Club Log.");
            if (c.Password.Length == 0)
                errs.Add("Inserisci l'app password nella scheda Club Log.");
            if (errs.Count > 0)
            {
                QsoUi.Show(this, string.Join("\n", errs), MessageBoxIcon.Error);
                return;
            }
            if (!QsoUi.Ask(this, "Scaricare da Club Log tutto il log di " + c.Callsign + "?\n\nServe solo per cercare i QSO " +
                    "non passati dal listener. Con un log grande può volerci un po'; non ripeterlo spesso.", MessageBoxIcon.Question))
                return;
            QsoUi.RunAsync(this, new Control[] { bNew, bFix, bDel, bGet, bClose }, () =>
            {
                string msg;
                string outcome = owner.engine.DownloadClubLogLog(c, out msg);
                return new[] { outcome, msg };
            }, (outcome, msg) =>
            {
                if (outcome == "errore")
                    QsoUi.Show(this, msg, MessageBoxIcon.Error);
                Reload();
            });
        }

        void RefreshList()
        {
            string call = fCall.Text.Trim().ToUpperInvariant();
            string day = Regex.Replace(fDate.Text, @"\D", "");
            string band = fBand.SelectedIndex > 0 ? (string)fBand.SelectedItem : "";
            int found = 0;
            var items = new List<ListViewItem>();
            var order = Enumerable.Range(0, entries.Count)  // dal più recente
                .OrderByDescending(j => Util.Get(entries[j].Rec, "qso_date").Trim() + Util.Get(entries[j].Rec, "time_on").Trim(),
                                   StringComparer.Ordinal)
                .ThenByDescending(j => j);
            foreach (int i in order)
            {
                var r = entries[i].Rec;
                if (call.Length > 0 && !Util.Get(r, "call").ToUpperInvariant().Contains(call) ||
                    day.Length > 0 && !Util.Get(r, "qso_date").Trim().StartsWith(day, StringComparison.Ordinal) ||
                    band.Length > 0 && Util.Get(r, "band").Trim().ToLowerInvariant() != band)
                    continue;
                if (++found > MaxRows)
                    continue;
                string d = Util.Get(r, "qso_date").Trim(), t = Util.Get(r, "time_on").Trim().PadRight(6, '0');
                string mode = Util.Get(r, "submode").Trim();
                var it = new ListViewItem(new[] {
                    string.Format("{0}-{1}-{2}", Util.Slice(d, 0, 4), Util.Slice(d, 4, 6), Util.Slice(d, 6, 8)),
                    string.Format("{0}:{1}:{2}", Util.Slice(t, 0, 2), Util.Slice(t, 2, 4), Util.Slice(t, 4, 6)),
                    Util.Get(r, "call").Trim(), Util.Get(r, "band").Trim().ToLowerInvariant(), mode.Length > 0 ? mode : Util.Get(r, "mode").Trim(),
                    Util.Get(r, "rst_sent").Trim(), Util.Get(r, "rst_rcvd").Trim(), entries[i].Status });
                it.Tag = entries[i];
                if (entries[i].Status == Manuale.StatusDeleted)
                    it.ForeColor = Color.FromArgb(0x88, 0x88, 0x88);
                else if (entries[i].Status == Manuale.StatusRejected)
                    it.ForeColor = MainForm.Colors["err"];
                else if (entries[i].Status == Manuale.StatusQueued)
                    it.ForeColor = MainForm.Colors["rx"];
                items.Add(it);
            }
            list.BeginUpdate();
            list.Items.Clear();
            list.Items.AddRange(items.ToArray());
            list.EndUpdate();
            lCount.Text = found + " QSO" + (found > MaxRows ? string.Format(" (mostrati i {0} più recenti)", MaxRows) : "");
        }

        ReceivedQso Selected()
        {
            if (list.SelectedItems.Count == 0)
            {
                QsoUi.Show(this, "Seleziona un QSO nell'elenco.", MessageBoxIcon.Information);
                return null;
            }
            return (ReceivedQso)list.SelectedItems[0].Tag;
        }

        void DoFix()
        {
            var e = Selected();
            if (e != null)
                owner.OpenQsoForm(this, e, Reload);
        }

        void DoDelete()
        {
            var e = Selected();
            if (e == null)
                return;
            string desc = Adif.Describe(e.Rec);
            if (e.Status == Manuale.StatusDeleted)
            {
                QsoUi.Show(this, "Il QSO " + desc + " è già stato cancellato.", MessageBoxIcon.Information);
                return;
            }
            if (e.Status == Manuale.StatusRejected)
            {
                QsoUi.Show(this, "Il QSO " + desc + " era stato rifiutato da Club Log: non è nel log.", MessageBoxIcon.Information);
                return;
            }
            List<string> errs;
            Settings c = owner.ClubSettings(true, out errs);
            if (errs.Count > 0)
            {
                QsoUi.Show(this, string.Join("\n", errs), MessageBoxIcon.Error);
                return;
            }
            string what = e.Status == Manuale.StatusQueued ? "Il QSO è ancora in coda: viene solo tolto dalla coda."
                                                          : "La cancellazione da Club Log non si può annullare.";
            if (c.DryRun)
                what += "\n\nModalità TEST: niente viene cancellato su Club Log.";
            if (!QsoUi.Ask(this, string.Format("Cancellare dal log Club Log di {0} il QSO?\n\n{1}\n({2} UTC)\n\n{3}",
                    c.Callsign, desc, Manuale.DeleteDatetime(e.Rec), what), MessageBoxIcon.Warning))
                return;
            QsoUi.RunAsync(this, new Control[] { bNew, bFix, bDel, bGet, bClose }, () =>
            {
                string msg;
                string outcome = owner.engine.DeleteQso(e.Rec, c, out msg);
                return new[] { outcome, msg };
            }, (outcome, msg) =>
            {
                QsoUi.Show(this, msg, outcome == "errore" ? MessageBoxIcon.Error
                                     : outcome == "non trovato" ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
                Reload();
            });
        }
    }
}
