// Finestra di importazione di un log ADIF pregresso.

using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace ClubLogListener
{
    sealed class ImportForm : Form
    {
        readonly MainForm owner;
        readonly string path, call;
        readonly List<Dictionary<string, string>> records;
        readonly bool includeFreq;
        readonly CheckBox cMissing;
        readonly TextBox eFrom, eTo;
        readonly Label summary;
        readonly Button bOk;
        ImportResult res;

        public ImportForm(MainForm owner, string path, List<Dictionary<string, string>> records, string call, bool includeFreq)
        {
            this.owner = owner;
            this.path = path;
            this.records = records;
            this.call = call;
            this.includeFreq = includeFreq;

            SuspendLayout();
            AutoScaleMode = AutoScaleMode.None;
            Font = new Font("Segoe UI", 9F);
            Text = "Importa log ADIF";
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
            t.ColumnCount = 5;
            for (int i = 0; i < 5; i++)
                t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            var lFile = Lbl("File: " + Path.GetFileName(path));
            lFile.Font = new Font("Segoe UI", 10F, FontStyle.Bold);
            Span(t, lFile, 0);
            var lInfo = Lbl("Vengono caricati solo i QSO con STATION_CALLSIGN = " + call);
            lInfo.Margin = Ui.P(3, 4, 3, 8);
            Span(t, lInfo, 1);

            cMissing = new CheckBox();
            cMissing.Text = "Includi anche i QSO senza STATION_CALLSIGN (verranno assegnati a " + call + ")";
            cMissing.AutoSize = true;
            cMissing.CheckedChanged += (s, e) => RefreshSummary();
            Span(t, cMissing, 2);

            eFrom = new TextBox();
            eFrom.Width = Ui.S(90);
            eTo = new TextBox();
            eTo.Width = Ui.S(90);
            eFrom.TextChanged += (s, e) => RefreshSummary();
            eTo.TextChanged += (s, e) => RefreshSummary();
            t.Controls.Add(Lbl("Solo QSO dal"), 0, 3);
            t.Controls.Add(eFrom, 1, 3);
            t.Controls.Add(Lbl("al"), 2, 3);
            t.Controls.Add(eTo, 3, 3);
            t.Controls.Add(Lbl("(AAAA-MM-GG, vuoto = qualsiasi data)"), 4, 3);

            summary = new Label();
            summary.AutoSize = true;
            summary.Font = new Font("Consolas", 9F);
            summary.Margin = Ui.P(3, 10, 3, 10);
            Span(t, summary, 4);

            var btns = new FlowLayoutPanel();
            btns.AutoSize = true;
            btns.FlowDirection = FlowDirection.RightToLeft;
            btns.Anchor = AnchorStyles.Right;
            var bCancel = new Button();
            bCancel.Text = "Annulla";
            bCancel.AutoSize = true;
            bCancel.DialogResult = DialogResult.Cancel;
            bOk = new Button();
            bOk.Text = "Carica su Club Log";
            bOk.AutoSize = true;
            bOk.Padding = Ui.P(6, 1, 6, 1);
            bOk.Click += (s, e) => Confirm();
            btns.Controls.Add(bCancel);
            btns.Controls.Add(bOk);
            Span(t, btns, 5);
            CancelButton = bCancel;

            Controls.Add(t);
            ResumeLayout(false);
            PerformLayout();
            RefreshSummary();
        }

        static Label Lbl(string text)
        {
            var l = new Label();
            l.Text = text;
            l.AutoSize = true;
            l.Anchor = AnchorStyles.Left;
            return l;
        }

        static void Span(TableLayoutPanel t, Control c, int row)
        {
            t.Controls.Add(c, 0, row);
            t.SetColumnSpan(c, 5);
        }

        static string ParseDate(string text)
        {
            string digits = Regex.Replace(text, @"\D", "");
            if (digits.Length == 0)
                return "";
            DateTime d;
            if (!DateTime.TryParseExact(digits, "yyyyMMdd", Adif.Inv, System.Globalization.DateTimeStyles.None, out d))
                throw new FormatException();
            return digits;
        }

        void RefreshSummary()
        {
            string dfrom, dto;
            try
            {
                dfrom = ParseDate(eFrom.Text);
                dto = ParseDate(eTo.Text);
            }
            catch (FormatException)
            {
                summary.Text = "Data non valida: usa il formato AAAA-MM-GG.";
                summary.ForeColor = MainForm.Colors["err"];
                bOk.Text = "Carica su Club Log";
                bOk.Enabled = false;
                return;
            }
            res = Adif.AnalyzeImport(records, call, includeFreq, cMissing.Checked, dfrom, dto);
            int n = res.Selected.Count;
            var lines = new List<string> {
                string.Format("QSO nel file:                     {0}", res.Total),
                string.Format("QSO di {0,-10} da caricare:     {1}", call, n) };
            if (n > 0)
                lines.Add(string.Format("   periodo: {0}  ->  {1}", Adif.FormatStamp(res.First), Adif.FormatStamp(res.Last)));
            var others = res.Others.OrderByDescending(kv => kv.Value).ToList();
            lines.Add(string.Format("Altri nominativi (esclusi):       {0}", res.Others.Values.Sum()));
            if (others.Count > 0)
                lines.Add("   " + string.Join(", ", others.Take(6).Select(kv => kv.Key + ": " + kv.Value)) +
                          (others.Count > 6 ? ", ..." : ""));
            lines.Add(string.Format("Senza STATION_CALLSIGN ({0}):  {1}", cMissing.Checked ? "inclusi" : "esclusi", res.Missing));
            if (dfrom.Length > 0 || dto.Length > 0)
                lines.Add(string.Format("Fuori dall'intervallo di date:    {0}", res.OutOfRange));
            lines.Add(string.Format("Non validi (data/banda/modo):     {0}", res.Invalid));
            summary.Text = string.Join("\n", lines);
            summary.ForeColor = MainForm.Colors["info"];
            bOk.Text = string.Format("Carica su Club Log ({0} QSO)", n);
            bOk.Enabled = n > 0;
        }

        void Confirm()
        {
            var selected = res.Selected;
            if (MessageBox.Show(this, string.Format("Caricare {0} QSO nel log Club Log di {1}?\n\n" +
                    "I QSO vengono UNITI al log esistente: nessun QSO viene cancellato " +
                    "e quelli già presenti vengono riconosciuti da Club Log.", selected.Count, call),
                    App.Name, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                return;
            string job;
            try
            {
                job = Adif.CreateImportJob(selected, path);
            }
            catch (Exception e)
            {
                MessageBox.Show(this, "Impossibile preparare il file da inviare:\n" + e.Message, App.Name,
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            string rel = job.StartsWith(App.BaseDir + "\\", StringComparison.OrdinalIgnoreCase)
                ? job.Substring(App.BaseDir.Length + 1) : job;
            owner.AddLog("info", string.Format("Log importato da {0}: {1} QSO di {2} pronti in {3}",
                Path.GetFileName(path), selected.Count, call, rel));
            if (!owner.engine.Running || owner.engine.Uploader.DryRun)
                owner.AddLog("warn", "Il log importato verrà inviato appena avvii l'ascolto con la modalità TEST disattivata.");
            owner.engine.Uploader.Wake.Set();
            Close();
        }
    }
}
