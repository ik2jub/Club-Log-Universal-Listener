// Punto di ingresso.

using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace ClubLogListener
{
    static class Program
    {
        [DllImport("user32.dll")]
        static extern bool SetProcessDPIAware();

        [STAThread]
        static void Main()
        {
            try
            {
                SetProcessDPIAware();  // testo nitido con lo schermo in scala 125-150%
            }
            catch (Exception)
            {
            }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.ThreadException += (s, e) => Fatal(e.Exception);
            AppDomain.CurrentDomain.UnhandledException += (s, e) => Fatal(e.ExceptionObject as Exception);
            Application.Run(new MainForm());
        }

        static void Fatal(Exception e)
        {
            MessageBox.Show("Errore imprevisto:\n\n" + (e != null ? e.ToString() : "sconosciuto"), App.Name,
                            MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
