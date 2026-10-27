// Avvio con Windows: voce in HKCU\...\Run, la stessa per la versione Python e per quella C#, così
// all'accensione parte un solo programma (le porte UDP sono le stesse).

using System;
using System.Windows.Forms;
using Microsoft.Win32;

namespace ClubLogListener
{
    static class AvvioWindows
    {
        const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        const string RunValue = App.Name;
        public const string Arg = "--avvio-windows";  // avviato da Windows: si apre ridotto a icona

        static string Target { get { return Application.ExecutablePath; } }

        // Comando registrato per l'avvio con Windows ("" se non c'è)
        public static string Entry()
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RunKey))
                {
                    object v = key != null ? key.GetValue(RunValue) : null;
                    return v != null ? v.ToString() : "";
                }
            }
            catch (Exception)
            {
                return "";
            }
        }

        public static bool IsMine(string command)
        {
            return command.IndexOf(Target, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static void Set(bool enabled)
        {
            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(RunKey))
            {
                if (enabled)
                    key.SetValue(RunValue, "\"" + Target + "\" " + Arg, RegistryValueKind.String);
                else if (IsMine(Entry()))
                    key.DeleteValue(RunValue, false);
            }
        }

        public static bool StartedByWindows()
        {
            foreach (string a in Environment.GetCommandLineArgs())
                if (a == Arg)
                    return true;
            return false;
        }
    }
}
