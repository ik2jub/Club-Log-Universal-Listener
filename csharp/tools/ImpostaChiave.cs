// Crea chiave_api.cs con la API key Club Log offuscata, da integrare nel programma.
// Lo compila e lo avvia compila_con_chiave.bat. Stesso offuscamento di chiave_api.py
// della versione Python.
// chiave_api.cs è escluso da git: NON pubblicarlo e NON pubblicare l'eseguibile
// creato con compila_con_chiave.bat, che contiene la chiave.

using System;
using System.IO;
using System.Text;

namespace ClubLogListener
{
    static class ImpostaChiave
    {
        // Legge la chiave senza mostrarla (funziona anche incollandola)
        static string ReadHidden()
        {
            if (Console.IsInputRedirected)
                return Console.In.ReadLine() ?? "";
            var sb = new StringBuilder();
            while (true)
            {
                ConsoleKeyInfo k = Console.ReadKey(true);
                if (k.Key == ConsoleKey.Enter)
                    break;
                if (k.Key == ConsoleKey.Backspace)
                {
                    if (sb.Length > 0)
                        sb.Length--;
                }
                else if (k.KeyChar != '\0')
                    sb.Append(k.KeyChar);
            }
            Console.WriteLine();
            return sb.ToString();
        }

        static int Main(string[] args)
        {
            string path = Path.GetFullPath(args.Length > 0 ? args[0] : "chiave_api.cs");
            Console.WriteLine("Imposta la API key Club Log da integrare nel programma.");
            Console.WriteLine("La chiave si richiede qui: https://clublog.org/requestapikey.php");
            Console.WriteLine();
            Console.Write("Incolla la API key (non viene mostrata) e premi Invio: ");
            string key = ReadHidden().Trim();
            if (key.Length == 0)
            {
                Console.WriteLine("Nessuna chiave inserita: niente da fare.");
                return 1;
            }
            string hidden = BuiltinKey.Obfuscate(key);
            if (BuiltinKey.Reveal(hidden) != key)
            {
                Console.WriteLine("Errore interno: la chiave non si rilegge correttamente.");
                return 1;
            }
            File.WriteAllText(path,
                "// API key Club Log offuscata, generata da compila_con_chiave.bat.\r\n" +
                "// NON PUBBLICARE questo file (è escluso da git).\r\n" +
                "static class ChiaveApi\r\n{\r\n    public const string CHIAVE = \"" + hidden + "\";\r\n}\r\n",
                new UTF8Encoding(false));
            Console.WriteLine();
            Console.WriteLine("Creato " + path);
            return 0;
        }
    }
}
