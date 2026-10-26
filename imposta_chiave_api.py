"""
Crea chiave_api.py con la API key Club Log offuscata, da integrare nel programma.

chiave_api.py è escluso da git: NON pubblicarlo e NON pubblicare l'eseguibile
creato con crea_exe.bat, che contiene la chiave.
"""

import getpass
import importlib.machinery
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_listener():
    path = os.path.join(HERE, "clublog_listener.pyw")
    loader = importlib.machinery.SourceFileLoader("clublog_listener", path)
    spec = importlib.util.spec_from_loader("clublog_listener", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def main():
    print("Imposta la API key Club Log da integrare nel programma.")
    print("La chiave si richiede qui: https://clublog.org/requestapikey.php\n")
    key = getpass.getpass("Incolla la API key (non viene mostrata) e premi Invio: ").strip()
    if not key:
        print("Nessuna chiave inserita: niente da fare.")
        return 1
    listener = load_listener()
    hidden = listener.obfuscate_key(key)
    if listener.reveal_key(hidden) != key:
        print("Errore interno: la chiave non si rilegge correttamente.")
        return 1
    path = os.path.join(HERE, "chiave_api.py")
    with open(path, "w", encoding="utf-8") as f:
        f.write("# API key Club Log offuscata, generata da imposta_chiave_api.py.\n"
                "# NON PUBBLICARE questo file (è escluso da git).\n"
                "CHIAVE = \"%s\"\n" % hidden)
    print("\nCreato %s" % path)
    print("Il programma ora usa la chiave integrata e nasconde il campo API key.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
