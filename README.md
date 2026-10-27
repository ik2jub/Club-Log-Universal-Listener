# Club Log Universal Listener

Riceve in tempo reale i QSO via UDP da **DXLog, QARTest, WSJT-X, JTDX e MSHV** e li carica sul log
[Club Log](https://clublog.org) di una spedizione o di una stazione. Un solo programma, con interfaccia
grafica, al posto di più gateway diversi.

*English: a small Windows GUI that listens on up to five UDP ports for logged QSOs from DXLog, QARTest,
WSJT-X, JTDX and MSHV and uploads them to Club Log in real time (realtime.php), with a persistent queue,
batch catch-up uploads (putlogs.php), ADIF import filtered by station callsign, and a tray icon.*

## Funzioni

- **5 porte UDP**, una per programma. Per ognuna si sceglie l'interfaccia di rete (`0.0.0.0` = tutte,
  `127.0.0.1` o l'IP di una scheda), la porta e, se serve, un gruppo multicast (es. `224.0.0.1`).
- **Riconoscimento automatico del formato** su ogni porta:
  - protocollo binario WSJT-X, messaggi *QSO Logged* (tipo 5) e *Logged ADIF* (tipo 12): WSJT-X, JTDX, MSHV;
  - XML in formato N1MM `<contactinfo>` / `<contactreplace>`: QARTest e DXLog;
  - testo ADIF semplice (es. "secondary UDP server" di WSJT-X/JTDX).
- **Messaggi di stato a video**: ultimo pacchetto ricevuto per ogni porta (anche gli heartbeat), QSO
  ricevuti, conferme e errori di Club Log, contatori. **Alt+W** cancella l'area messaggi.
- **Nessun QSO perso**: la coda dei QSO non ancora inviati è salvata su disco a ogni modifica e
  sopravvive a crash, mancanza di corrente e assenza di internet.
- **Rispetto delle regole di Club Log**: pausa minima configurabile tra due invii, invio a blocchi con
  `putlogs.php` quando la coda cresce (es. dopo un'interruzione della linea), almeno 5 minuti tra due invii
  a blocchi, stop immediato in caso di credenziali rifiutate (HTTP 403).
- **Importazione di un log ADIF pregresso**: carica solo i QSO con `STATION_CALLSIGN` uguale al nominativo
  impostato, con filtro facoltativo per date. I QSO vengono **uniti** al log esistente (nessuna
  cancellazione).
- **Doppioni**: WSJT-X e JTDX inviano ogni QSO in due formati; ne viene caricato uno solo.
- **Modalità TEST**: riceve e mostra i QSO senza inviarli, per verificare la configurazione.
- **Icona nella tray bar** con colore di stato (verde online, arancione test, rosso errore) e notifiche
  degli errori.
- **Credenziali cifrate** con la protezione dati di Windows (DPAPI), legate all'utente del PC.

## Requisiti

- Windows con **Python 3.10 o successivo** ([python.org](https://www.python.org/downloads/)), con tkinter
  (incluso nell'installazione standard).
- Facoltativo, per l'icona nella tray bar:
  ```
  pip install -r requirements.txt
  ```
  Senza questi moduli il programma funziona lo stesso e si riduce nella barra delle applicazioni.

## Avvio

Scarica il codice (pulsante verde **Code → Download ZIP**, oppure `git clone`), poi fai doppio clic su
`avvia_listener.bat` o su `clublog_listener.pyw`.

Impostazioni, coda e file generati vengono salvati nella stessa cartella del programma.

## Credenziali Club Log

| Campo | Cos'è | Dove si ottiene |
|---|---|---|
| Nominativo DX | Il log Club Log in cui caricare i QSO | — |
| Email | L'email del tuo account Club Log | — |
| App password | Password dedicata alle applicazioni | Club Log → Settings → App Passwords |
| API key | Chiave che identifica *il programma* presso Club Log | [clublog.org/requestapikey.php](https://clublog.org/requestapikey.php) |

L'API key è richiesta da Club Log per tutti i programmi che usano le sue API. I logger commerciali la
includono già nel codice; questo programma è open source, quindi **ognuno deve richiedere la propria** e
inserirla nella GUI. Non pubblicare mai la tua API key: Club Log cancella automaticamente le chiavi che
trova pubblicate online.

### Versione con API key integrata (per il proprio gruppo)

Per dare agli operatori di una spedizione un programma pronto all'uso, senza Python e senza il campo
API key:

1. esegui `crea_exe.bat`: la prima volta chiede la API key (tramite `imposta_chiave_api.py`, che crea
   `chiave_api.py` con la chiave offuscata);
2. distribuisci `dist\ClubLogUniversalListener.exe` **solo all'interno del gruppo**.

`chiave_api.py`, `build\` e `dist\` sono esclusi da git. L'offuscamento impedisce solo la lettura a colpo
d'occhio: chi ha l'eseguibile può estrarre la chiave, quindi **non pubblicare l'eseguibile** (né come
release né altrove).

## Configurazione dei programmi

Porte proposte di default (modificabili dalla GUI). Ogni programma deve inviare a una porta diversa.

| Programma | Dove si imposta | Indirizzo / porta |
|---|---|---|
| WSJT-X | Settings → Reporting → UDP Server | `127.0.0.1` : `2237` |
| JTDX | Settings → Reporting → UDP Server | `127.0.0.1` : `2238` |
| MSHV | Network Configuration → UDP Broadcast Settings | `127.0.0.1` : `2239` (o multicast `224.0.0.1`) |
| QARTest | Broadcast UDP | `127.0.0.1` : `12060` |
| DXLog | Options → Broadcast → QSOs, con **Use N1MM QSO format** | `127.0.0.1` : `12061` |

Note:
- In WSJT-X/JTDX/MSHV il QSO viene inviato quando si conferma la finestra **Log QSO**.
- Se un altro programma usa già la stessa porta (es. il Club Log Gateway ufficiale sulla 12060, o
  JTAlert/GridTracker sulla 2237), la riga della porta mostra l'errore "porta occupata": cambia porta o
  usa un indirizzo multicast.
- Le cancellazioni di QSO inviate da DXLog/QARTest vengono segnalate nel log ma vanno fatte a mano su
  Club Log.

## Prova senza i programmi

`simula_pacchetti.py` invia al listener gli stessi pacchetti UDP dei cinque programmi (heartbeat e QSO di
esempio). Avvia il listener in modalità TEST, poi:

```
python simula_pacchetti.py                       tutti e 5 i programmi
python simula_pacchetti.py JTDX QARTest          solo alcuni
python simula_pacchetti.py --host 192.168.1.10   listener su un altro PC
```

I QSO di prova finiscono anche in `qso_ricevuti.adi`: cancellalo dopo le prove.

## File creati dal programma

| File | Contenuto |
|---|---|
| `clublog_listener.json` | Impostazioni (password e API key cifrate; la chiave integrata non viene mai salvata qui) |
| `clublog_listener_coda.json` | QSO in attesa di invio |
| `qso_ricevuti.adi` | Copia ADIF di tutti i QSO ricevuti |
| `qso_rifiutati.adi` | QSO scartati da Club Log come non validi |
| `caricamenti_in_attesa\` / `caricamenti_inviati\` | Log ADIF importati, prima e dopo l'invio |

## Limiti noti

- Club Log non pubblica limiti numerici per le sue API: i valori di default (5 s tra due QSO, invio a
  blocchi da 20 QSO in coda, 5 minuti tra due blocchi) sono scelte prudenti.
- L'heartbeat del Live Stream è una funzione riservata al Club Log Gateway ufficiale e non è supportato.
- Versione iniziale: i formati sono stati provati con pacchetti simulati. Segnalazioni e correzioni sono
  benvenute tramite le *Issues* del progetto.

## Licenza

[MIT](LICENSE) © 2026 IK2JUB
