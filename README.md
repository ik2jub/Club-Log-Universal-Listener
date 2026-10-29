# Club Log Universal Listener

Riceve in tempo reale i QSO via UDP da **DXLog, QARTest, WSJT-X, JTDX e MSHV** e li carica sul log
[Club Log](https://clublog.org) di una spedizione o di una stazione. Un solo programma, con interfaccia
grafica, al posto di più gateway diversi.

*English: a small Windows GUI that listens on up to five UDP ports for logged QSOs from DXLog, QARTest,
WSJT-X, JTDX and MSHV and uploads them to Club Log in real time (realtime.php), with a persistent queue,
batch catch-up uploads (putlogs.php), ADIF import filtered by station callsign, and a tray icon.*

## Funzioni

- **Finestra compatta a schede**: "Club Log" (credenziali e opzioni) e "UDP" (porte in ascolto), con
  i pulsanti e l'area messaggi sempre visibili sotto. Le impostazioni si salvano da sole a ogni modifica.
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
- **Recupero dei QSO registrati a listener spento** (WSJT-X, JTDX, MSHV): mentre ascolta, il
  programma salva ogni minuto l'ultimo momento in ascolto per ogni programma. Al riavvio dell'ascolto
  (dopo la chiusura, "Ferma", lo spegnimento di Windows, un crash o una mancanza di corrente) legge il log
  del programma e mette in coda i QSO registrati nel frattempo, con 5 minuti di margine. I QSO già
  ricevuti (presenti in `qso_ricevuti.adi`) non vengono rimandati. I log vengono trovati da soli:
  - WSJT-X e JTDX: `%LOCALAPPDATA%\WSJT-X\wsjtx_log.adi` e `%LOCALAPPDATA%\JTDX\wsjtx_log.adi` (percorso
    fisso, non configurabile nei programmi), comprese le istanze avviate con `--rig-name`;
  - MSHV: nella cartella di installazione, letta dal registro di Windows. Con l'opzione **Use Save QSOs
    In ADIF Log** del menu del log (attiva di default) si usa `log\mshvlog.adi`, dove MSHV aggiunge ogni
    QSO con il nominativo usato in quel momento. Se l'opzione è spenta si usa `log\mshvlog.edim`, che
    non ha il nominativo di ogni QSO: si usa quello impostato in MSHV, come fa MSHV stesso. In questo
    caso il listener salva anche il nominativo di MSHV insieme all'ultimo momento in ascolto: se al
    riavvio è diverso, i QSO del periodo non vengono recuperati ma elencati in rosso, da controllare e
    caricare a mano. Le correzioni fatte in MSHV a un QSO non arrivano in `mshvlog.adi`.

  Al primo avvio non c'è un periodo da controllare. Se il programma gira su un altro PC il suo log non è
  raggiungibile e il recupero non avviene.
- **Importazione di un log ADIF pregresso**: carica solo i QSO con `STATION_CALLSIGN` uguale al nominativo
  impostato, con filtro facoltativo per date. I QSO vengono **uniti** al log esistente (nessuna
  cancellazione).
- **QSO inseriti a mano** (pulsante **Nuovo QSO...**): nominativo, data e ora UTC, banda, modo e rapporti.
  Il QSO segue la stessa strada di quelli ricevuti (copia in `qso_ricevuti.adi`, coda, modalità TEST).
  Prima dell'invio il programma avvisa se c'è già un QSO con lo stesso nominativo e la stessa banda
  nell'ora vicina.
- **Cerca, correggi e cancella** (pulsante **Cerca QSO...**): elenca i QSO passati dal listener, con data
  e ora inviate a Club Log e lo stato (ricevuto, in coda, cancellato, rifiutato), filtrabili per
  nominativo, data e banda.
  - **Cancella da Club Log** usa l'API `delete.php` di Club Log, che vuole data e ora esatte: per questo
    si usano quelle salvate in `qso_ricevuti.adi`. Un QSO ancora in coda viene solo tolto dalla coda. La
    cancellazione non si può annullare; quelle fatte restano in `qso_cancellati.adi`.
  - **Correggi** cancella il QSO sbagliato e invia quello corretto, come suggerisce Club Log.
  - Club Log permette di cancellare con le API solo i QSO su 160-10 m, 6, 4 e 2 m, 70, 23 e 13 cm; gli
    altri vanno cancellati dal sito.
  - **Scarica log da Club Log** scarica tutto il log (API `getadif.php`) in `log_clublog.adi`: nell'elenco
    compaiono anche i QSO caricati in altro modo (dal sito, da altri PC o programmi), con stato "su Club
    Log", e si possono cancellare o correggere. Per non caricare Club Log, tra due download devono
    passare almeno 5 minuti.
- **Aggiunta ai log dei programmi** (spunte nella finestra del QSO, mai in modalità TEST):
  - WSJT-X e JTDX: il QSO viene aggiunto in fondo a `wsjtx_log.adi`, nel loro formato, dopo averne
    salvato una copia in `copie_log_programmi\`. Il programma lo vede come già collegato dopo il riavvio.
    Un QSO corretto resta nel loro log: WSJT-X e JTDX non hanno un comando per cancellarlo.
  - MSHV: il log di MSHV non va scritto da fuori, quindi il listener prepara un file in
    `da_importare_in_MSHV\` da aggiungere con il comando **Add ADIF To Log** della finestra del log di
    MSHV. Dal codice di MSHV (`HvLogW::AddExtrnalAdif`):
    - l'importazione non trasmette il QSO via UDP né a Club Log;
    - non controlla i doppioni, quindi ogni file va importato una volta sola;
    - accetta solo i modi di MSHV (FT8, FT4, MSK144, JT65, Q65, SSB, CW, FM...): per gli altri, ad
      esempio RTTY, il file non viene creato.

    Non inserire lo stesso QSO anche a mano in MSHV: MSHV lo trasmetterebbe e arriverebbe due volte.
    Un QSO corretto va cancellato in MSHV (finestra del log: selezionalo e premi **DELETE SELECTED**),
    oppure lo si corregge direttamente con **EDIT QSO**. Cancellazioni e correzioni cambiano solo
    `mshvlog.edim`: in `mshvlog.adi` il QSO vecchio resta, ma il listener non lo rimanda.
- **Controllo del nominativo**: i QSO ricevuti con `STATION_CALLSIGN` diverso dal nominativo DX
  impostato vengono scartati e segnalati in rosso nei messaggi (i QSO senza `STATION_CALLSIGN` sono
  accettati).
- **Orario di fine QSO**: se il QSO ha sia l'inizio sia la fine (`TIME_ON` e `TIME_OFF`, come in
  WSJT-X, JTDX e MSHV), a Club Log vengono inviate la data e l'ora di **fine**, anche per i log
  importati. Per i QSO a cavallo della mezzanotte UTC vale la data di fine (`QSO_DATE_OFF`); se manca, è
  il giorno dopo l'inizio quando l'ora di fine è minore di quella di inizio.
- **Doppioni**: WSJT-X e JTDX inviano ogni QSO in due formati; ne viene caricato uno solo.
- **Modalità TEST**: riceve e mostra i QSO senza inviarli, per verificare la configurazione.
- **Icona nella tray bar** con colore di stato (verde online, arancione test, rosso errore) e notifiche
  degli errori.
- **Avvio con Windows** (spunta): all'accensione del PC il programma parte ridotto a icona; con
  "Avvia ascolto all'apertura" riceve e invia i QSO senza toccare niente. La voce di avvio è una sola
  per la versione Python e per quella C#: spuntandola in una si toglie dall'altra.
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

## Versione C# (senza Python)

La cartella [`csharp`](csharp) contiene lo stesso programma scritto in C#, per **.NET Framework 4.8**, che
è già incluso in Windows 10 e 11: l'eseguibile gira su qualsiasi PC Windows senza installare niente, e
l'icona nella tray bar c'è sempre.

- Doppio clic su `csharp\compila.bat`: crea `csharp\ClubLogUniversalListener.exe` con il compilatore C#
  che Windows contiene già.
- L'icona del programma è `icona.ico` (tutti i formati da 16 a 256 pixel, per Esplora risorse,
  desktop, barra delle applicazioni e Alt+Tab): la usano sia l'exe C# sia quello creato da `crea_exe.bat`.
  Se manca, `compila.bat` la ricrea.
- Stesse funzioni e stessi file dati della versione Python (impostazioni, coda, ADIF): passando da una
  versione all'altra con lo stesso utente Windows, impostazioni e password cifrate restano valide.
- Versione con API key integrata per il gruppo: `csharp\compila_con_chiave.bat` chiede la chiave la prima
  volta (crea `csharp\chiave_api.cs`, escluso da git) e crea `csharp\dist\ClubLogUniversalListener.exe`,
  da distribuire **solo al gruppo**.

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

I QSO di prova finiscono anche in `qso_ricevuti.adi`: cancellalo dopo le prove, anche perché i QSO presenti
in quel file risultano già ricevuti e non vengono recuperati dai log dei programmi.

## File creati dal programma

| File | Contenuto |
|---|---|
| `clublog_listener.json` | Impostazioni (password e API key cifrate; la chiave integrata non viene mai salvata qui) |
| `clublog_listener_coda.json` | QSO in attesa di invio |
| `clublog_listener_stato.json` | Ultimo momento in ascolto per ogni programma (per il recupero dei QSO) |
| `qso_ricevuti.adi` | Copia ADIF di tutti i QSO ricevuti |
| `qso_rifiutati.adi` | QSO scartati da Club Log come non validi |
| `qso_cancellati.adi` | QSO cancellati da Club Log o tolti dalla coda con "Cerca QSO..." |
| `log_clublog.adi` | Ultimo log scaricato da Club Log con "Scarica log da Club Log" |
| `copie_log_programmi\` | Copia di `wsjtx_log.adi` di WSJT-X/JTDX prima dell'ultima aggiunta di un QSO |
| `da_importare_in_MSHV\` | QSO inseriti a mano da aggiungere al log di MSHV con Add ADIF To Log |
| `caricamenti_in_attesa\` / `caricamenti_inviati\` | Log ADIF importati, prima e dopo l'invio |

## Limiti noti

- Club Log non pubblica limiti numerici per le sue API: i valori di default (5 s tra due QSO, invio a
  blocchi da 20 QSO in coda, 5 minuti tra due blocchi) sono scelte prudenti.
- L'heartbeat del Live Stream è una funzione riservata al Club Log Gateway ufficiale e non è supportato.
- Versione iniziale: i formati sono stati provati con pacchetti simulati. Segnalazioni e correzioni sono
  benvenute tramite le *Issues* del progetto.

## Licenza

[MIT](LICENSE) © 2026 IK2JUB
