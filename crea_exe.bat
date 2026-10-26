@echo off
rem Crea dist\ClubLogUniversalListener.exe con la API key integrata.
rem L'eseguibile contiene la chiave: distribuiscilo SOLO ai membri del gruppo, NON pubblicarlo.
setlocal
cd /d "%~dp0"

if not exist chiave_api.py (
    echo API key non ancora impostata.
    python imposta_chiave_api.py || goto :errore
)

echo.
echo Installazione/aggiornamento di PyInstaller, pystray e Pillow...
python -m pip install --upgrade --quiet pyinstaller pystray pillow || goto :errore

echo Creazione dell'eseguibile...
python -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name ClubLogUniversalListener --hidden-import chiave_api ^
    --distpath dist --workpath build --specpath build ^
    clublog_listener.pyw || goto :errore

echo.
echo Creato: %~dp0dist\ClubLogUniversalListener.exe
echo ATTENZIONE: contiene la API key. Distribuiscilo solo al tuo gruppo, NON pubblicarlo.
pause
exit /b 0

:errore
echo.
echo Errore durante la creazione dell'eseguibile.
pause
exit /b 1
