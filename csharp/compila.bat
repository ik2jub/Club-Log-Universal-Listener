@echo off
rem Compila ClubLogUniversalListener.exe con il compilatore C# incluso in Windows
rem (.NET Framework 4.8): non serve installare niente.
rem Senza parametri crea la versione senza API key integrata.
rem Con --con-chiave (lo usa compila_con_chiave.bat) integra chiave_api.cs e crea dist\.
setlocal
cd /d "%~dp0"

set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
    echo Compilatore C# di .NET Framework 4 non trovato.
    goto :errore
)

set "OUT=ClubLogUniversalListener.exe"
set "KEY="
if "%~1"=="--con-chiave" (
    if not exist chiave_api.cs (
        echo chiave_api.cs non trovato: usa compila_con_chiave.bat.
        goto :errore
    )
    if not exist dist mkdir dist
    set "OUT=dist\ClubLogUniversalListener.exe"
    set "KEY=/define:CHIAVE_API chiave_api.cs"
)

set "REFS=/r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Security.dll /r:System.Web.Extensions.dll /r:System.Windows.Forms.dll /r:System.Xml.dll"

rem Icona del programma (Esplora risorse, desktop, barra delle applicazioni): la crea se manca
set "ICO=%~dp0..\icona.ico"
if not exist "%ICO%" (
    if not exist build mkdir build
    "%CSC%" /nologo /utf8output /codepage:65001 /target:exe /main:ClubLogListener.CreaIcona ^
        /out:build\crea_icona.exe %REFS% src\*.cs tools\CreaIcona.cs || goto :errore
    build\crea_icona.exe "%ICO%" || goto :errore
)

"%CSC%" /nologo /utf8output /codepage:65001 /target:winexe /optimize+ /out:%OUT% %REFS% ^
    /win32icon:"%ICO%" /resource:"%ICO%",icona.ico ^
    src\*.cs %KEY% || goto :errore

echo.
echo Creato: %~dp0%OUT%
if defined KEY echo ATTENZIONE: contiene la API key. Distribuiscilo solo al tuo gruppo, NON pubblicarlo.
if not "%~2"=="--senza-pausa" pause
exit /b 0

:errore
echo.
echo Errore durante la compilazione.
if not "%~2"=="--senza-pausa" pause
exit /b 1
