@echo off
rem Crea dist\ClubLogUniversalListener.exe con la API key integrata.
rem L'eseguibile contiene la chiave: distribuiscilo SOLO ai membri del gruppo, NON pubblicarlo.
setlocal
cd /d "%~dp0"
if exist chiave_api.cs goto :compila

set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
    echo Compilatore C# di .NET Framework 4 non trovato.
    goto :errore
)
if not exist build mkdir build
echo API key non ancora impostata.
"%CSC%" /nologo /utf8output /codepage:65001 /target:exe /main:ClubLogListener.ImpostaChiave ^
    /out:build\imposta_chiave.exe ^
    /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Security.dll ^
    /r:System.Web.Extensions.dll /r:System.Windows.Forms.dll /r:System.Xml.dll ^
    src\*.cs tools\ImpostaChiave.cs || goto :errore
build\imposta_chiave.exe chiave_api.cs || goto :errore

:compila
call "%~dp0compila.bat" --con-chiave
exit /b %errorlevel%

:errore
echo.
echo Errore: chiave non impostata.
pause
exit /b 1
