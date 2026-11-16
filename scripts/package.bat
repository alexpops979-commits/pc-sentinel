@echo off
rem Собирает переносимый пакет приложения в dist-package\.
rem Из него делается установщик (scripts\setup.bat) или архив для GitHub Releases.
setlocal
set ROOT=%~dp0..
set OUT=%ROOT%\dist-package
set AGENT=%ROOT%\agent\target\release\pc-sentinel.exe

if not exist "%AGENT%" (
  echo [!] Не найден агент. Сначала запустите build.bat
  exit /b 1
)
if not exist "%ROOT%\dist\index.html" (
  echo [!] Не найден интерфейс. Сначала запустите build.bat
  exit /b 1
)

echo === Сборка пакета ===
if exist "%OUT%" rmdir /s /q "%OUT%"
mkdir "%OUT%"
mkdir "%OUT%\dist"
mkdir "%OUT%\dist\styles"

copy /Y "%AGENT%" "%OUT%\pc-sentinel.exe" >nul || exit /b 1
copy /Y "%ROOT%\dist\index.html" "%OUT%\dist\index.html" >nul || exit /b 1
copy /Y "%ROOT%\dist\main.js" "%OUT%\dist\main.js" >nul || exit /b 1
copy /Y "%ROOT%\dist\styles\app.css" "%OUT%\dist\styles\app.css" >nul || exit /b 1
if exist "%ROOT%\dist\icon.png" copy /Y "%ROOT%\dist\icon.png" "%OUT%\dist\icon.png" >nul
if exist "%ROOT%\dist\app.ico" copy /Y "%ROOT%\dist\app.ico" "%OUT%\dist\app.ico" >nul

for %%F in (rules.txt signatures.txt yara.txt heuristics.txt) do (
  if exist "%ROOT%\%%F" copy /Y "%ROOT%\%%F" "%OUT%\%%F" >nul
)

copy /Y "%ROOT%\LICENSE" "%OUT%\LICENSE" >nul
copy /Y "%ROOT%\README.md" "%OUT%\README.md" >nul

echo Готово: %OUT%
echo.
echo Установка: "%OUT%\pc-sentinel.exe" --install
