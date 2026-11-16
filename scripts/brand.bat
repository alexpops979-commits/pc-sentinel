@echo off
rem Встраивает иконку, версию и манифест в собранный exe.
rem rcedit лежит в .tools; при отсутствии пытаемся скачать один раз.
setlocal
set ROOT=%~dp0..
set RCEDIT=%ROOT%\.tools\rcedit.exe
set EXE=%ROOT%\agent\target\release\pc-sentinel.exe
set ICO=%ROOT%\public\app.ico

if not exist "%EXE%" (
  echo [!] Не найден %EXE%
  exit /b 1
)

if not exist "%ICO%" (
  "%ROOT%\tools\icobuild\target\release\icobuild.exe" "%ROOT%\public\icon.png" "%ICO%" || exit /b 1
)

if not exist "%RCEDIT%" (
  echo [i] Скачиваем rcedit...
  curl -k -L -s -o "%RCEDIT%" "https://github.com/electron/rcedit/releases/download/v2.0.0/rcedit-x64.exe"
)
if not exist "%RCEDIT%" (
  echo [!] rcedit недоступен — иконка не встроена, приложение работает без неё
  exit /b 0
)

"%RCEDIT%" "%EXE%" ^
  --set-icon "%ICO%" ^
  --application-manifest "%ROOT%\agent\app.manifest" ^
  --set-file-version "1.0.0.0" ^
  --set-product-version "1.0.0.0" ^
  --set-version-string "ProductName" "PC Sentinel" ^
  --set-version-string "FileDescription" "PC Sentinel — диагностика и оптимизация ПК" ^
  --set-version-string "CompanyName" "PC Sentinel" ^
  --set-version-string "LegalCopyright" "Локальный инструмент диагностики" ^
  --set-version-string "OriginalFilename" "pc-sentinel.exe" ^
  --set-version-string "InternalName" "pc-sentinel" || exit /b 1

echo [ok] Иконка и версия встроены
