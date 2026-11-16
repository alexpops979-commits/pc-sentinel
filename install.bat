@echo off
setlocal
set ROOT=%~dp0

if not exist "%ROOT%dist\index.html" (
  echo === Сначала сборка интерфейса ===
  call "%ROOT%build.bat" || exit /b 1
)

if not exist "%ROOT%agent\target\release\pc-sentinel.exe" (
  echo [!] Не найден агент. Запустите build.bat
  exit /b 1
)

echo === Установка PC Sentinel ===
"%ROOT%agent\target\release\pc-sentinel.exe" --install
if errorlevel 1 exit /b 1

echo.
echo Готово. Ярлык «PC Sentinel» появился на рабочем столе и в меню Пуск.
if "%~1"=="" pause
