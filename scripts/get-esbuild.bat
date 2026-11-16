@echo off
rem Скачивает esbuild в .tools\package, если его нет.
rem Нужен для сборки интерфейса: посторонний человек клонирует репозиторий
rem и должен получить рабочую сборку без ручной подготовки окружения.
setlocal
set ROOT=%~dp0..
rem Внимание: %~dp0.. не содержит завершающего обратного слэша,
rem поэтому разделитель нужен явно, иначе получится «...scripts\...tools».
set DEST=%ROOT%\.tools\package
set EXE=%DEST%\esbuild.exe
set VERSION=0.28.2
set TGZ=%ROOT%\.tools\esbuild.tgz
set TMPDIR=%ROOT%\.tools\esbuild-tmp

if exist "%EXE%" (
  exit /b 0
)

where curl >nul 2>&1
if errorlevel 1 (
  echo [!] Не найден curl — скачайте esbuild вручную:
  echo     https://registry.npmjs.org/@esbuild/win32-x64/-/win32-x64-%VERSION%.tgz
  echo     распакуйте esbuild.exe в %DEST%
  exit /b 1
)

echo [i] Скачиваем esbuild %VERSION%...
if not exist "%ROOT%\.tools" mkdir "%ROOT%\.tools"
curl -k -L -s -o "%TGZ%" "https://registry.npmjs.org/@esbuild/win32-x64/-/win32-x64-%VERSION%.tgz"
if not exist "%TGZ%" (
  echo [!] Не удалось скачать esbuild
  exit /b 1
)

if exist "%TMPDIR%" rmdir /s /q "%TMPDIR%"
mkdir "%TMPDIR%" 2>nul
tar -xzf "%TGZ%" -C "%TMPDIR%"
if errorlevel 1 (
  echo [!] Не удалось распаковать esbuild
  exit /b 1
)

if not exist "%DEST%" mkdir "%DEST%"
copy /Y "%TMPDIR%\package\esbuild.exe" "%EXE%" >nul
if exist "%TMPDIR%\package\LICENSE.txt" copy /Y "%TMPDIR%\package\LICENSE.txt" "%DEST%\LICENSE.txt" >nul
rmdir /s /q "%TMPDIR%" 2>nul
del /q "%TGZ%" 2>nul

if not exist "%EXE%" (
  echo [!] esbuild не установлен
  exit /b 1
)
echo [ok] esbuild готов
exit /b 0
