@echo off
setlocal
set ROOT=%~dp0
set ESBUILD=%ROOT%.tools\package\esbuild.exe
set RCEDIT=%ROOT%.tools\rcedit.exe

if not exist "%ESBUILD%" (
  echo [!] Не найден %ESBUILD%
  exit /b 1
)
if not exist "%ROOT%dist" mkdir "%ROOT%dist"
if not exist "%ROOT%dist\styles" mkdir "%ROOT%dist\styles"

echo [1/4] TypeScript -^> dist\main.js
"%ESBUILD%" "%ROOT%src\main.ts" --bundle --format=esm --target=es2022 --outfile="%ROOT%dist\main.js" --log-level=warning || exit /b 1

echo [2/4] CSS -^> dist\styles\app.css
"%ESBUILD%" "%ROOT%src\styles\app.css" --bundle --outfile="%ROOT%dist\styles\app.css" --log-level=warning || exit /b 1

echo [3/4] Статика
copy /Y "%ROOT%index.html" "%ROOT%dist\index.html" >nul
copy /Y "%ROOT%public\icon.png" "%ROOT%dist\icon.png" >nul
copy /Y "%ROOT%public\app.ico" "%ROOT%dist\app.ico" >nul

echo [4/4] Агент
cargo +stable-x86_64-pc-windows-gnu build --release --manifest-path "%ROOT%agent\Cargo.toml" || exit /b 1
copy /Y "%ROOT%rules.txt" "%ROOT%agent\target\release\rules.txt" >nul

call "%ROOT%scripts\brand.bat"

echo Готово: dist\ и agent\target\release\pc-sentinel.exe
