@echo off
setlocal
set ROOT=%~dp0
set AGENT=%ROOT%agent\target\release\pc-sentinel.exe

if not exist "%AGENT%" (
  echo === Сборка агента ===
  cargo +stable-x86_64-pc-windows-gnu build --release --manifest-path "%ROOT%agent\Cargo.toml" || exit /b 1
)

if not exist "%ROOT%dist\index.html" (
  echo === Сборка интерфейса ===
  call "%ROOT%build.bat" || exit /b 1
)

if not exist "%ROOT%agent\target\release\rules.txt" (
  if exist "%ROOT%rules.txt" copy /Y "%ROOT%rules.txt" "%ROOT%agent\target\release\rules.txt" >nul
)

echo === Запуск PC Sentinel ===
pushd "%ROOT%"
"%AGENT%" %*
popd
