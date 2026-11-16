@echo off
rem Builds SkyDLCStudio.exe with Visual Studio 2022 (x64, static CRT, no install needed)
setlocal
set "VS="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq delims=" %%i in (`call "%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS=%%i"
if not defined VS (
    echo Visual Studio with C++ tools not found
    exit /b 1
)
call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1 || exit /b 1
cd /d "%~dp0"
if not exist obj mkdir obj
cl /nologo /std:c++17 /O2 /EHsc /utf-8 /MT /W4 /wd4100 /DUNICODE /D_UNICODE /Foobj\ SkyDLCCore.cpp SkyDLCStudio.cpp /Fe:SkyDLCStudio.exe /link /SUBSYSTEM:WINDOWS /MANIFEST:EMBED || exit /b 1
echo OK: %~dp0SkyDLCStudio.exe
