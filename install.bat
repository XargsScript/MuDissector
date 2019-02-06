@echo off

pushd %0\..

mkdir %USERPROFILE%\AppData\Roaming\Wireshark\Plugins > NUL 2>&1

xcopy .\dissector.lua %USERPROFILE%\AppData\Roaming\Wireshark\Plugins\ /Y >nul

