@echo off

git add --all

set "MSG=%~1"
if "%MSG%"=="" set "MSG=fix mov to handle 16-bit values and added STORE and HSTORE"

git status

git commit -m "%MSG%"

git push origin main

pause
