@echo off

git add --all

set "MSG=%~1"
if "%MSG%"=="" set "MSG=MASSIVE upgrade chat like actually mssive like maybe `15 instructions or smth"

git status

git commit -m "%MSG%"

git push origin main

pause
