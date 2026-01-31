@echo off

git add --all

set "MSG=%~1"
if "%MSG%"=="" set "MSG=minimal interrupt system will better it"

git status

git commit -m "%MSG%"

git push origin main

pause
