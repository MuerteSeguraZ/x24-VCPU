@echo off

git add --all

set "MSG=%~1"
if "%MSG%"=="" set "MSG=hardware device stuff"

git status

git commit -m "%MSG%"

git push origin main

pause
