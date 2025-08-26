@echo off

git checkout master

git add --all

set "MSG=%~1"
if "%MSG%"=="" set "MSG=Added za bitwise operations"

git status

git commit -m "%MSG%"

git push -u origin master

pause
