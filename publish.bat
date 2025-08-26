@echo off

git checkout master

git add --all

git remote set-url origin https://github.com/EditSIMS/x24-VCPU.git

set "MSG=%~1"
if "%MSG%"=="" set "MSG=Added za bitwise operations"

git status

git commit -m "%MSG%"

git push -u origin master

pause
