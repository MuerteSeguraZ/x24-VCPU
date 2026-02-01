@echo off

git add --all

set "MSG=%~1"
if "%MSG%"=="" set "MSG=I/O port isolation (IN, OUT, INW, OUTW, SETIOPL, IOALLOW, IODENY, ENABLEIOMAP, DISABLEIOMAP)"

git status

git commit -m "%MSG%"

git push origin main

pause
