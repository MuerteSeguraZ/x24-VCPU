@echo off
REM Switch to main branch (create if it doesn't exist)
git checkout main 2>nul
if %errorlevel% neq 0 git checkout -b main

REM Add all changes
git add --all

REM Commit with fixed message
git commit -m "increment/decrement shortcuts and negation"

REM Set remote origin if not already set
git remote | findstr origin >nul
if %errorlevel% neq 0 git remote add origin https://github.com/MuerteSeguraZ/x24.git

REM Push to remote main
git push -u origin main

pause
