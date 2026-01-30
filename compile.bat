@echo off

echo [*] Deleting old test.exe...
if exist test.exe del test.exe

echo [*] Compiling test program...
g++ -std=c++17 main.cpp -O2 -o test.exe

if exist test.exe (
    echo [*] Success! Run 'test' to execute
) else (
    echo [!] Compilation failed!
)