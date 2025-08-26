@echo off

cls
echo [*] Deleting old vcpu.exe...
del vcpu.exe
echo [*] Compiling..
g++ -std=c++17 vcpu.cpp -O2 -o vcpu