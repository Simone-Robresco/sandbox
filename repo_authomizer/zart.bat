@echo off

:: colore azzurro
color 0B

:: stampa logo dalla cartella git-sync
type "%~dp0git-sync\logo.txt"

:: torna colore normale
color 07

:: entra nella cartella
cd /d "%~dp0git-sync"

:: avvia python
python z_git-sync.py

pause