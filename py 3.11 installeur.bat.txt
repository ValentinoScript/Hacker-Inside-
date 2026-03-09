@echo off
REM Télécharge l’installateur Python 3.11 pour Windows (64-bit)

echo Téléchargement de Python 3.11...
powershell -Command "Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.11.5/python-3.11.5-amd64.exe -OutFile python-3.11.5-amd64.exe"

IF EXIST python-3.11.5-amd64.exe (
    echo Installation silencieuse...
    python-3.11.5-amd64.exe /quiet InstallAllUsers=1 PrependPath=1

    IF %ERRORLEVEL% EQU 0 (
        echo Installation terminée avec succès.
    ) ELSE (
        echo Une erreur s’est produite pendant l’installation.
    )
) ELSE (
    echo Échec du téléchargement de l’installateur.
)

echo Vérification de l’installation...
python --version

pause
