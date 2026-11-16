@echo off
rem setup_db.bat - one-time: creates the secureee database and the chat_app MySQL user.
rem Run after installing MySQL Server. Asks for the MySQL root password.
setlocal EnableExtensions EnableDelayedExpansion
title SecureComm - Database setup
cd /d "%~dp0"

set "SQL=instance\create_app_user.sql"
if not exist "%SQL%" (
    python scripts\check_db.py prepare
    if errorlevel 1 goto :end
)

set "MYSQL="
for /d %%D in ("%ProgramFiles%\MySQL\MySQL Server *") do (
    if exist "%%D\bin\mysql.exe" set "MYSQL=%%D\bin\mysql.exe"
)
if not defined MYSQL for /f "delims=" %%P in ('where mysql 2^>nul') do (
    if not defined MYSQL set "MYSQL=%%P"
)
if not defined MYSQL (
    echo [X] mysql.exe not found. Install MySQL Server 8.0 first.
    goto :end
)

echo Using !MYSQL!
echo Enter the MySQL ROOT password you chose during installation.
echo.
"!MYSQL!" -u root -p -h 127.0.0.1 -P 3306 < "%SQL%"
if errorlevel 1 (
    echo.
    echo [X] Setup failed - wrong root password, or MySQL is not running.
    goto :end
)

del /q "%SQL%"
echo.
echo [OK] Database "secureee" and user "chat_app" created.
echo      The setup file was deleted - the password stays in instance\.env.
echo      Now run start.bat.

:end
echo.
pause
