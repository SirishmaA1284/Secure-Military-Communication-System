@echo off
rem start.bat - starts MySQL (if needed) and the SecureComm web server.
setlocal EnableExtensions EnableDelayedExpansion
title SecureComm Launcher
cd /d "%~dp0"

echo ==================================================
echo   SecureComm - Secure Military Communication
echo ==================================================
echo.

rem ---------------------------------------------------------------- settings
set "MYSQL_HOST=127.0.0.1"
set "MYSQL_PORT=3306"
set "APP_PORT=5000"
set "USE_TLS=1"
if not exist "instance\.env" (
    echo [X] instance\.env not found.
    if exist ".env.example" (
        copy /y ".env.example" "instance\.env" >nul
        echo     Created instance\.env from .env.example.
        echo     Put your MySQL username and password in it, then run start.bat again.
    )
    goto :fail
)
for /f "usebackq eol=# tokens=1,* delims==" %%A in ("instance\.env") do (
    if /i "%%A"=="MYSQL_HOST" set "MYSQL_HOST=%%B"
    if /i "%%A"=="MYSQL_PORT" set "MYSQL_PORT=%%B"
    if /i "%%A"=="APP_PORT"   set "APP_PORT=%%B"
    if /i "%%A"=="USE_TLS"    set "USE_TLS=%%B"
)

rem ---------------------------------------------------------------- 1. Python
echo [1/4] Python
if exist ".venv\Scripts\activate.bat" call ".venv\Scripts\activate.bat"
if exist "venv\Scripts\activate.bat" call "venv\Scripts\activate.bat"
where python >nul 2>&1
if errorlevel 1 (
    echo     [X] Python is not installed or not on PATH.
    goto :fail
)
for /f "delims=" %%V in ('python --version 2^>^&1') do echo     %%V

rem ---------------------------------------------------------------- 2. packages
echo [2/4] Python packages
python -c "import flask, flask_socketio, simple_websocket, Crypto, cryptography, bcrypt, pyotp, qrcode, mysql.connector, dotenv" >nul 2>&1
if errorlevel 1 (
    echo     Installing missing packages from requirements.txt ...
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo     [X] pip install failed.
        goto :fail
    )
) else (
    echo     All required packages are installed.
)

rem ---------------------------------------------------------------- 3. MySQL
echo [3/4] MySQL server at %MYSQL_HOST%:%MYSQL_PORT%
python scripts\check_db.py port
if not errorlevel 1 (
    echo     Already running.
    goto :mysql_check
)

set "IS_LOCAL="
if /i "%MYSQL_HOST%"=="127.0.0.1" set "IS_LOCAL=1"
if /i "%MYSQL_HOST%"=="localhost" set "IS_LOCAL=1"
if not defined IS_LOCAL (
    echo     [X] MySQL on %MYSQL_HOST% is not reachable. Start it on that machine.
    goto :fail
)

rem a^) an installed Windows service such as MySQL80
set "SVC="
for /f "tokens=2 delims=: " %%S in ('sc query state^= all ^| findstr /i /r "SERVICE_NAME:.*mysql SERVICE_NAME:.*maria"') do (
    if not defined SVC set "SVC=%%S"
)
if defined SVC (
    echo     Starting Windows service !SVC! ...
    net start "!SVC!" >nul 2>&1
    if errorlevel 1 (
        echo     Administrator rights are needed - approve the Windows prompt.
        powershell -NoProfile -Command "Start-Process -FilePath net -ArgumentList 'start','!SVC!' -Verb RunAs -Wait -WindowStyle Hidden" >nul 2>&1
    )
    goto :mysql_wait
)

rem b^) a mysqld.exe from MySQL Server, XAMPP or PATH
set "MYSQLD="
set "MYSQL_INI="
for /d %%D in ("%ProgramFiles%\MySQL\MySQL Server *") do (
    if exist "%%D\bin\mysqld.exe" (
        set "MYSQLD=%%D\bin\mysqld.exe"
        set "MYSQL_INI="
        if exist "%ProgramData%\MySQL\%%~nxD\my.ini" set "MYSQL_INI=%ProgramData%\MySQL\%%~nxD\my.ini"
    )
)
if not defined MYSQLD if exist "C:\xampp\mysql\bin\mysqld.exe" (
    set "MYSQLD=C:\xampp\mysql\bin\mysqld.exe"
    if exist "C:\xampp\mysql\bin\my.ini" set "MYSQL_INI=C:\xampp\mysql\bin\my.ini"
)
if not defined MYSQLD for /f "delims=" %%P in ('where mysqld 2^>nul') do (
    if not defined MYSQLD set "MYSQLD=%%P"
)
if defined MYSQLD (
    echo     Starting !MYSQLD! in a separate window ...
    if defined MYSQL_INI (
        start "MySQL Server" /min "!MYSQLD!" --defaults-file="!MYSQL_INI!" --console
    ) else (
        start "MySQL Server" /min "!MYSQLD!" --console
    )
    goto :mysql_wait
)

rem c^) nothing to start
echo.
echo     [X] No MySQL server is installed on this PC.
if exist "%ProgramData%\MySQL\MySQL Server 8.0\my.ini" (
    echo         Your old MySQL 8.0 settings and data are still in %ProgramData%\MySQL,
    echo         but the server program mysqld.exe has been removed.
)
echo         To fix:
echo           1. Download "MySQL Installer for Windows": https://dev.mysql.com/downloads/installer/
echo           2. Install "MySQL Server 8.0" as a Windows service - the default name is MySQL80.
echo           3. Make sure the user in instance\.env exists, then run start.bat again.
goto :fail

:mysql_wait
echo     Waiting for MySQL to accept connections ...
python scripts\check_db.py wait 30
if errorlevel 1 (
    echo     [X] MySQL did not start within 30 seconds.
    echo         Try right-click start.bat - "Run as administrator", or check the MySQL window / error log.
    goto :fail
)

:mysql_check
python scripts\check_db.py check
if errorlevel 1 goto :fail

rem ---------------------------------------------------------------- 4. web server
echo [4/4] SecureComm web server
netstat -ano | findstr /r /c:":%APP_PORT% .*LISTENING" >nul
if not errorlevel 1 (
    echo     [X] Port %APP_PORT% is already in use - is SecureComm already running?
    echo         Close it, or set APP_PORT in instance\.env.
    goto :fail
)
set "SCHEME=https"
if "%USE_TLS%"=="0" set "SCHEME=http"
set "URL=!SCHEME!://localhost:%APP_PORT%"
echo     Opening !URL! in your browser ...
if not "%USE_TLS%"=="0" echo     The certificate is self-signed: the first time, click "Advanced" then "Proceed to localhost".
start "" /b powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 5; Start-Process '!URL!'"
echo     Press Ctrl+C to stop the server.
echo.
python app.py
echo.
echo Server stopped.
pause
exit /b 0

:fail
echo.
echo Startup aborted.
pause
exit /b 1
