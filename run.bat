@echo off
rem One-click local run for Aegis Shield (Windows).
rem Builds and starts everything with Docker, then prints the URL to open.
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem Require Docker.
docker version >nul 2>nul
if errorlevel 1 (
    echo Docker is not installed or not running.
    echo Install Docker Desktop from https://www.docker.com/products/docker-desktop/ and start it, then run this again.
    pause
    exit /b 1
)

rem First run: create .env from the template so config/secrets aren't hardcoded.
if not exist ".env" (
    copy ".env.example" ".env" >nul
    echo Created .env from .env.example.
    echo   -^> Before going live, edit .env and change JWT_SECRET and ADMIN_PASSWORD.
)

rem Read APP_PORT from .env (default 8000).
set "APP_PORT=8000"
for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
    if /i "%%A"=="APP_PORT" set "APP_PORT=%%B"
)

echo Building and starting Aegis Shield (first build can take several minutes)...
docker compose up --build -d
if errorlevel 1 (
    echo Failed to start. See the output above.
    pause
    exit /b 1
)

echo Waiting for Aegis Shield to become healthy...
for /l %%i in (1,1,60) do (
    curl -fs "http://localhost:!APP_PORT!/health" >nul 2>nul
    if not errorlevel 1 (
        echo.
        echo ------------------------------------------------
        echo   Aegis Shield is running.
        echo   Open:  http://localhost:!APP_PORT!
        echo ------------------------------------------------
        echo   Sign in with the admin e-mail/password from your .env file.
        echo   Stop it with:  docker compose down
        pause
        exit /b 0
    )
    timeout /t 3 /nobreak >nul
)

echo The app did not report healthy in time. Recent logs:
docker compose logs --tail=40 app
pause
exit /b 1
