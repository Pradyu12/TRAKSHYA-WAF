@echo off
echo ================================================
echo   TRAKSHYA-WAF - Starting all services...
echo ================================================
echo.

:: Kill any existing processes
echo [1/5] Cleaning up old processes...
taskkill /F /IM trakshya-api.exe 2>nul
taskkill /F /IM trakshya-proxy.exe 2>nul
taskkill /F /IM node.exe 2>nul
timeout /t 2 /nobreak >nul
echo       Done.
echo.

:: Start upstream server (port 3000)
echo [2/5] Starting upstream server on port %UPSTREAM_PORT%...
start "Upstream Server" node "%~dp0server.js"
timeout /t 2 /nobreak >nul
echo       Done.
echo.

:: Start Go API with traffic generator (port 8000)
echo [3/4] Starting Go API on port 8000...
setlocal
set TRAKSHYA_FRONTEND_DIR=%~dp0frontend
set TRAKSHYA_CONFIG=%~dp0config\trakshya.yaml
set TRAKSHYA_DUCKDB_PATH=trakshya_events.duckdb
start "Go API" "%~dp0app\bin\trakshya-api.exe"
endlocal
timeout /t 3 /nobreak >nul
echo       Done.
echo.

:: Start Rust WAF proxy (port 8080) with separate database
echo [4/4] Starting WAF Proxy on port 8080...
setlocal
set TRAKSHYA_DUCKDB_PATH=trakshya_proxy.duckdb
set TRAKSHYA_MGMT_API_URL=http://127.0.0.1:8000
set TRAKSHYA_UPSTREAM_URL=http://127.0.0.1:3000
start "WAF Proxy" "%~dp0app\bin\trakshya-proxy.exe"
endlocal
timeout /t 3 /nobreak >nul
echo       Done.
echo.

echo ================================================
echo   All services started!
echo ================================================
echo.
echo   Upstream Server : http://localhost:3000
echo   Go API          : http://localhost:8000
echo   WAF Proxy       : http://localhost:8080
echo.
echo   Traffic flows through the WAF proxy:
echo   Client -^> WAF Proxy (8080) -^> Upstream (3000)
echo.
echo   Opening dashboard in your browser...
echo ================================================

:: Open dashboard in default browser
start http://localhost:8000

pause

echo ================================================
echo   All services started!
echo ================================================
echo.
echo   Upstream Server : http://localhost:3000
echo   Go API          : http://localhost:8000
echo   WAF Proxy       : http://localhost:8080
echo   Dashboard       : Electron window
echo.
echo   Traffic flows through the WAF proxy:
echo   Client -^> WAF Proxy (8080) -^> Upstream (3000)
echo.
echo   Press Ctrl+C to stop all services.
echo ================================================
pause
