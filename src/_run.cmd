@echo OFF

echo Starting server...
start "Server %1" cmd /c "test\server.exe %1 & pause"

echo Starting client...
timeout 2 > NUL
start "Client %1" cmd /c "test\client.exe %1 & pause"

echo Done