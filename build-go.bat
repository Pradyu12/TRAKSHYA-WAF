@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
set CGO_ENABLED=1
set CC=cl.exe
cd /d E:\WAF\TRAKSHYA-WAF\go
go build -o ..\build\trakshya-api.exe .\cmd\trakshya-api\
echo Build complete!