REM Upstream loaders use the amd64 suffix for every 64-bit Windows process,
REM including ARM64. The activated compiler determines the binary architecture.
set REQUIRE_CYTHON_BUILD=1

pushd src\debugpy\_vendored\pydevd\pydevd_attach_to_process
if errorlevel 1 exit /b 1
del *.exe
del *.lib
del *.obj
del *.pdb
del *.dll
del *.exp
del *.so
del *.dylib

pushd windows
if errorlevel 1 exit /b 1

cl -DUNICODE -D_UNICODE /EHsc /Zi /O1 /W3 /LD /MD attach.cpp /link /DEBUG /OPT:REF /OPT:ICF /out:attach_amd64.dll
if errorlevel 1 exit /b 1
copy attach_amd64.dll ..\attach_amd64.dll /Y
if errorlevel 1 exit /b 1
copy attach_amd64.pdb ..\attach_amd64.pdb /Y
if errorlevel 1 exit /b 1

cl -DUNICODE -D_UNICODE /EHsc /Zi /O1 /LD /MD /D BITS_64 run_code_on_dllmain.cpp /link /DEBUG /OPT:REF /OPT:ICF /out:run_code_on_dllmain_amd64.dll
if errorlevel 1 exit /b 1
copy run_code_on_dllmain_amd64.dll ..\run_code_on_dllmain_amd64.dll /Y
if errorlevel 1 exit /b 1
copy run_code_on_dllmain_amd64.pdb ..\run_code_on_dllmain_amd64.pdb /Y
if errorlevel 1 exit /b 1

cl /EHsc /Zi /O1 inject_dll.cpp /link /DEBUG  /OPT:REF /OPT:ICF /out:inject_dll_amd64.exe
if errorlevel 1 exit /b 1
copy inject_dll_amd64.exe ..\inject_dll_amd64.exe /Y
if errorlevel 1 exit /b 1
copy inject_dll_amd64.pdb ..\inject_dll_amd64.pdb /Y
if errorlevel 1 exit /b 1

del *.exe
del *.lib
del *.obj
del *.pdb
del *.dll
del *.exp
popd
popd

%PYTHON% -m pip install . -vv
if errorlevel 1 exit /b 1
