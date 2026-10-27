@echo off
REM Quick MinGW build (no CMake). Requires gcc in PATH.
set CC=gcc
where %CC% >nul 2>&1
if errorlevel 1 (
  if exist C:\msys64\ucrt64\bin\gcc.exe (
    echo Found MSYS2 GCC, adding to PATH...
    set "PATH=C:\msys64\ucrt64\bin;%PATH%"
  ) else (
    echo Install MinGW gcc, or: cmake -B build ^&^& cmake --build build
    exit /b 1
  )
)

if not exist build mkdir build
set INC=-Iinclude -Isrc
set SRC=src\fips202.c src\symmetric.c src\randombytes.c src\verify.c src\utils.c src\reduce.c src\ntt.c src\rounding.c src\poly.c src\polyvec.c src\packing.c src\sign.c

%CC% %INC% -O2 -std=c99 %SRC% tests\test_verify.c -o build\test_verify.exe -lbcrypt
if errorlevel 1 exit /b 1
%CC% %INC% -O2 -std=c99 %SRC% examples\dilithium_sig.c -o build\dilithium_sig.exe -lbcrypt
if errorlevel 1 exit /b 1

build\test_verify.exe
echo All OK
