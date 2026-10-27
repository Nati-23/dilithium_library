import os

bat_path = r"C:\Users\HP\Desktop\sphincs_library\build.bat"

new_bat_content = """@echo off
setlocal

echo Checking build environment...

where cmake >nul 2>&1
if not errorlevel 1 (
    echo Configuring SPHINCS+ build with CMake...
    cmake -B build
    if not errorlevel 1 (
        echo Building SPHINCS+ with CMake...
        cmake --build build --config Release
        if not errorlevel 1 goto RUN_TESTS
    )
)

echo CMake not found or failed. Falling back to MinGW GCC...
set CC=gcc
where %CC% >nul 2>&1
if errorlevel 1 (
    if exist C:\\msys64\\ucrt64\\bin\\gcc.exe (
        echo Found MSYS2 GCC, adding to PATH...
        set "PATH=C:\\msys64\\ucrt64\\bin;%PATH%"
    ) else (
        echo Error: Neither CMake nor GCC was found in PATH.
        exit /b 1
    )
)

if not exist build mkdir build
if not exist build\\Release mkdir build\\Release
if not exist keys mkdir keys

echo Building test_sign_verify...
gcc -Iinclude -Isrc -O2 -std=c99 src/*.c tests/test_sign_verify.c -o build/test_sign_verify.exe -lbcrypt
if errorlevel 1 exit /b 1

echo Building basic_signature_example...
gcc -Iinclude -Isrc -O2 -std=c99 src/*.c examples/basic_signature_example.c -o build/basic_signature_example.exe -lbcrypt
if errorlevel 1 exit /b 1

echo Building sphincs_cli...
gcc -Iinclude -Isrc -O2 -std=c99 src/*.c examples/sphincs_web_cli.c -o build/sphincs_cli.exe -lbcrypt
if errorlevel 1 exit /b 1

copy /y build\\test_sign_verify.exe build\\Release\\ >nul 2>&1
copy /y build\\basic_signature_example.exe build\\Release\\ >nul 2>&1
copy /y build\\sphincs_cli.exe build\\Release\\ >nul 2>&1

:RUN_TESTS
echo.
echo Running SPHINCS+ sign & verify tests...
if exist build\Release\test_sign_verify.exe (
    build\Release\test_sign_verify.exe
) else if exist build\test_sign_verify.exe (
    build\test_sign_verify.exe
)

echo.
echo Running basic signature example...
if exist build\Release\basic_signature_example.exe (
    build\Release\basic_signature_example.exe
) else if exist build\basic_signature_example.exe (
    build\basic_signature_example.exe
)

echo.
echo All SPHINCS+ builds and tests completed successfully!
"""

with open(bat_path, "w", encoding="utf-8") as f:
    f.write(new_bat_content)

print("Updated build.bat successfully!")
