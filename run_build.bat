@echo off
chcp 65001 > nul
echo ========================================
echo    NEXUS-AI Build System - Windows
echo ========================================

echo Checking Python installation...
python --version > nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found! Please install Python 3.8+
    pause
    exit /b 1
)

echo ✅ Python found
echo Installing dependencies...
pip install -r requirements.txt

echo Building NEXUS-AI executable...
python build_executable.py

if errorlevel 1 (
    echo ❌ Build failed!
    pause
    exit /b 1
)

echo ✅ Build completed successfully!
echo.
echo 🚀 NEXUS-AI is ready in the 'NEXUS-AI_Portable' folder!
pause