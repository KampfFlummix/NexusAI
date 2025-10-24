#!/usr/bin/env python3
"""
Alternative Build Script - Simplified Version
Fixes encoding issues
"""

import os
import sys
import subprocess
from pathlib import Path

def clean_build():
    """Clean previous build artifacts"""
    folders = ['build', 'dist', '__pycache__', 'NEXUS-AI_Portable']
    files = ['version.txt', 'NEXUS-AI.spec']
    
    for folder in folders:
        if Path(folder).exists():
            import shutil
            shutil.rmtree(folder)
            print(f"🧹 Cleaned: {folder}")
    
    for file in files:
        if Path(file).exists():
            os.remove(file)
            print(f"🧹 Cleaned: {file}")

def simple_build():
    """Simple PyInstaller build without problematic options"""
    print("🔨 Starting simple build...")
    
    # Basic PyInstaller command
    cmd = [
        sys.executable, '-m', 'PyInstaller',
        'nexus_ai.py',
        '--name=NEXUS-AI',
        '--onefile',
        '--windowed',
        '--clean',
        '--noconfirm'
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
        if result.returncode == 0:
            print("✅ Build successful!")
            
            # Create simple portable package
            portable_dir = Path("NEXUS-AI_Simple")
            portable_dir.mkdir(exist_ok=True)
            
            if sys.platform == 'win32':
                exe_src = Path("dist/NEXUS-AI.exe")
                exe_dest = portable_dir / "NEXUS-AI.exe"
            else:
                exe_src = Path("dist/NEXUS-AI")
                exe_dest = portable_dir / "NEXUS-AI"
            
            if exe_src.exists():
                import shutil
                shutil.copy2(exe_src, exe_dest)
                print(f"✅ Portable package created: {portable_dir}")
                return True
            else:
                print("❌ Executable not found after build")
                return False
        else:
            print(f"❌ Build failed: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Build error: {e}")
        return False

if __name__ == "__main__":
    print("NEXUS-AI Simple Build System")
    print("This build avoids problematic options that cause encoding issues.")
    
    clean_build()
    
    if simple_build():
        print("\n🎉 Simple build completed!")
        print("The executable is in the 'NEXUS-AI_Simple' folder.")
    else:
        print("\n💡 If simple build fails, try:")
        print("1. Install dependencies: pip install -r requirements.txt")
        print("2. Run directly: python nexus_ai.py")
        sys.exit(1)